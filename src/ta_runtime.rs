// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::{Child, Command},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use dashmap::{DashMap, mapref::entry::Entry};

const DEFAULT_TA_ROOT: &str = "/tee/ta";
const DEFAULT_REGISTER_TIMEOUT_MS: u64 = 3_000;

fn ta_runtime_debug_enabled() -> bool {
    std::env::var_os("VSOCK_MANAGER_DEBUG_TA_RUNTIME").is_some()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnsureTaError {
    NotFound,
    SpawnFailed,
    RegisterTimeout,
    Internal,
}

pub struct TaRegistry {
    ta_root: PathBuf,
    register_timeout: Duration,
    state: Mutex<RegistryState>,
    cond: Condvar,
    virtual_sessions: VirtualSessionManager,
}

struct RegistryState {
    entries: HashMap<String, TaEntry>,
}

struct TaEntry {
    flags: Option<TaFlags>,
    instances: HashMap<u32, InstanceEntry>,
    next_instance_id: u32,
}

impl Default for TaEntry {
    fn default() -> Self {
        Self {
            flags: None,
            instances: HashMap::new(),
            next_instance_id: 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaFlags {
    pub is_single_instance: bool,
    pub is_multi_session: bool,
    pub is_instance_keep_alive: bool,
}

#[derive(Debug, Clone)]
pub struct InstanceRoute {
    pub uuid: String,
    pub instance_id: u32,
    pub socket_path: String,
}

#[derive(Debug)]
struct InstanceEntry {
    child: Option<Child>,
    pid: Option<u32>,
    state: InstanceState,
    socket_path: String,
    active_sessions: u32,
}

impl InstanceEntry {
    fn new_starting(uuid: &str, instance_id: u32) -> Self {
        Self {
            child: None,
            pid: None,
            state: InstanceState::Starting,
            socket_path: format!("/tmp/{}.{}.sock", uuid, instance_id),
            active_sessions: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstanceState {
    Starting,
    Ready,
    Dead,
}

impl TaRegistry {
    pub fn from_env() -> Self {
        let ta_root = std::env::var("TEE_TA_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_TA_ROOT));
        let timeout_ms = std::env::var("TEE_TA_REGISTER_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_REGISTER_TIMEOUT_MS);
        Self {
            ta_root,
            register_timeout: Duration::from_millis(timeout_ms),
            state: Mutex::new(RegistryState {
                entries: HashMap::new(),
            }),
            cond: Condvar::new(),
            virtual_sessions: VirtualSessionManager::default(),
        }
    }

    /// 测试用：空 `ta_root` 下任意 UUID 的 `spawn_ta` 均为 [`EnsureTaError::NotFound`]。
    #[cfg(test)]
    pub(crate) fn new_for_test(ta_root: PathBuf, register_timeout_ms: u64) -> Self {
        Self {
            ta_root,
            register_timeout: Duration::from_millis(register_timeout_ms),
            state: Mutex::new(RegistryState {
                entries: HashMap::new(),
            }),
            cond: Condvar::new(),
            virtual_sessions: VirtualSessionManager::default(),
        }
    }

    fn rollback_failed_spawn(
        &self,
        uuid: &str,
        instance_id: u32,
    ) -> std::result::Result<(), EnsureTaError> {
        let mut guard = self.state.lock().map_err(|_| EnsureTaError::Internal)?;
        if let Some(entry) = guard.entries.get_mut(uuid) {
            entry.instances.remove(&instance_id);
            if entry.instances.is_empty() && entry.flags.is_none() {
                guard.entries.remove(uuid);
            }
        }
        self.cond.notify_all();
        Ok(())
    }

    pub fn prepare_instance_for_open(&self, uuid: &str) -> std::result::Result<InstanceRoute, EnsureTaError> {
        crate::debug_log(&format!("pio START uuid={uuid} timeout_ms={}", self.register_timeout.as_millis()));
        let deadline = Instant::now() + self.register_timeout;
        // 本次 OpenSession：当前 spawn 目标 instance_id，就绪后 Return（multi-instance 必需；其它路径也可填充无副作用）。
        let mut awaiting_instance_for_this_open: Option<u32> = None;

        loop {
            enum Decision {
                Return(InstanceRoute),
                Spawn { instance_id: u32 },
                Wait,
            }

            let decision = {
                let mut guard = self.state.lock().map_err(|_| EnsureTaError::Internal)?;
                let entry = guard.entries.entry(uuid.to_string()).or_default();
                self.reap_dead_instances_locked(uuid, entry);

                let flags = entry.flags;
                let has_starting = entry
                    .instances
                    .values()
                    .any(|inst| inst.state == InstanceState::Starting);

                if let Some(flags) = flags {
                    if flags.is_single_instance {
                        if let Some((instance_id, inst)) = entry
                            .instances
                            .iter()
                            .find(|(_, inst)| inst.state == InstanceState::Ready)
                        {
                            Decision::Return(InstanceRoute {
                                uuid: uuid.to_string(),
                                instance_id: *instance_id,
                                socket_path: inst.socket_path.clone(),
                            })
                        } else if has_starting {
                            Decision::Wait
                        } else {
                            let instance_id = self.allocate_instance_id(entry);
                            entry
                                .instances
                                .insert(instance_id, InstanceEntry::new_starting(uuid, instance_id));
                            Decision::Spawn { instance_id }
                        }
                    } else {
                        // multi-instance（single_instance=false）：每个 OpenSession 对应一个新 TA 进程；
                        // 必须等「本次 spawn 的 instance_id」注册为 Ready 后再 Return，否则会无限 allocate+spawn。
                        if let Some(wid) = awaiting_instance_for_this_open {
                            match entry.instances.get(&wid) {
                                Some(inst) if inst.state == InstanceState::Ready => {
                                    if ta_runtime_debug_enabled() {
                                        eprintln!(
                                            "[vsock-manager ta_runtime] uuid={uuid} multi-instance: instance {wid} Ready → Return route"
                                        );
                                    }
                                    Decision::Return(InstanceRoute {
                                        uuid: uuid.to_string(),
                                        instance_id: wid,
                                        socket_path: inst.socket_path.clone(),
                                    })
                                }
                                Some(inst) if inst.state == InstanceState::Starting => {
                                    if ta_runtime_debug_enabled() {
                                        eprintln!(
                                            "[vsock-manager ta_runtime] uuid={uuid} multi-instance: awaiting instance {wid} Starting → Wait"
                                        );
                                    }
                                    Decision::Wait
                                }
                                _ => {
                                    if ta_runtime_debug_enabled() {
                                        eprintln!(
                                            "[vsock-manager ta_runtime] uuid={uuid} multi-instance: awaiting instance {wid} missing/Dead → respawn"
                                        );
                                    }
                                    awaiting_instance_for_this_open = None;
                                    let instance_id = self.allocate_instance_id(entry);
                                    entry
                                        .instances
                                        .insert(instance_id, InstanceEntry::new_starting(uuid, instance_id));
                                    Decision::Spawn { instance_id }
                                }
                            }
                        } else {
                            let instance_id = self.allocate_instance_id(entry);
                            entry
                                .instances
                                .insert(instance_id, InstanceEntry::new_starting(uuid, instance_id));
                            if ta_runtime_debug_enabled() {
                                eprintln!(
                                    "[vsock-manager ta_runtime] uuid={uuid} multi-instance: allocate instance {instance_id} → Spawn"
                                );
                            }
                            Decision::Spawn { instance_id }
                        }
                    }
                } else if let Some((instance_id, inst)) = entry
                    .instances
                    .iter()
                    .find(|(_, inst)| inst.state == InstanceState::Ready)
                {
                    Decision::Return(InstanceRoute {
                        uuid: uuid.to_string(),
                        instance_id: *instance_id,
                        socket_path: inst.socket_path.clone(),
                    })
                } else if has_starting {
                    Decision::Wait
                } else {
                    let instance_id = self.allocate_instance_id(entry);
                    entry
                        .instances
                        .insert(instance_id, InstanceEntry::new_starting(uuid, instance_id));
                    Decision::Spawn { instance_id }
                }
            };

            match decision {
                Decision::Return(route) => {
                    crate::debug_log(&format!(
                        "pio RETURN uuid={uuid} instance_id={} socket_path={}",
                        route.instance_id, route.socket_path
                    ));
                    return Ok(route);
                }
                Decision::Wait => {
                    crate::debug_log(&format!("pio WAIT uuid={uuid}"));
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(EnsureTaError::RegisterTimeout);
                    }
                    let timeout = deadline.saturating_duration_since(now);
                    let guard = self.state.lock().map_err(|_| EnsureTaError::Internal)?;

                    // 在 wait 之前二次检查条件：消除 decision block 释放锁到此处
                    // 重新获取锁之间的信号丢失窗口。若 mark_registered 已在此窗口内
                    // 设 Ready 并 notify_all，此处直接 continue 回到循环顶重新判断。
                    let already_ready = {
                        if let Some(entry) = guard.entries.get(uuid) {
                            if let Some(wid) = awaiting_instance_for_this_open {
                                entry
                                    .instances
                                    .get(&wid)
                                    .map_or(false, |inst| inst.state == InstanceState::Ready)
                            } else {
                                entry
                                    .instances
                                    .values()
                                    .any(|inst| inst.state == InstanceState::Ready)
                            }
                        } else {
                            false
                        }
                    };
                    if already_ready {
                        drop(guard);
                        continue;
                    }

                    let (new_guard, wait_result) = self
                        .cond
                        .wait_timeout(guard, timeout)
                        .map_err(|_| EnsureTaError::Internal)?;
                    drop(new_guard);
                    if wait_result.timed_out() {
                        return Err(EnsureTaError::RegisterTimeout);
                    }
                    continue;
                }
                Decision::Spawn { instance_id } => {
                    crate::debug_log(&format!("pio SPAWN uuid={uuid} instance_id={instance_id}"));
                    awaiting_instance_for_this_open = Some(instance_id);
                    if ta_runtime_debug_enabled() {
                        eprintln!(
                            "[vsock-manager ta_runtime] uuid={uuid} Spawn pid pending: instance_id={instance_id} (track until Ready)"
                        );
                    }
                    let child = match self.spawn_ta(uuid, instance_id) {
                        Ok(c) => {
                            crate::debug_log(&format!("pio SPAWN_OK uuid={uuid} instance_id={instance_id} pid={}", c.id()));
                            c
                        }
                        Err(err) => {
                            crate::debug_log(&format!("pio SPAWN_ERR uuid={uuid} instance_id={instance_id} err={err:?}"));
                            // 决策阶段已插入 `Starting` 占位；spawn 失败必须回滚，否则会留下永远
                            // 不 Ready 的实例，后续 OpenSession 会误判 has_starting 而长时间阻塞在 Wait
                            //（bad_uuid 等对不存在 TA 的用例）。
                            let _ = self.rollback_failed_spawn(uuid, instance_id);
                            return Err(err);
                        }
                    };
                    let pid = child.id();
                    let mut guard = self.state.lock().map_err(|_| EnsureTaError::Internal)?;
                    let entry = guard.entries.entry(uuid.to_string()).or_default();
                    if let Some(instance) = entry.instances.get_mut(&instance_id) {
                        instance.pid = Some(pid);
                        instance.child = Some(child);
                        // mark_registered 可能在 spawn 期间已将状态提升为 Ready，
                        // 不要在此覆写回去，否则本线程下次检查时会误判为 Starting 而卡在 Wait。
                        if instance.state != InstanceState::Ready {
                            instance.state = InstanceState::Starting;
                        }
                    }
                    self.cond.notify_all();
                }
            }
        }
    }

    pub fn mark_registered(
        &self,
        uuid: &str,
        instance_id: u32,
        socket_path: String,
        flags: TaFlags,
    ) {
        crate::debug_log(&format!(
            "mark_registered uuid={uuid} instance_id={instance_id} socket_path={socket_path} single={} multi={} keep={}",
            flags.is_single_instance, flags.is_multi_session, flags.is_instance_keep_alive
        ));
        if let Ok(mut guard) = self.state.lock() {
            let entry = guard.entries.entry(uuid.to_string()).or_default();
            if let Some(existing) = entry.flags {
                if existing != flags {
                    eprintln!(
                        "TA flags mismatch for uuid {}: old={:?}, new={:?}",
                        uuid, existing, flags
                    );
                }
            } else {
                entry.flags = Some(flags);
            }

            let instance = entry
                .instances
                .entry(instance_id)
                .or_insert_with(|| InstanceEntry::new_starting(uuid, instance_id));
            instance.state = InstanceState::Ready;
            instance.socket_path = socket_path;
            self.cond.notify_all();
        }
    }

    pub fn mark_instance_unavailable(&self, uuid: &str, instance_id: u32) {
        if let Ok(mut guard) = self.state.lock() {
            if let Some(entry) = guard.entries.get_mut(uuid) {
                if let Some(inst) = entry.instances.get_mut(&instance_id) {
                    inst.state = InstanceState::Dead;
                }
            }
            self.cond.notify_all();
        }
        self.virtual_sessions
            .invalidate_instance(uuid, instance_id);
    }

    pub fn bind_session(
        &self,
        uuid: &str,
        instance_id: u32,
        socket_path: String,
        local_session_id: u32,
    ) -> std::result::Result<u32, EnsureTaError> {
        let global_session_id = self.virtual_sessions.bind(SessionBinding {
            uuid: uuid.to_string(),
            instance_id,
            local_session_id,
            socket_path,
            generation: 0,
        });
        let mut guard = self.state.lock().map_err(|_| EnsureTaError::Internal)?;
        if let Some(entry) = guard.entries.get_mut(uuid) {
            if let Some(inst) = entry.instances.get_mut(&instance_id) {
                inst.active_sessions = inst.active_sessions.saturating_add(1);
            }
        }
        Ok(global_session_id)
    }

    pub fn session_entry(&self, global_session_id: u32) -> Option<Arc<SessionEntry>> {
        self.virtual_sessions.get(global_session_id)
    }

    pub fn unbind_session(&self, global_session_id: u32) {
        self.virtual_sessions.unbind(global_session_id);
    }

    pub fn on_session_closed(&self, uuid: &str, instance_id: u32) {
        if let Ok(mut guard) = self.state.lock() {
            if let Some(entry) = guard.entries.get_mut(uuid) {
                let Some(flags) = entry.flags else {
                    return;
                };
                let mut retire = false;
                if let Some(inst) = entry.instances.get_mut(&instance_id) {
                    if inst.active_sessions > 0 {
                        inst.active_sessions -= 1;
                    }
                    if !flags.is_single_instance {
                        retire = true;
                    } else if !flags.is_instance_keep_alive && inst.active_sessions == 0 {
                        retire = true;
                    }
                    if ta_runtime_debug_enabled() {
                        eprintln!(
                            "[TEE] on_session_closed: uuid={uuid} instance_id={instance_id} active_sessions={} retire={retire} is_single={} keep_alive={}",
                            inst.active_sessions, flags.is_single_instance, flags.is_instance_keep_alive
                        );
                    }
                    if retire {
                        inst.state = InstanceState::Dead;
                        if let Some(child) = inst.child.as_mut() {
                            let _ = child.kill();
                        }
                    }
                }
            }
            self.cond.notify_all();
        }
    }

    fn reap_dead_instances_locked(&self, uuid: &str, entry: &mut TaEntry) {
        let mut dead_instances = Vec::new();
        for (instance_id, instance) in entry.instances.iter_mut() {
            if let Some(child) = instance.child.as_mut() {
                if let Ok(Some(_)) = child.try_wait() {
                    instance.child = None;
                    instance.pid = None;
                    instance.state = InstanceState::Dead;
                }
            }
            if instance.state == InstanceState::Dead {
                dead_instances.push(*instance_id);
            }
        }
        for instance_id in dead_instances {
            if let Some(instance) = entry.instances.get(&instance_id) {
                let _ = std::fs::remove_file(&instance.socket_path);
            }
            entry.instances.remove(&instance_id);
            self.virtual_sessions.invalidate_instance(uuid, instance_id);
        }
    }

    fn allocate_instance_id(&self, entry: &mut TaEntry) -> u32 {
        let mut id = entry.next_instance_id.max(1);
        while entry.instances.contains_key(&id) {
            id = id.wrapping_add(1).max(1);
        }
        entry.next_instance_id = id.wrapping_add(1).max(1);
        id
    }

    fn spawn_ta(&self, uuid: &str, instance_id: u32) -> std::result::Result<Child, EnsureTaError> {
        let path = resolve_ta_executable(&self.ta_root, uuid).map_err(|e| {
            if matches!(e, ResolveTaError::NotFound) {
                EnsureTaError::NotFound
            } else {
                EnsureTaError::SpawnFailed
            }
        })?;
        Command::new(path)
            .env("XTEE_TA_INSTANCE_ID", instance_id.to_string())
            .spawn()
            .map_err(|_| EnsureTaError::SpawnFailed)
    }
}

#[derive(Debug)]
enum ResolveTaError {
    NotFound,
}

fn resolve_ta_executable(root: &Path, uuid: &str) -> std::result::Result<PathBuf, ResolveTaError> {
    let candidates = [
        root.join(uuid),
        root.join(format!("{uuid}.ta")),
        root.join(uuid).join(uuid),
    ];

    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or(ResolveTaError::NotFound)
}

#[derive(Clone, Debug)]
pub struct SessionBinding {
    pub uuid: String,
    pub instance_id: u32,
    pub local_session_id: u32,
    pub socket_path: String,
    pub generation: u64,
}

#[derive(Default)]
pub struct VirtualSessionManager {
    mapping: DashMap<u32, Arc<SessionEntry>>,
    next_session_id: AtomicU32,
    next_generation: AtomicU64,
}

impl VirtualSessionManager {
    pub fn bind(&self, mut binding: SessionBinding) -> u32 {
        loop {
            let mut candidate = self.next_session_id.fetch_add(1, Ordering::Relaxed);
            if candidate == 0 {
                candidate = self.next_session_id.fetch_add(1, Ordering::Relaxed);
                if candidate == 0 {
                    continue;
                }
            }
            binding.generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
            let entry = Arc::new(SessionEntry::new(binding.clone()));
            match self.mapping.entry(candidate) {
                Entry::Vacant(v) => {
                    v.insert(entry);
                    if ta_runtime_debug_enabled() {
                        eprintln!(
                            "[TEE] VirtualSessionManager::bind: global_session_id={candidate} uuid={} instance_id={} local_session_id={}",
                            binding.uuid, binding.instance_id, binding.local_session_id
                        );
                    }
                    return candidate;
                }
                Entry::Occupied(_) => continue,
            }
        }
    }

    pub fn get(&self, global_session_id: u32) -> Option<Arc<SessionEntry>> {
        self.mapping.get(&global_session_id).map(|v| v.value().clone())
    }

    pub fn unbind(&self, global_session_id: u32) {
        if ta_runtime_debug_enabled() {
            eprintln!(
                "[TEE] VirtualSessionManager::unbind: global_session_id={global_session_id}"
            );
        }
        self.mapping.remove(&global_session_id);
    }

    pub fn invalidate_instance(&self, uuid: &str, instance_id: u32) {
        let keys: Vec<u32> = self
            .mapping
            .iter()
            .filter(|item| {
                let binding = item.value().binding();
                binding.uuid == uuid && binding.instance_id == instance_id
            })
            .map(|item| *item.key())
            .collect();
        for key in keys {
            self.mapping.remove(&key);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionState {
    Open,
    Closing,
}

pub struct SessionEntry {
    binding: SessionBinding,
    state: Mutex<SessionState>,
}

impl SessionEntry {
    fn new(binding: SessionBinding) -> Self {
        Self {
            binding,
            state: Mutex::new(SessionState::Open),
        }
    }

    pub fn binding(&self) -> SessionBinding {
        self.binding.clone()
    }

    pub fn with_invoke<R, F>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&SessionBinding) -> R,
    {
        {
            let state = self.state.lock().ok()?;
            if *state != SessionState::Open {
                return None;
            }
        }
        Some(f(&self.binding))
    }

    pub fn with_close<R, F>(&self, f: F) -> Option<R>
    where
        F: FnOnce(&SessionBinding) -> R,
    {
        {
            let mut state = self.state.lock().ok()?;
            if *state != SessionState::Open {
                return None;
            }
            *state = SessionState::Closing;
        }
        Some(f(&self.binding))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    fn mk_flags(single: bool, multi: bool, keep_alive: bool) -> TaFlags {
        TaFlags {
            is_single_instance: single,
            is_multi_session: multi,
            is_instance_keep_alive: keep_alive,
        }
    }

    #[test]
    fn global_session_id_is_unique_and_non_zero() {
        let manager = VirtualSessionManager::default();
        let base = SessionBinding {
            uuid: "u".to_string(),
            instance_id: 1,
            local_session_id: 7,
            socket_path: "/tmp/u.1.sock".to_string(),
            generation: 0,
        };

        let s1 = manager.bind(base.clone());
        let s2 = manager.bind(base.clone());
        let s3 = manager.bind(base);

        assert_ne!(s1, 0);
        assert_ne!(s2, 0);
        assert_ne!(s3, 0);
        assert_ne!(s1, s2);
        assert_ne!(s1, s3);
        assert_ne!(s2, s3);
    }

    #[test]
    fn invalidate_instance_removes_only_target_instance_sessions() {
        let manager = VirtualSessionManager::default();
        let sid_a = manager.bind(SessionBinding {
            uuid: "uuid-a".to_string(),
            instance_id: 1,
            local_session_id: 11,
            socket_path: "/tmp/uuid-a.1.sock".to_string(),
            generation: 0,
        });
        let sid_b = manager.bind(SessionBinding {
            uuid: "uuid-a".to_string(),
            instance_id: 2,
            local_session_id: 22,
            socket_path: "/tmp/uuid-a.2.sock".to_string(),
            generation: 0,
        });
        let sid_c = manager.bind(SessionBinding {
            uuid: "uuid-b".to_string(),
            instance_id: 1,
            local_session_id: 33,
            socket_path: "/tmp/uuid-b.1.sock".to_string(),
            generation: 0,
        });

        manager.invalidate_instance("uuid-a", 1);

        assert!(manager.get(sid_a).is_none());
        assert!(manager.get(sid_b).is_some());
        assert!(manager.get(sid_c).is_some());
    }

    #[test]
    fn session_entry_close_blocks_further_invoke() {
        let entry = SessionEntry::new(SessionBinding {
            uuid: "uuid".to_string(),
            instance_id: 3,
            local_session_id: 42,
            socket_path: "/tmp/uuid.3.sock".to_string(),
            generation: 0,
        });

        let first_close = entry.with_close(|b| b.local_session_id);
        let second_close = entry.with_close(|b| b.local_session_id);
        let invoke_after_close = entry.with_invoke(|b| b.local_session_id);

        assert_eq!(first_close, Some(42));
        assert_eq!(second_close, None);
        assert_eq!(invoke_after_close, None);
    }

    #[test]
    fn on_session_closed_respects_keep_alive_for_single_instance() {
        let registry = TaRegistry::from_env();
        let uuid = "keepalive-uuid";

        registry.mark_registered(
            uuid,
            1,
            "/tmp/keepalive-uuid.1.sock".to_string(),
            mk_flags(true, true, true),
        );
        let sid = registry
            .bind_session(uuid, 1, "/tmp/keepalive-uuid.1.sock".to_string(), 1)
            .expect("bind should succeed");
        registry.unbind_session(sid);
        registry.on_session_closed(uuid, 1);

        let guard = registry
            .state
            .lock()
            .expect("registry state lock should not be poisoned");
        let entry = guard.entries.get(uuid).expect("entry should exist");
        let instance = entry.instances.get(&1).expect("instance should exist");
        assert_eq!(instance.state, InstanceState::Ready);
        assert_eq!(instance.active_sessions, 0);
    }

    #[test]
    fn on_session_closed_retires_instance_when_single_false() {
        let registry = TaRegistry::from_env();
        let uuid = "single-false-uuid";

        registry.mark_registered(
            uuid,
            7,
            "/tmp/single-false-uuid.7.sock".to_string(),
            mk_flags(false, true, false),
        );
        let sid = registry
            .bind_session(uuid, 7, "/tmp/single-false-uuid.7.sock".to_string(), 2)
            .expect("bind should succeed");
        registry.unbind_session(sid);
        registry.on_session_closed(uuid, 7);

        let guard = registry
            .state
            .lock()
            .expect("registry state lock should not be poisoned");
        let entry = guard.entries.get(uuid).expect("entry should exist");
        let instance = entry.instances.get(&7).expect("instance should exist");
        assert_eq!(instance.state, InstanceState::Dead);
        assert_eq!(instance.active_sessions, 0);
    }

    #[test]
    fn on_session_closed_retires_when_keep_alive_disabled() {
        let registry = TaRegistry::from_env();
        let uuid = "single-keepalive-off";

        registry.mark_registered(
            uuid,
            9,
            "/tmp/single-keepalive-off.9.sock".to_string(),
            mk_flags(true, true, false),
        );
        let sid = registry
            .bind_session(uuid, 9, "/tmp/single-keepalive-off.9.sock".to_string(), 5)
            .expect("bind should succeed");
        registry.unbind_session(sid);
        registry.on_session_closed(uuid, 9);

        let guard = registry
            .state
            .lock()
            .expect("registry state lock should not be poisoned");
        let entry = guard.entries.get(uuid).expect("entry should exist");
        let instance = entry.instances.get(&9).expect("instance should exist");
        assert_eq!(instance.state, InstanceState::Dead);
        assert_eq!(instance.active_sessions, 0);
    }

    #[test]
    fn bind_session_updates_mapping_and_active_count() {
        let registry = TaRegistry::from_env();
        let uuid = "binding-uuid";
        let socket_path = "/tmp/binding-uuid.1.sock".to_string();
        let local_session_id = 88;

        registry.mark_registered(
            uuid,
            1,
            socket_path.clone(),
            mk_flags(true, true, true),
        );
        let global_session_id = registry
            .bind_session(uuid, 1, socket_path.clone(), local_session_id)
            .expect("bind should succeed");

        let entry = registry
            .session_entry(global_session_id)
            .expect("global session should be present");
        let binding = entry.binding();
        assert_eq!(binding.uuid, uuid);
        assert_eq!(binding.instance_id, 1);
        assert_eq!(binding.local_session_id, local_session_id);
        assert_eq!(binding.socket_path, socket_path);

        let guard = registry
            .state
            .lock()
            .expect("registry state lock should not be poisoned");
        let instance = guard
            .entries
            .get(uuid)
            .and_then(|ta| ta.instances.get(&1))
            .expect("instance should exist");
        assert_eq!(instance.active_sessions, 1);
    }

    #[test]
    fn mark_instance_unavailable_invalidates_related_global_sessions() {
        let registry = TaRegistry::from_env();
        registry.mark_registered(
            "uuid-x",
            1,
            "/tmp/uuid-x.1.sock".to_string(),
            mk_flags(true, true, true),
        );
        registry.mark_registered(
            "uuid-y",
            1,
            "/tmp/uuid-y.1.sock".to_string(),
            mk_flags(true, true, true),
        );

        let s1 = registry
            .bind_session("uuid-x", 1, "/tmp/uuid-x.1.sock".to_string(), 10)
            .expect("bind should succeed");
        let s2 = registry
            .bind_session("uuid-x", 1, "/tmp/uuid-x.1.sock".to_string(), 11)
            .expect("bind should succeed");
        let s3 = registry
            .bind_session("uuid-y", 1, "/tmp/uuid-y.1.sock".to_string(), 12)
            .expect("bind should succeed");

        registry.mark_instance_unavailable("uuid-x", 1);

        assert!(registry.session_entry(s1).is_none());
        assert!(registry.session_entry(s2).is_none());
        assert!(registry.session_entry(s3).is_some());
    }

    #[test]
    fn on_session_closed_single_instance_only_retires_after_last_session() {
        let registry = TaRegistry::from_env();
        let uuid = "single-multi-close-order";
        let socket = "/tmp/single-multi-close-order.1.sock".to_string();

        registry.mark_registered(uuid, 1, socket.clone(), mk_flags(true, true, false));
        let s1 = registry
            .bind_session(uuid, 1, socket.clone(), 100)
            .expect("bind should succeed");
        let s2 = registry
            .bind_session(uuid, 1, socket.clone(), 101)
            .expect("bind should succeed");

        registry.unbind_session(s1);
        registry.on_session_closed(uuid, 1);

        {
            let guard = registry
                .state
                .lock()
                .expect("registry state lock should not be poisoned");
            let instance = guard
                .entries
                .get(uuid)
                .and_then(|ta| ta.instances.get(&1))
                .expect("instance should exist");
            assert_eq!(instance.state, InstanceState::Ready);
            assert_eq!(instance.active_sessions, 1);
        }

        registry.unbind_session(s2);
        registry.on_session_closed(uuid, 1);

        let guard = registry
            .state
            .lock()
            .expect("registry state lock should not be poisoned");
        let instance = guard
            .entries
            .get(uuid)
            .and_then(|ta| ta.instances.get(&1))
            .expect("instance should exist");
        assert_eq!(instance.state, InstanceState::Dead);
        assert_eq!(instance.active_sessions, 0);
    }

    #[test]
    fn session_entry_invoke_allowed_before_close() {
        let entry = SessionEntry::new(SessionBinding {
            uuid: "invoke-open".to_string(),
            instance_id: 2,
            local_session_id: 9,
            socket_path: "/tmp/invoke-open.2.sock".to_string(),
            generation: 0,
        });

        let invoke = entry.with_invoke(|b| (b.instance_id, b.local_session_id));
        assert_eq!(invoke, Some((2, 9)));
    }

    #[test]
    fn unbind_session_removes_mapping() {
        let registry = TaRegistry::from_env();
        let uuid = "unbind-mapping";
        registry.mark_registered(
            uuid,
            5,
            "/tmp/unbind-mapping.5.sock".to_string(),
            mk_flags(true, true, true),
        );
        let sid = registry
            .bind_session(uuid, 5, "/tmp/unbind-mapping.5.sock".to_string(), 66)
            .expect("bind should succeed");
        assert!(registry.session_entry(sid).is_some());

        registry.unbind_session(sid);

        assert!(registry.session_entry(sid).is_none());
    }

    #[test]
    fn prepare_instance_for_open_reuses_ready_single_instance_route() {
        let registry = TaRegistry::from_env();
        let uuid = "ready-single-route";
        let socket_path = "/tmp/ready-single-route.12.sock".to_string();
        registry.mark_registered(
            uuid,
            12,
            socket_path.clone(),
            mk_flags(true, true, true),
        );

        let route = registry
            .prepare_instance_for_open(uuid)
            .expect("should reuse ready instance without spawning");
        assert_eq!(route.uuid, uuid);
        assert_eq!(route.instance_id, 12);
        assert_eq!(route.socket_path, socket_path);
    }

    /// 不存在 TA 二进制时：第一次 `spawn_ta` 失败不得留下 `Starting` 占位，否则第二次
    /// `OpenSession` 会卡在 `has_starting` + condvar 直至注册超时（harness `bad_uuid` 等）。
    #[test]
    fn prepare_instance_for_open_not_found_twice_no_register_timeout_wait() {
        let dir = std::env::temp_dir().join(format!(
            "vsock_mgr_ta_root_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let registry = TaRegistry::new_for_test(dir.clone(), 5000);
        let uuid = "22222222-2222-2222-2222-222222222222";

        assert!(matches!(
            registry.prepare_instance_for_open(uuid),
            Err(EnsureTaError::NotFound)
        ));
        let t0 = Instant::now();
        assert!(matches!(
            registry.prepare_instance_for_open(uuid),
            Err(EnsureTaError::NotFound)
        ));
        assert!(
            t0.elapsed() < Duration::from_millis(500),
            "second NotFound should be immediate, not wait register timeout; got {:?}",
            t0.elapsed()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_virtual_session_bind_generates_unique_ids() {
        let manager = Arc::new(VirtualSessionManager::default());
        let workers = 8usize;
        let per_worker = 300usize;
        let mut handles = Vec::with_capacity(workers);

        for worker in 0..workers {
            let manager = manager.clone();
            handles.push(thread::spawn(move || {
                let mut ids = Vec::with_capacity(per_worker);
                for i in 0..per_worker {
                    let sid = manager.bind(SessionBinding {
                        uuid: format!("uuid-{worker}"),
                        instance_id: (worker as u32) + 1,
                        local_session_id: i as u32 + 1,
                        socket_path: format!("/tmp/uuid-{worker}.{}.sock", worker + 1),
                        generation: 0,
                    });
                    ids.push(sid);
                }
                ids
            }));
        }

        let mut all_ids = Vec::with_capacity(workers * per_worker);
        for handle in handles {
            let ids = handle.join().expect("worker should complete");
            all_ids.extend(ids);
        }

        assert_eq!(all_ids.len(), workers * per_worker);
        assert!(all_ids.iter().all(|sid| *sid != 0));
        let unique: HashSet<u32> = all_ids.iter().copied().collect();
        assert_eq!(unique.len(), all_ids.len());
    }

    #[test]
    fn concurrent_registry_bind_unbind_close_keeps_state_consistent() {
        let registry = Arc::new(TaRegistry::from_env());
        let uuid = "concurrent-bind-close";
        let instance_id = 21u32;
        let socket_path = "/tmp/concurrent-bind-close.21.sock".to_string();
        registry.mark_registered(
            uuid,
            instance_id,
            socket_path.clone(),
            mk_flags(true, true, true),
        );

        let workers = 6usize;
        let per_worker = 120usize;
        let mut handles = Vec::with_capacity(workers);
        let all_ids = Arc::new(Mutex::new(Vec::with_capacity(workers * per_worker)));

        for worker in 0..workers {
            let registry = registry.clone();
            let all_ids = all_ids.clone();
            let socket_path = socket_path.clone();
            handles.push(thread::spawn(move || {
                for i in 0..per_worker {
                    let sid = registry
                        .bind_session(
                            uuid,
                            instance_id,
                            socket_path.clone(),
                            ((worker * per_worker + i) as u32) + 1,
                        )
                        .expect("bind should succeed");
                    all_ids.lock().expect("id vec lock").push(sid);
                    registry.unbind_session(sid);
                    registry.on_session_closed(uuid, instance_id);
                }
            }));
        }

        for handle in handles {
            handle.join().expect("worker should complete");
        }

        let ids = all_ids.lock().expect("id vec lock");
        for sid in ids.iter().copied() {
            assert!(registry.session_entry(sid).is_none());
        }

        let guard = registry
            .state
            .lock()
            .expect("registry state lock should not be poisoned");
        let instance = guard
            .entries
            .get(uuid)
            .and_then(|ta| ta.instances.get(&instance_id))
            .expect("instance should exist");
        assert_eq!(instance.state, InstanceState::Ready);
        assert_eq!(instance.active_sessions, 0);
    }

    #[test]
    fn session_lookup_does_not_cross_instances_with_same_local_session_id() {
        let registry = TaRegistry::from_env();
        let uuid = "route-no-cross-instance";

        registry.mark_registered(
            uuid,
            1,
            "/tmp/route-no-cross-instance.1.sock".to_string(),
            mk_flags(false, true, false),
        );
        registry.mark_registered(
            uuid,
            2,
            "/tmp/route-no-cross-instance.2.sock".to_string(),
            mk_flags(false, true, false),
        );

        // Same local session id on two different instances must map to different global ids.
        let gsid_1 = registry
            .bind_session(uuid, 1, "/tmp/route-no-cross-instance.1.sock".to_string(), 42)
            .expect("bind instance 1 should succeed");
        let gsid_2 = registry
            .bind_session(uuid, 2, "/tmp/route-no-cross-instance.2.sock".to_string(), 42)
            .expect("bind instance 2 should succeed");

        assert_ne!(gsid_1, gsid_2);

        let binding_1 = registry
            .session_entry(gsid_1)
            .expect("lookup gsid_1")
            .binding();
        let binding_2 = registry
            .session_entry(gsid_2)
            .expect("lookup gsid_2")
            .binding();

        assert_eq!(binding_1.instance_id, 1);
        assert_eq!(binding_1.local_session_id, 42);
        assert_eq!(binding_1.socket_path, "/tmp/route-no-cross-instance.1.sock");

        assert_eq!(binding_2.instance_id, 2);
        assert_eq!(binding_2.local_session_id, 42);
        assert_eq!(binding_2.socket_path, "/tmp/route-no-cross-instance.2.sock");
    }
}
