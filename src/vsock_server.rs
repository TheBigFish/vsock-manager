// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::Duration;src/ta_server.rs

use dashmap::DashMap;
use mbedtls::error::codes;
use mbedtls::rng::{CtrDrbg, OsEntropy};
use mbedtls::ssl::config::{Endpoint, Preset, Transport};
use mbedtls::ssl::CipherSuite::{
    DhePskWithSm4128GcmSm3, EcdhePskWithSm4128GcmSm3, PskWithSm4128GcmSm3, RsaPskWithSm4128GcmSm3,
};
use mbedtls::ssl::{Config, Context, Version};
use postcard::{from_bytes, to_vec};
use virga::server::{ServerConfig, ServerManager, VirgeServer};

use crate::protocol::{TeeRequest, TeeResponse};
use crate::psk::{generate_psk, get_psk_identity};
use crate::ta_runtime::{EnsureTaError, TaRegistry};
use crate::vsock_define::VSOCK_PORT;
use crate::vsock_protocol::{PacketHeader, CHUNK_SIZE};

const TEE_ERROR_GENERIC: u32 = 0xFFFF0000;
const TEE_ERROR_ITEM_NOT_FOUND: u32 = 0xFFFF0008;
const TEE_ERROR_BUSY: u32 = 0xFFFF000D;
const TEE_ERROR_COMMUNICATION: u32 = 0xFFFF000E;
const TEE_SUCCESS: u32 = 0;
const OPEN_SESSION_RETRY_TIMES: usize = 6;
const OPEN_SESSION_RETRY_INTERVAL_MS: u64 = 30;

#[derive(Clone, Copy, Debug)]
enum TaUnixForwardKind {
    OpenSession,
    LongRunning,
}

fn ta_forward_debug() -> bool {
    std::env::var_os("VSOCK_MANAGER_DEBUG_TA_FORWARD").is_some()
}

fn vsock_close_debug() -> bool {
    std::env::var_os("VSOCK_MANAGER_DEBUG_CLOSE_SESSION").is_some()
}

fn parse_timeout_ms_env_opt(key: &str) -> Option<Duration> {
    let Ok(s) = std::env::var(key) else {
        return None;
    };
    let ms: u64 = s.trim().parse().unwrap_or(0);
    if ms == 0 {
        None
    } else {
        Some(Duration::from_millis(ms))
    }
}

fn ta_unix_read_timeout(kind: TaUnixForwardKind) -> Option<Duration> {
    match kind {
        TaUnixForwardKind::OpenSession => {
            parse_timeout_ms_env_opt("VSOCK_MANAGER_TA_OPEN_READ_TIMEOUT_MS")
        }
        TaUnixForwardKind::LongRunning => {
            // 与 Open 一致：默认不设置 `SO_RCVTIMEO`。部分 Linux/组合下超时到期表现为
            // `WouldBlock` 等，易在对端仍正常写响应时诱发本端提前放弃读并关连接 → TA 侧 Broken pipe。
            parse_timeout_ms_env_opt("VSOCK_MANAGER_TA_UNIX_READ_TIMEOUT_MS")
        }
    }
}

/// 客户端在 `CloseSession` / `FinalizeContext` 后关闭 TLS 时，底层读常表现为
/// `mbedTLS … NetRecvFailed`，而 **不是** `UnexpectedEof` / `ConnectionReset`。
/// 将其与常见内核 errno 一并视为正常断连，避免误报为「read header failed」。
fn header_read_is_peer_closed(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::ConnectionReset
            | ErrorKind::UnexpectedEof
            | ErrorKind::BrokenPipe
            | ErrorKind::ConnectionAborted
    ) || e.to_string().contains("NetRecvFailed")
}

pub fn run_vsock_server(registry: Arc<TaRegistry>) -> anyhow::Result<()> {
    println!("Vsock server is running...");

    let entropy = OsEntropy::new();
    let rng = Arc::new(CtrDrbg::new(Arc::new(entropy), None)?);
    let cipher_suites: Vec<i32> = vec![EcdhePskWithSm4128GcmSm3.into(), 0];
    let mut psk = generate_psk()?;
    let psk_identity = get_psk_identity();
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);

    config.set_rng(rng);
    config.set_min_version(Version::Tls1_2)?;
    config.set_max_version(Version::Tls1_2)?;
    config.set_ciphersuites(Arc::new(cipher_suites));
    config.set_psk(&psk, psk_identity)?;

    // 敏感数据使用后立即清零
    psk.zeroize();

    let rc_config = Arc::new(config);
    let config = ServerConfig::new(0xFFFFFFFF, VSOCK_PORT, CHUNK_SIZE as u32, false);
    let mut manager = ServerManager::new(config);
    manager.start()?;

    loop {
        let server = manager.accept()?;
        thread::spawn({
            let registry = registry.clone();
            let config = rc_config.clone();
            move || {
                if let Err(e) = handle_vsock_request(server, registry.clone(), config) {
                    eprintln!("Failed to handle vsock request: {:?}", e);
                }
            }
        });
    }
}

pub fn handle_vsock_request(
    stream: VirgeServer,
    registry: Arc<TaRegistry>,
    config: Arc<Config>,
) -> anyhow::Result<()> {
    let mut ctx = Context::new(config.clone());
    ctx.establish(stream, None)?;

    loop {
        let mut header = [0; PacketHeader::SIZE];

        if ctx.io_mut().is_none() {
            break;
        }

        if let Err(e) = ctx.read_exact(&mut header) {
            if header_read_is_peer_closed(&e) {
                println!("Vsock server connection closed");
                break;
            }
            println!("Vsock server read header failed: {e}");
            break;
        }

        handle_packet(
            &mut ctx,
            PacketHeader::from_bytes(&header),
            registry.as_ref(),
        )?;

        //thread::sleep(std::time::Duration::from_millis(1));
    }

    ctx.close();

    Ok(())
}

fn handle_packet(
    ctx: &mut Context<VirgeServer>,
    header: PacketHeader,
    registry: &TaRegistry,
) -> anyhow::Result<()> {
    let mut data = vec![0u8; header.data_size as usize];
    recv_data(ctx, &mut data)?;

    let req: TeeRequest = from_bytes(&data)?;
    match req {
        TeeRequest::OpenSession {
            uuid,
            connection_method,
            params,
        } => {
            let route = match registry.prepare_instance_for_open(&uuid) {
                Ok(route) => {
                    if std::env::var_os("VSOCK_MANAGER_DEBUG_OPEN_SESSION").is_some() {
                        eprintln!(
                            "[vsock-manager vsock_server] OpenSession route uuid={} instance_id={} socket_path={}",
                            route.uuid, route.instance_id, route.socket_path
                        );
                    }
                    route
                }
                Err(err) => {
                    let resp = TeeResponse::OpenSession {
                        session_id: 0,
                        result: map_ensure_error_to_result(err),
                    };
                    send_serialized_response(ctx, &resp)?;
                    return Ok(());
                }
            };

            let request = TeeRequest::OpenSession {
                uuid: uuid.clone(),
                connection_method,
                params,
            };
            let req_buf = serialize_message(&request)?;
            let forwarded = forward_request_to_ta_with_retry(
                &route.socket_path,
                &req_buf,
                OPEN_SESSION_RETRY_TIMES,
                std::time::Duration::from_millis(OPEN_SESSION_RETRY_INTERVAL_MS),
            );
            let resp_buf = match forwarded {
                Ok(buf) => buf,
                Err(err) => {
                    registry.mark_instance_unavailable(&uuid, route.instance_id);
                    let resp = TeeResponse::OpenSession {
                        session_id: 0,
                        result: map_forward_error_to_result(&err),
                    };
                    send_serialized_response(ctx, &resp)?;
                    return Ok(());
                }
            };
            let resp: TeeResponse = from_bytes(&resp_buf)?;
            let rewritten = match resp {
                TeeResponse::OpenSession {
                    session_id: local_session_id,
                    result,
                } if result == TEE_SUCCESS && local_session_id != 0 => {
                    match registry.bind_session(
                        &route.uuid,
                        route.instance_id,
                        route.socket_path.clone(),
                        local_session_id,
                    ) {
                        Ok(global_session_id) => TeeResponse::OpenSession {
                            session_id: global_session_id,
                            result,
                        },
                        Err(_) => {
                            let close_req = TeeRequest::CloseSession {
                                session_id: local_session_id,
                            };
                            if let Ok(close_buf) = serialize_message(&close_req) {
                                let _ = forward_request_to_ta(
                                    &route.socket_path,
                                    &close_buf,
                                    TaUnixForwardKind::LongRunning,
                                );
                            }
                            TeeResponse::OpenSession {
                                session_id: 0,
                                result: TEE_ERROR_GENERIC,
                            }
                        }
                    }
                }
                TeeResponse::OpenSession { session_id, result } => {
                    TeeResponse::OpenSession { session_id, result }
                }
                _ => TeeResponse::OpenSession {
                    session_id: 0,
                    result: TEE_ERROR_GENERIC,
                },
            };
            send_serialized_response(ctx, &rewritten)?;
        }
        TeeRequest::InvokeCommand {
            session_id: global_session_id,
            cmd_id,
            params,
        } => {
            let Some(entry) = registry.session_entry(global_session_id) else {
                let resp = TeeResponse::InvokeCommand {
                    params,
                    result: TEE_ERROR_ITEM_NOT_FOUND,
                };
                send_serialized_response(ctx, &resp)?;
                return Ok(());
            };
            let params_fallback = params.clone();
            let invoke_result = entry.with_invoke(|binding| {
                let local_req = TeeRequest::InvokeCommand {
                    session_id: binding.local_session_id,
                    cmd_id,
                    params,
                };
                let req_buf = serialize_message(&local_req)?;
                let resp_buf = forward_request_to_ta(
                    &binding.socket_path,
                    &req_buf,
                    TaUnixForwardKind::LongRunning,
                )?;
                let resp: TeeResponse = from_bytes(&resp_buf)?;
                Ok::<TeeResponse, anyhow::Error>(resp)
            });

            match invoke_result {
                Some(Ok(resp)) => send_serialized_response(ctx, &resp)?,
                Some(Err(_)) => {
                    let resp = TeeResponse::InvokeCommand {
                        params: params_fallback,
                        result: TEE_ERROR_COMMUNICATION,
                    };
                    send_serialized_response(ctx, &resp)?;
                }
                None => {
                    let resp = TeeResponse::InvokeCommand {
                        params: params_fallback,
                        result: TEE_ERROR_ITEM_NOT_FOUND,
                    };
                    send_serialized_response(ctx, &resp)?;
                }
            }
        }
        TeeRequest::CloseSession {
            session_id: global_session_id,
        } => {
            if vsock_close_debug() {
                eprintln!(
                    "[vsock-mgr CloseSession] enter global_session_id={global_session_id}"
                );
            }
            let Some(entry) = registry.session_entry(global_session_id) else {
                if vsock_close_debug() {
                    eprintln!(
                        "[vsock-mgr CloseSession] no SessionEntry for global_session_id={global_session_id}"
                    );
                }
                let resp = TeeResponse::CloseSession {
                    result: TEE_ERROR_ITEM_NOT_FOUND,
                };
                send_serialized_response(ctx, &resp)?;
                return Ok(());
            };

            let binding = entry.binding();
            if vsock_close_debug() {
                eprintln!(
                    "[vsock-mgr CloseSession] binding uuid={} instance_id={} local_session_id={} socket_path={}",
                    binding.uuid,
                    binding.instance_id,
                    binding.local_session_id,
                    binding.socket_path
                );
            }

            let close_result = entry.with_close(|binding| {
                let local_req = TeeRequest::CloseSession {
                    session_id: binding.local_session_id,
                };
                let req_buf = serialize_message(&local_req)?;
                let resp_buf = forward_request_to_ta(
                    &binding.socket_path,
                    &req_buf,
                    TaUnixForwardKind::LongRunning,
                )?;
                let resp: TeeResponse = from_bytes(&resp_buf)?;
                Ok::<(SessionCloseAction, TeeResponse), anyhow::Error>((
                    SessionCloseAction {
                        uuid: binding.uuid.clone(),
                        instance_id: binding.instance_id,
                    },
                    resp,
                ))
            });

            if vsock_close_debug() {
                eprintln!(
                    "[vsock-mgr CloseSession] with_close result is_some={} (global_session_id={global_session_id})",
                    close_result.is_some()
                );
            }

            match close_result {
                Some(Ok((action, resp))) => {
                    registry.unbind_session(global_session_id);
                    registry.on_session_closed(&action.uuid, action.instance_id);
                    send_serialized_response(ctx, &resp)?;
                }
                Some(Err(_)) => {
                    registry.unbind_session(global_session_id);
                    let resp = TeeResponse::CloseSession {
                        result: TEE_ERROR_COMMUNICATION,
                    };
                    send_serialized_response(ctx, &resp)?;
                }
                None => {
                    let resp = TeeResponse::CloseSession {
                        result: TEE_ERROR_ITEM_NOT_FOUND,
                    };
                    send_serialized_response(ctx, &resp)?;
                }
            }
        }
        TeeRequest::RequestCancellation { session_id: _ } => {
            let resp = TeeResponse::RequestCancellation {
                result: TEE_ERROR_GENERIC,
            };
            send_serialized_response(ctx, &resp)?;
        }
    }

    Ok(())
}

struct SessionCloseAction {
    uuid: String,
    instance_id: u32,
}

/// 同一 TA Unix 路径上并发「建连 → 写 → 读」转发条数上限的默认值（每条 Open/Invoke/Close 各占一席直至读完响应）。
/// 默认与 `xtee-utee` 的 `MAX_CA_CONNECTIONS`（16）对齐，避免 16 路同时 Close 时上限过小人为放大尾延迟。
/// 可用环境变量 `VSOCK_MANAGER_TA_UNIX_MAX_CONCURRENT_FORWARDS`（正整数）覆盖。
const DEFAULT_TA_UNIX_MAX_CONCURRENT_FORWARDS: usize = 16;
const FORWARD_SEMAPHORE_TIMEOUT_SECS: u64 = 30;

struct SemaphoreEntry {
    in_flight: usize,
    max: usize,
}

struct SemaphoreSlot {
    inner: Mutex<SemaphoreEntry>,
    cv: Condvar,
}

struct TaForwardSemaphore {
    entries: DashMap<String, Arc<SemaphoreSlot>>,
    max_per_target: usize,
}

impl TaForwardSemaphore {
    fn new() -> Self {
        let max = std::env::var("VSOCK_MANAGER_TA_UNIX_MAX_CONCURRENT_FORWARDS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_TA_UNIX_MAX_CONCURRENT_FORWARDS);
        Self {
            entries: DashMap::new(),
            max_per_target: max,
        }
    }

    fn acquire(&self, socket_path: &str) -> std::io::Result<ForwardPermit> {
        let slot = self
            .entries
            .entry(socket_path.to_string())
            .or_insert_with(|| {
                Arc::new(SemaphoreSlot {
                    inner: Mutex::new(SemaphoreEntry {
                        in_flight: 0,
                        max: self.max_per_target,
                    }),
                    cv: Condvar::new(),
                })
            })
            .value()
            .clone();

        let mut guard = slot.inner.lock().map_err(|_| {
            std::io::Error::new(ErrorKind::Other, "forward semaphore poisoned")
        })?;

        loop {
            if guard.in_flight < guard.max {
                guard.in_flight += 1;
                if ta_forward_debug() {
                    eprintln!(
                        "[fwd-sem] acquire: path={} in_flight={}/{}",
                        socket_path, guard.in_flight, guard.max
                    );
                }
                drop(guard);
                return Ok(ForwardPermit { slot });
            }

            if ta_forward_debug() {
                eprintln!(
                    "[fwd-sem] wait: path={} in_flight={}/{} (full, waiting)",
                    socket_path, guard.in_flight, guard.max
                );
            }
            let wait_result = slot
                .cv
                .wait_timeout(guard, Duration::from_secs(FORWARD_SEMAPHORE_TIMEOUT_SECS))
                .map_err(|_| {
                    std::io::Error::new(ErrorKind::Other, "forward semaphore poisoned")
                })?;
            if wait_result.1.timed_out() {
                return Err(std::io::Error::new(
                    ErrorKind::TimedOut,
                    format!(
                        "forward semaphore acquire timed out after {}s (path={})",
                        FORWARD_SEMAPHORE_TIMEOUT_SECS, socket_path
                    ),
                ));
            }
            guard = wait_result.0;
        }
    }
}

struct ForwardPermit {
    slot: Arc<SemaphoreSlot>,
}

impl Drop for ForwardPermit {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.slot.inner.lock() {
            guard.in_flight = guard.in_flight.saturating_sub(1);
            if ta_forward_debug() {
                eprintln!(
                    "[fwd-sem] release: in_flight={}/{}",
                    guard.in_flight, guard.max
                );
            }
        }
        if let Ok(guard) = self.slot.inner.lock() {
            drop(guard);
            self.slot.cv.notify_one();
        }
    }
}

static TA_FORWARD_SEMAPHORE: OnceLock<TaForwardSemaphore> = OnceLock::new();

fn forward_request_to_ta(
    socket_path: &str,
    req: &[u8],
    kind: TaUnixForwardKind,
) -> std::io::Result<Vec<u8>> {
    let semaphore = TA_FORWARD_SEMAPHORE.get_or_init(TaForwardSemaphore::new);
    let _permit = semaphore.acquire(socket_path)?;

    if ta_forward_debug() {
        eprintln!(
            "[vsock-mgr ta-fwd] begin kind={kind:?} path={socket_path} req_len={}",
            req.len()
        );
    }
    let fwd_start = std::time::Instant::now();

    let mut stream = UnixStream::connect(socket_path)?;
    if let Some(d) = ta_unix_read_timeout(kind) {
        stream.set_read_timeout(Some(d))?;
    }

    let mut message = Vec::with_capacity(4 + req.len());
    message.extend_from_slice(&(req.len() as u32).to_ne_bytes());
    message.extend_from_slice(req);
    stream.write_all(&message)?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_ne_bytes(len_buf) as usize;
    let mut resp = vec![0u8; len];
    stream.read_exact(&mut resp)?;

    if ta_forward_debug() {
        eprintln!(
            "[vsock-mgr ta-fwd] done kind={kind:?} path={socket_path} elapsed={:?} resp_len={}",
            fwd_start.elapsed(),
            resp.len()
        );
    }

    Ok(resp)
}

fn forward_request_to_ta_with_retry(
    socket_path: &str,
    req: &[u8],
    max_attempts: usize,
    interval: std::time::Duration,
) -> std::io::Result<Vec<u8>> {
    let attempts = max_attempts.max(1);
    let mut last_err: Option<std::io::Error> = None;
    for idx in 0..attempts {
        match forward_request_to_ta(socket_path, req, TaUnixForwardKind::OpenSession) {
            Ok(resp) => return Ok(resp),
            Err(err) => {
                let retryable = matches!(
                    err.kind(),
                    ErrorKind::NotFound
                        | ErrorKind::ConnectionRefused
                        | ErrorKind::ConnectionAborted
                        | ErrorKind::ConnectionReset
                        | ErrorKind::TimedOut
                        | ErrorKind::WouldBlock
                        | ErrorKind::Interrupted
                        | ErrorKind::BrokenPipe
                );
                if !retryable || idx + 1 == attempts {
                    return Err(err);
                }
                last_err = Some(err);
                thread::sleep(interval);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| std::io::Error::other("TA forward failed")))
}

fn send_response_to_ca(ctx: &mut Context<VirgeServer>, resp: &[u8]) -> mbedtls::Result<()> {
    let len_buf = (resp.len() as u32).to_ne_bytes();
    send_data(ctx, &len_buf)?;
    send_data(ctx, resp)?;
    Ok(())
}

fn send_serialized_response(
    ctx: &mut Context<VirgeServer>,
    resp: &TeeResponse,
) -> anyhow::Result<()> {
    let data = serialize_message(resp)?;
    send_response_to_ca(ctx, &data)?;
    Ok(())
}

fn serialize_message<T: serde::Serialize>(value: &T) -> anyhow::Result<Vec<u8>> {
    to_vec::<_, 65536>(value)
        .map(|v| v.to_vec())
        .map_err(|e| anyhow::anyhow!("serialize message failed: {e}"))
}

fn map_forward_error_to_result(err: &std::io::Error) -> u32 {
    match err.kind() {
        ErrorKind::NotFound | ErrorKind::ConnectionRefused => TEE_ERROR_ITEM_NOT_FOUND,
        ErrorKind::ConnectionAborted
        | ErrorKind::ConnectionReset
        | ErrorKind::TimedOut
        | ErrorKind::WouldBlock
        | ErrorKind::BrokenPipe => TEE_ERROR_COMMUNICATION,
        _ => TEE_ERROR_GENERIC,
    }
}

fn map_ensure_error_to_result(err: EnsureTaError) -> u32 {
    match err {
        EnsureTaError::NotFound => TEE_ERROR_ITEM_NOT_FOUND,
        EnsureTaError::RegisterTimeout => TEE_ERROR_BUSY,
        EnsureTaError::SpawnFailed | EnsureTaError::Internal => TEE_ERROR_GENERIC,
    }
}

fn recv_data(ctx: &mut Context<VirgeServer>, data: &mut [u8]) -> mbedtls::Result<()> {
    ctx.read_exact(data).map_err(|_| codes::NetRecvFailed)?;
    Ok(())
}

fn send_data(ctx: &mut Context<VirgeServer>, data: &[u8]) -> mbedtls::Result<()> {
    ctx.write_all(data).map_err(|_| codes::NetSendFailed)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn map_forward_error_to_result_covers_retryable_and_generic_errors() {
        let not_found = io::Error::new(ErrorKind::NotFound, "not found");
        let reset = io::Error::new(ErrorKind::ConnectionReset, "reset");
        let would_block = io::Error::new(ErrorKind::WouldBlock, "would block");
        let other = io::Error::other("other");

        assert_eq!(map_forward_error_to_result(&not_found), TEE_ERROR_ITEM_NOT_FOUND);
        assert_eq!(map_forward_error_to_result(&reset), TEE_ERROR_COMMUNICATION);
        assert_eq!(
            map_forward_error_to_result(&would_block),
            TEE_ERROR_COMMUNICATION
        );
        assert_eq!(map_forward_error_to_result(&other), TEE_ERROR_GENERIC);
    }

    #[test]
    fn map_ensure_error_to_result_matches_contract() {
        assert_eq!(
            map_ensure_error_to_result(EnsureTaError::NotFound),
            TEE_ERROR_ITEM_NOT_FOUND
        );
        assert_eq!(
            map_ensure_error_to_result(EnsureTaError::RegisterTimeout),
            TEE_ERROR_BUSY
        );
        assert_eq!(
            map_ensure_error_to_result(EnsureTaError::SpawnFailed),
            TEE_ERROR_GENERIC
        );
        assert_eq!(
            map_ensure_error_to_result(EnsureTaError::Internal),
            TEE_ERROR_GENERIC
        )
    }

    #[test]
    fn serialize_message_roundtrip_for_open_session_response() {
        let resp = TeeResponse::OpenSession {
            session_id: 1234,
            result: TEE_SUCCESS,
        };
        let bytes = serialize_message(&resp).expect("serialize should succeed");
        let decoded: TeeResponse = from_bytes(&bytes).expect("decode should succeed");
        match decoded {
            TeeResponse::OpenSession { session_id, result } => {
                assert_eq!(session_id, 1234);
                assert_eq!(result, TEE_SUCCESS);
            }
            _ => panic!("decoded response variant mismatch"),
        }
    }
}
