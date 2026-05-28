// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

use std::{
    io::Write,
    sync::Arc,
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{ta_server::run_ta_server, vsock_server::run_vsock_server};

mod protocol;
mod psk;
mod ta_server;
mod ta_runtime;
mod vsock_define;
mod vsock_protocol;
mod vsock_server;

pub(crate) fn debug_log(msg: &str) {
    if std::env::var_os("VSOCK_MANAGER_FILE_LOG").is_none() {
        return;
    }
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let line = format!("{ts} {msg}\n");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/vsock-manager.log")
    {
        let _ = f.write_all(line.as_bytes());
    }
}

fn main() {
    let ta_registry = Arc::new(ta_runtime::TaRegistry::from_env());

    let handle1 = thread::spawn({
        let registry = ta_registry.clone();
        move || {
            if let Err(e) = run_ta_server(registry) {
                eprintln!("TA server failed: {:?}", e);
            }
        }
    });

    let handle2 = thread::spawn({
        let registry = ta_registry.clone();
        move || {
            if let Err(e) = run_vsock_server(registry) {
                eprintln!("Vsock server failed: {:?}", e);
            }
        }
    });

    handle1.join().expect("TA server thread panicked");
    handle2.join().expect("Vsock server thread panicked");
}
