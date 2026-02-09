// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

use std::{sync::Arc, thread};

use dashmap::DashSet;

use crate::{ta_server::run_ta_server, vsock_server::run_vsock_server};

mod pks;
mod protocal;
mod ta_server;
mod vsock_define;
mod vsock_protocal;
mod vsock_server;

fn main() {
    let ta_registry = Arc::new(DashSet::<String>::new());

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
