// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

use std::{
    io::Read,
    os::unix::net::{UnixListener, UnixStream},
    sync::Arc,
    thread,
};

use dashmap::DashSet;
use postcard::from_bytes;

use crate::protocol::TARequest;

const SERVER_SOCKET_PATH: &str = "/tmp/server.sock";

pub fn run_ta_server(registry: Arc<DashSet<String>>) -> anyhow::Result<()> {
    println!("TA server is running...");

    let _ = std::fs::remove_file(SERVER_SOCKET_PATH);
    let listener = UnixListener::bind(SERVER_SOCKET_PATH)?;
    println!("Listening on {}", SERVER_SOCKET_PATH);

    for stream in listener.incoming() {
        let stream = stream?;
        thread::spawn({
            let registry = registry.clone();
            move || {
                if let Err(e) = handle_ta_request(stream, registry.clone()) {
                    eprintln!("Failed to handle TA request: {:?}", e);
                }
            }
        });
    }

    Ok(())
}

pub fn handle_ta_request(
    mut stream: UnixStream,
    registry: Arc<DashSet<String>>,
) -> anyhow::Result<()> {
    println!("New TA connection established");

    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf)?;
    if n == 0 {
        return Ok(());
    }

    let req: TARequest = from_bytes(&buf[..n])?;
    match req {
        TARequest::Register { uuid } => {
            registry.insert(uuid.clone());
            println!("Registered TA with UUID: {}", uuid);
        }
    }

    Ok(())
}
