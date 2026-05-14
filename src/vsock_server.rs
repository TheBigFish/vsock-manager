// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

use std::{
    io::{ErrorKind, Read, Write},
    os::unix::net::UnixStream,
    sync::Arc,
    thread,
};

use dashmap::DashSet;
use mbedtls::{
    error::codes,
    rng::{CtrDrbg, OsEntropy},
    ssl::{
        CipherSuite::{
            DhePskWithSm4128GcmSm3, EcdhePskWithSm4128GcmSm3, PskWithSm4128GcmSm3,
            RsaPskWithSm4128GcmSm3,
        },
        Config, Context, Version,
        config::{Endpoint, Preset, Transport},
    },
};

use postcard::from_bytes;
use virga::server::{ServerConfig, ServerManager, VirgeServer};

use crate::{
    protocol::TEE_Request,
    psk::{generate_psk, get_psk_identity},
    vsock_define::VSOCK_PORT,
    vsock_protocol::{CHUNK_SIZE, PacketHeader},
};

pub fn run_vsock_server(registry: Arc<DashSet<String>>) -> anyhow::Result<()> {
    println!("Vsock server is running...");

    let entropy = OsEntropy::new();
    let rng = Arc::new(CtrDrbg::new(Arc::new(entropy), None)?);
    let cipher_suites: Vec<i32> = vec![
        EcdhePskWithSm4128GcmSm3.into(),
        DhePskWithSm4128GcmSm3.into(),
        RsaPskWithSm4128GcmSm3.into(),
        PskWithSm4128GcmSm3.into(),
        0,
    ];
    let psk = generate_psk()?;
    let psk_identity = get_psk_identity();
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);

    config.set_rng(rng);
    config.set_min_version(Version::Tls1_2)?;
    config.set_max_version(Version::Tls1_2)?;
    config.set_ciphersuites(Arc::new(cipher_suites));
    config.set_psk(&psk, psk_identity)?;
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
    _registry: Arc<DashSet<String>>,
    config: Arc<Config>,
) -> anyhow::Result<()> {
    let mut ctx = Context::new(config.clone());
    ctx.establish(stream, None)?;
    let mut session_uuid: Option<String> = None;

    loop {
        let mut header = [0; PacketHeader::SIZE];

        if ctx.io_mut().is_none() {
            break;
        }

        if let Err(e) = ctx.read_exact(&mut header) {
            match e.kind() {
                ErrorKind::ConnectionReset | ErrorKind::UnexpectedEof => {
                    println!("Vsock server connection closed");
                    break;
                }
                _ => {
                    println!("Vsock server read header failed: {e}");
                    break;
                }
            }
        }

        handle_packet(
            &mut ctx,
            PacketHeader::from_bytes(&header),
            &mut session_uuid,
        )?;

        //thread::sleep(std::time::Duration::from_millis(1));
    }

    ctx.close();

    Ok(())
}

fn handle_packet(
    ctx: &mut Context<VirgeServer>,
    header: PacketHeader,
    session_uuid: &mut Option<String>,
) -> anyhow::Result<()> {
    let mut data = vec![0u8; header.data_size as usize];
    recv_data(ctx, &mut data)?;

    let req: TEE_Request = from_bytes(&data)?;
    let uuid = match req {
        TEE_Request::OpenSession { uuid, .. } => {
            *session_uuid = Some(uuid.clone());
            uuid
        }
        _ => session_uuid.as_ref().unwrap().clone(),
    };

    let path = format!("/tmp/{}.sock", uuid);
    let mut stream = UnixStream::connect(path)?;
    let mut message = Vec::with_capacity(4 + data.len());
    message.extend_from_slice(&(data.len() as u32).to_ne_bytes());
    message.extend_from_slice(&data);
    stream.write_all(&message)?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    send_data(ctx, &len_buf)?;

    let len = u32::from_ne_bytes(len_buf) as usize;
    let mut resp = vec![0u8; len];
    stream.read_exact(&mut resp)?;
    send_data(ctx, &resp)?;

    Ok(())
}

fn recv_data(ctx: &mut Context<VirgeServer>, data: &mut [u8]) -> mbedtls::Result<()> {
    ctx.read_exact(data).map_err(|_| codes::NetRecvFailed)?;
    Ok(())
}

fn send_data(ctx: &mut Context<VirgeServer>, data: &[u8]) -> mbedtls::Result<()> {
    ctx.write_all(data).map_err(|_| codes::NetSendFailed)?;
    Ok(())
}
