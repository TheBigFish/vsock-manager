// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

//! 基于 VSOCK + ECDH-PSK 的机密通信服务端。
//!
//! ## 服务端身份与 TOFU 模型
//!
//! 服务端在启动时生成一个长期 SM2 DSA 密钥对，该密钥对跨连接持久化：
//! - 每次 ECDH 协商时，服务端用长期密钥对交换数据签名
//! - 客户端通过 TOFU（Trust On First Use）模型校验服务端长期公钥的一致性
//! - 若服务端重启导致密钥变更，客户端会检测到并拒绝连接（防御持续性 MITM）
//!
//! 注意：服务端长期密钥仅在进程生命周期内有效，重启后会重新生成。
//! 在机密通信场景中，服务端与客户端部署在同一设备上，首次连接发生在
//! 受控环境中，因此 TOFU 模型足以保障服务端身份不被替换。

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
        CipherSuite::EcdhePskWithSm4128GcmSm3,
        Config, Context, Version,
        config::{Endpoint, Preset, Transport},
    },
};
use postcard::from_bytes;
use teec_protocol::{CHUNK_SIZE, MAX_MESSAGE_SIZE, PacketHeader, TEE_Request};
use virga::server::{ServerConfig, ServerManager, VirgeServer};
use xtee_psk::{ServerPskContext, new_crypto_rng, virga_transport::VirgeServerTransport};

use crate::vsock_define::VSOCK_PORT;

pub fn run_vsock_server(registry: Arc<DashSet<String>>) -> anyhow::Result<()> {
    println!("Vsock server is running...");

    let entropy = Arc::new(OsEntropy::new());
    let cipher_suites: Arc<Vec<i32>> = Arc::new(vec![EcdhePskWithSm4128GcmSm3.into(), 0]);

    // 服务端长期密钥：启动时生成，跨连接持久化
    // 用于对每次 ECDH 交换签名，使客户端可通过 TOFU 模型校验服务端身份一致性
    let mut key_rng =
        new_crypto_rng().map_err(|e| anyhow::anyhow!("ECDH: create crypto rng failed: {e}"))?;
    let psk_ctx = Arc::new(
        ServerPskContext::generate(&mut key_rng)
            .map_err(|e| anyhow::anyhow!("ECDH: generate long-term key failed: {e}"))?,
    );

    let config = ServerConfig::new(0xFFFFFFFF, VSOCK_PORT, CHUNK_SIZE as u32, false);
    let mut manager = ServerManager::new(config);
    manager.start()?;

    loop {
        let server = manager.accept()?;
        thread::spawn({
            let registry_arc = Arc::clone(&registry);
            let entropy_arc = Arc::clone(&entropy);
            let cipher_suites_arc = Arc::clone(&cipher_suites);
            let psk_ctx_arc = Arc::clone(&psk_ctx);
            move || {
                let rng = CtrDrbg::new(entropy_arc, None).expect("create TLS RNG");
                let mut crypto_rng = new_crypto_rng().expect("create crypto RNG");

                // ECDH 密钥协商（在 VSOCK 上，TLS 握手之前）
                let mut transport = VirgeServerTransport(server);
                let (psk, psk_identity) =
                    match psk_ctx_arc.negotiate(&mut transport, &mut crypto_rng) {
                        Ok(result) => result,
                        Err(e) => {
                            eprintln!("ECDH 密钥协商失败：{e}");
                            return;
                        }
                    };
                let stream = transport.0;

                // 创建 per-connection TLS 配置（必须在循环内，不能在 loop 外面）。
                // 原因：每个连接通过 ECDH 协商出唯一的 PSK，
                // config.set_psk() 绑定的是当前连接的专属密钥，
                // 跨连接复用会导致所有连接使用同一个 PSK，失去前向安全性。
                let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
                config
                    .set_min_version(Version::Tls1_2)
                    .expect("set min version");
                config
                    .set_max_version(Version::Tls1_2)
                    .expect("set max version");
                config.set_ciphersuites(cipher_suites_arc);
                config.set_rng(Arc::new(rng));
                config.set_psk(&*psk, psk_identity).expect("set PSK");

                if let Err(e) = handle_vsock_request(stream, registry_arc.clone(), Arc::new(config))
                {
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
    let mut ctx = Context::new(config);
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
    // 基本校验：防止异常的 data_size 导致 OOM
    if header.data_size as usize > MAX_MESSAGE_SIZE {
        return Err(anyhow::anyhow!(
            "invalid packet header: data_size too large"
        ));
    }

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
