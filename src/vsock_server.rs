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
use xtee_psk::{
    CryptoRng, PSK_LEN, SM2_POINT_LEN, Sm2DsaKeypair, build_ecdh_response, derive_psk,
    ecdh_compute_shared, extract_ec_point, generate_dsa_keypair, generate_ecdh_keypair,
    get_psk_identity, new_crypto_rng, sign_ecdh_exchange,
};
use zeroize::Zeroize;

use crate::vsock_define::VSOCK_PORT;

pub fn run_vsock_server() -> anyhow::Result<()> {
    println!("Vsock server is running...");

    let entropy = Arc::new(OsEntropy::new());
    let cipher_suites: Arc<Vec<i32>> = Arc::new(vec![EcdhePskWithSm4128GcmSm3.into(), 0]);

    // 服务端长期密钥：启动时生成，跨连接持久化
    // 用于对每次 ECDH 交换签名，使客户端可通过 TOFU 模型校验服务端身份一致性
    let mut key_rng =
        new_crypto_rng().map_err(|e| anyhow::anyhow!("ECDH: create crypto rng failed: {e}"))?;
    let lt_key = generate_dsa_keypair(&mut key_rng)
        .map_err(|e| anyhow::anyhow!("ECDH: generate long-term key failed: {e}"))?;
    // 预提取长期公钥（不可变，跨连接共享，避免每次连接重复计算）
    let long_term_point: Arc<Vec<u8>> = Arc::new(
        extract_ec_point(&lt_key)
            .map_err(|e| anyhow::anyhow!("ECDH: extract long-term point failed: {e}"))?,
    );
    let long_term_key: Arc<Sm2DsaKeypair> = Arc::new(lt_key);

    let config = ServerConfig::new(0xFFFFFFFF, VSOCK_PORT, CHUNK_SIZE as u32, false);
    let mut manager = ServerManager::new(config);

    manager.start()?;

    loop {
        let server = manager.accept()?;
        thread::spawn({
            let cipher_suites = cipher_suites.clone();
            let entropy = entropy.clone();
            let long_term_key = long_term_key.clone();
            let long_term_point = long_term_point.clone();
            move || {
                if let Err(e) = handle_vsock_request(
                    server,
                    cipher_suites,
                    entropy,
                    long_term_key,
                    long_term_point,
                ) {
                    eprintln!("Failed to handle vsock request: {:?}", e);
                }
            }
        });
    }
}

pub fn handle_vsock_request(
    mut stream: VirgeServer,
    cipher_suites: Arc<Vec<i32>>,
    entropy: Arc<OsEntropy>,
    long_term_key: Arc<Sm2DsaKeypair>,
    long_term_point: Arc<Vec<u8>>,
) -> anyhow::Result<()> {
    let rng = CtrDrbg::new(entropy, None)?;
    let mut crypto_rng =
        new_crypto_rng().map_err(|e| anyhow::anyhow!("ECDH: create crypto rng failed: {e}"))?;
    //  ECDH 密钥协商（在 VSOCK 上）
    let (mut psk, psk_identity) = ecdh_negotiate(
        &mut stream,
        &mut crypto_rng,
        &long_term_key,
        &long_term_point,
    )
    .map_err(|e| {
        eprintln!("ECDH 密钥协商失败：{e}");
        e
    })?;

    // 创建 per-connection TLS 配置（每个连接使用独立的动态 PSK）
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);

    config.set_min_version(Version::Tls1_2)?;
    config.set_max_version(Version::Tls1_2)?;
    config.set_ciphersuites(cipher_suites);
    config.set_rng(Arc::new(rng));
    config.set_psk(&psk, &psk_identity)?;

    // 清除敏感数据
    psk.zeroize();

    let mut ctx = Context::new(Arc::new(config));
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

        let packet_header = PacketHeader::from_bytes(&header);
        // 基本校验：防止异常的 data_size 导致 OOM
        if packet_header.data_size as usize > MAX_MESSAGE_SIZE {
            return Err(anyhow::anyhow!(
                "invalid packet header: data_size too large"
            ));
        }

        handle_packet(&mut ctx, packet_header, &mut session_uuid)?;

        //thread::sleep(std::time::Duration::from_millis(1));
    }

    ctx.close();

    Ok(())
}

/// ECDH 密钥协商（服务端侧）。
///
/// 协议流程：
/// 1. 接收客户端临时 EC point（65 字节未压缩格式）
/// 2. 生成服务端临时 SM2 密钥对（每连接独立，保障前向安全性）
/// 3. 使用长期 DSA 密钥对交换数据签名，发送长期公钥给客户端
/// 4. 客户端通过 TOFU 模型校验长期公钥一致性（首次信任，后续校验）
/// 5. 双方各自通过 ECDH + HKDF-SM3 派生相同的 32 字节 PSK
fn ecdh_negotiate(
    stream: &mut VirgeServer,
    rng: &mut CryptoRng,
    long_term_key: &Sm2DsaKeypair,
    long_term_point: &[u8],
) -> anyhow::Result<([u8; PSK_LEN], String)> {
    let client_point = stream.recv()?;

    if client_point.len() != SM2_POINT_LEN || client_point[0] != 0x04 {
        return Err(anyhow::anyhow!(
            "ECDH: invalid client point (len={}, prefix=0x{:02x})",
            client_point.len(),
            client_point.first().unwrap_or(&0)
        ));
    }

    // 1. 生成服务端临时 SM2 密钥对
    let ecdh_key = generate_ecdh_keypair(rng)
        .map_err(|e| anyhow::anyhow!("ECDH: failed to generate key pair: {e}"))?;

    // 2. 提取服务端裸 EC point
    let server_point = extract_ec_point(&ecdh_key)
        .map_err(|e| anyhow::anyhow!("ECDH: failed to extract server point: {e}"))?;

    // 3. 使用持久化的长期密钥签名
    let signature = sign_ecdh_exchange(long_term_key, &client_point, &server_point, rng)
        .map_err(|e| anyhow::anyhow!("ECDH: failed to sign exchange: {e}"))?;

    // 4. 构建并发送响应
    let send_buf = build_ecdh_response(&server_point, &signature, long_term_point);
    stream.send(send_buf)?;

    // 5. 通过 ECDH 协商共享秘密
    let mut shared = ecdh_compute_shared(&ecdh_key, &client_point)
        .map_err(|e| anyhow::anyhow!("ECDH: failed to compute shared secret: {e}"))?;

    drop(ecdh_key);

    // 6. 使用 HKDF-SM3 派生 PSK
    let psk_result = derive_psk(&shared, &client_point, &server_point);
    shared.zeroize();
    let psk = psk_result.map_err(|e| anyhow::anyhow!("ECDH: failed to derive PSK: {e}"))?;

    let psk_identity = get_psk_identity();
    Ok((psk, psk_identity.to_string()))
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
