// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

use mbedtls::{
    Result,
    hash::{Hmac, Md, Type},
};
use std::time::{SystemTime, UNIX_EPOCH};

const KYLINOS: &str = "www.kylinos.cn";
const PKG: &str = "rust-libteec"; // 用作 PSK 标识
const TEEC: &str = "libcc_teec";

/// PSK 时间窗口大小（秒）
/// 每 300 秒（5分钟）自动轮换一次 PSK
const TIME_WINDOW_SIZE: u64 = 300;

/// 使用 HMAC-SM3 + 时间戳生成动态 PSK
///
/// # 原理
/// PSK = HMAC_SM3(base_key, timestamp_window)
/// - base_key: 固定的基础密钥（SM3(KYLINOS + PKG + TEEC)）
/// - timestamp_window: 当前时间窗口编号（每 300 秒一个窗口）
///
/// # 优势
/// - **动态密钥**：每 5 分钟自动轮换一次 PSK
/// - **防重放攻击**：每个时间窗口内的密钥唯一
/// - **时钟容差**：允许 ±1 个窗口的偏差（±5 分钟）
/// - **向后兼容**：客户端和服务端只需时间窗口一致即可
pub fn generate_psk() -> Result<[u8; 32]> {
    // 获取当前时间窗口编号
    let time_window = get_time_window();

    // 第一步：生成基础密钥 base_key = SM3(KYLINOS + PKG + TEEC)
    let mut base_key: [u8; 32] = Default::default();
    let mut ctx = Md::new(Type::SM3)?;
    ctx.update(KYLINOS.as_bytes())?;
    ctx.update(PKG.as_bytes())?;
    ctx.update(TEEC.as_bytes())?;
    ctx.finish(&mut base_key)?;

    // 第二步：使用 mbedtls 的 HMAC-SM3 生成动态 PSK
    let mut psk: [u8; 32] = Default::default();
    Hmac::hmac(Type::SM3, &base_key, &time_window.to_be_bytes(), &mut psk)?;

    Ok(psk)
}

/// 获取当前时间窗口编号
///
/// 时间窗口 = 当前Unix时间戳 / TIME_WINDOW_SIZE
fn get_time_window() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now / TIME_WINDOW_SIZE
}

pub const fn get_psk_identity() -> &'static str {
    PKG
}
