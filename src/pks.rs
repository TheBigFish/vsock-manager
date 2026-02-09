// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

use mbedtls::{
    hash::{Md, Type},
    Result,
};

const KYLINOS: &str = "www.kylinos.cn";
const PKG: &str = "cc-utils";
const TEEC: &str = "libcc_teec";

pub fn generate_psk() -> Result<[u8; 32]> {
    let mut psk: [u8; 32] = Default::default();
    let mut ctx = Md::new(Type::SM3)?;

    ctx.update(KYLINOS.as_bytes())?;
    ctx.update(PKG.as_bytes())?;
    ctx.update(TEEC.as_bytes())?;
    let _len = ctx.finish(&mut psk);

    Ok(psk)
}

pub const fn get_psk_identity() -> &'static str {
    PKG
}
