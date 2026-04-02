// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

#![allow(dead_code)]

use bytemuck::{Pod, Zeroable};

pub const CHUNK_SIZE: u64 = 512;

#[derive(Debug, PartialEq, Eq)]
pub enum PacketType {
    Unknown,
    OpenSession,
    CloseSession,
    InvokeCommand,
    RequestCancellation,
}

impl From<u64> for PacketType {
    fn from(value: u64) -> Self {
        match value {
            0 => PacketType::Unknown,
            1 => PacketType::OpenSession,
            2 => PacketType::CloseSession,
            3 => PacketType::InvokeCommand,
            4 => PacketType::RequestCancellation,
            _ => PacketType::Unknown,
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Pod, Zeroable)]
pub struct PacketHeader {
    pub data_type: u64,
    pub data_size: u64,
}

impl PacketHeader {
    pub const SIZE: usize = size_of::<PacketHeader>();

    pub fn to_bytes(&self) -> &[u8] {
        bytemuck::bytes_of(self)
    }

    pub fn from_bytes(buf: &[u8]) -> Self {
        *bytemuck::from_bytes(buf)
    }
}
