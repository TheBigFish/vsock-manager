// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 KylinSoft Co., Ltd. <https://www.kylinos.cn/>
// See LICENSES for license details.

#![allow(dead_code)]
#![allow(non_camel_case_types)]

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum TARequest {
    Register { uuid: String },
}

#[derive(Serialize, Deserialize)]
pub enum TEE_Request {
    OpenSession {
        uuid: String,
        connection_method: u32,
        params: TEE_Parameters,
    },
    CloseSession {
        session_id: u32,
    },
    InvokeCommand {
        session_id: u32,
        cmd_id: u32,
        params: TEE_Parameters,
    },
    RequestCancellation {
        session_id: u32,
    },
}

#[derive(Serialize, Deserialize)]
pub enum TEE_Response {
    OpenSession { session_id: u32, result: u32 },
    CloseSession { result: u32 },
    InvokeCommand { params: TEE_Parameters, result: u32 },
    RequestCancellation { result: u32 },
}

#[derive(Serialize, Deserialize, Default)]
pub struct TEE_Parameters(
    pub TEE_Parameter,
    pub TEE_Parameter,
    pub TEE_Parameter,
    pub TEE_Parameter,
);

#[derive(Serialize, Deserialize, Default)]
pub struct TEE_Parameter {
    pub param: TEE_Param,
    pub param_type: TEE_ParamType,
}

#[derive(Serialize, Deserialize, Default)]
pub struct TEE_Param {
    pub data: Vec<u8>,
    pub value: TEE_Value,
}

#[derive(Serialize, Deserialize, Default)]
pub struct TEE_Value {
    pub a: u32,
    pub b: u32,
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq, Clone, Copy)]
pub enum TEE_ParamType {
    #[default]
    None = 0,
    ValueInput = 1,
    ValueOutput = 2,
    ValueInout = 3,
    MemrefInput = 5,
    MemrefOutput = 6,
    MemrefInout = 7,
}

impl From<u32> for TEE_ParamType {
    fn from(value: u32) -> Self {
        match value {
            0 => TEE_ParamType::None,
            1 => TEE_ParamType::ValueInput,
            2 => TEE_ParamType::ValueOutput,
            3 => TEE_ParamType::ValueInout,
            5 => TEE_ParamType::MemrefInput,
            6 => TEE_ParamType::MemrefOutput,
            7 => TEE_ParamType::MemrefInout,
            _ => TEE_ParamType::None,
        }
    }
}
