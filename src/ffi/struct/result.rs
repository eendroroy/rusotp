use crate::ffi::converter::to_cstr;
use std::ffi::c_char;
use std::ptr::null;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct StringResult {
    pub success: bool,
    pub data: *const c_char,
    pub error: *const c_char,
}

pub(crate) fn error_string_result(error: &str) -> StringResult {
    StringResult {
        success: false,
        data: null(),
        error: to_cstr(error),
    }
}

pub(crate) fn success_string_result(data: &str) -> StringResult {
    StringResult {
        success: true,
        data: to_cstr(data),
        error: null(),
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct BoolResult {
    pub success: bool,
    pub data: bool,
    pub error: *const c_char,
}

pub(crate) fn error_bool_result(error: &str) -> BoolResult {
    BoolResult {
        success: false,
        data: false,
        error: to_cstr(error),
    }
}

pub(crate) fn success_bool_result(data: bool) -> BoolResult {
    BoolResult {
        success: true,
        data,
        error: null(),
    }
}
