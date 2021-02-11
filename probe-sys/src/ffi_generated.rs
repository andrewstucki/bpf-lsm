use super::compiler_generated::*;
use std::os::raw::{c_char, c_int, c_void};

#[repr(C)]
#[derive(Copy, Clone)]
pub struct bprm_check_security_event_event_t {
    pub action: [c_char; 256],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bprm_check_security_event_process_parent_t {
    pub pid: u32,
    pub entity_id: [c_char; 256],
    pub name: [c_char; 256],
    pub args_count: u64,
    pub args: [[c_char; 128]; 64],
    pub ppid: u32,
    pub start: u64,
    pub thread__id: u64,
    pub executable: [c_char; 256],
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bprm_check_security_event_process_t {
    pub pid: u32,
    pub entity_id: [c_char; 256],
    pub name: [c_char; 256],
    pub ppid: u32,
    pub executable: [c_char; 256],
    pub args_count: u64,
    pub start: u64,
    pub thread__id: u64,
    pub args: [[c_char; 128]; 64],
    pub parent: bprm_check_security_event_process_parent_t,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bprm_check_security_event_user_group_t {
    pub id: u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bprm_check_security_event_user_effective_group_t {
    pub id: u32,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bprm_check_security_event_user_effective_t {
    pub id: u32,
    pub group: bprm_check_security_event_user_effective_group_t,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bprm_check_security_event_user_t {
    pub id: u32,
    pub group: bprm_check_security_event_user_group_t,
    pub effective: bprm_check_security_event_user_effective_t,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bprm_check_security_event_t {
    pub __timestamp: u64,
    pub event: bprm_check_security_event_event_t,
    pub process: bprm_check_security_event_process_t,
    pub user: bprm_check_security_event_user_t,
}

pub type bprm_check_security_event_handler = extern "C" fn(ctx: *mut c_void, e: bprm_check_security_event_t);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct state_configuration {
    pub debug: bool,
    pub bprm_check_security_ctx: *mut c_void,
    pub bprm_check_security_handler: bprm_check_security_event_handler,
}
pub enum state {}
extern "C" {
    pub fn new_state(config: state_configuration) -> *mut state;
    pub fn poll_state(_self: *mut state, timeout: c_int);
    pub fn destroy_state(_self: *mut state);
    pub fn set_process_path(_self: *mut state, pid: i32, file_path: *const c_char);
    pub fn flush_bprm_check_security_filter_rule(_self: *mut state, rule: query_bpf_bprm_check_security_event_t);
    pub fn flush_bprm_check_security_rejection_rule(_self: *mut state, rule: query_bpf_bprm_check_security_event_t);
}

pub unsafe fn unpack_bprm_check_security_closure<F>(closure: &mut F) -> (*mut c_void, bprm_check_security_event_handler)
where
    F: FnMut(bprm_check_security_event_t),
{
    extern "C" fn trampoline<F>(data: *mut c_void, e: bprm_check_security_event_t)
    where
        F: FnMut(bprm_check_security_event_t),
    {
        let closure: &mut F = unsafe { &mut *(data as *mut F) };
        (*closure)(e);
    }
    (closure as *mut F as *mut c_void, trampoline::<F>)
}