#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unused_imports)]

extern crate protobuf;

use log::{debug, error, warn};
use std::error;
use std::fmt;
use std::fmt::Debug;
use std::os::raw::c_int;
use std::panic;

use protobuf::json::{print_to_string, PrintError};
use protobuf::{Message, ProtobufError};

mod struct_pb;
pub use struct_pb::*;

pub mod ffi {
    use std::os::raw::{c_char, c_int, c_uint, c_void};

    // begin bprm_check_security

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct bprm_check_security_event_process_target_t {
        pub executable: [c_char; 256],
        pub args_count: u64,
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct bprm_check_security_event_process_t {
        pub pid: u32,
        pub entity_id: [c_char; 256],
        pub name: [c_char; 256],
        pub ppid: u32,
        pub thread__id: u64,
        pub target: bprm_check_security_event_process_target_t,
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct bprm_check_security_event_user_group_t {
        pub id: u32,
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct bprm_check_security_event_user_t {
        pub id: u32,
        pub group: bprm_check_security_event_user_group_t,
    }

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct bprm_check_security_event_t {
        pub __timestamp: u64,
        pub process: bprm_check_security_event_process_t,
        pub user: bprm_check_security_event_user_t,
    }

    pub type bprm_check_security_event_handler =
        extern "C" fn(ctx: *mut c_void, e: bprm_check_security_event_t);

    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    pub struct state_configuration {
        pub filtered_uid: u32,
        pub debug: bool,
        pub bprm_check_security_ctx: *mut c_void,
        pub bprm_check_security_handler: bprm_check_security_event_handler,
    }
    pub enum state {}
    extern "C" {
        pub fn new_state(config: state_configuration) -> *mut state;
        pub fn poll_state(_self: *mut state, timeout: c_int);
        pub fn destroy_state(_self: *mut state);
    }

    /// Unpack a Rust closure, extracting a `void*` pointer to the data and a
    /// trampoline function which can be used to invoke it.
    ///
    /// # Safety
    ///
    /// It is the user's responsibility to ensure the closure outlives the returned
    /// `void*` pointer.
    ///
    /// Calling the trampoline function with anything except the `void*` pointer
    /// will result in *Undefined Behaviour*.
    ///
    /// The closure should guarantee that it never panics, seeing as panicking
    /// across the FFI barrier is *Undefined Behaviour*. You may find
    /// `std::panic::catch_unwind()` useful.

    pub unsafe fn unpack_bprm_check_security_closure<F>(
        closure: &mut F,
    ) -> (*mut c_void, bprm_check_security_event_handler)
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
}

#[derive(Debug, Clone)]
pub enum Error {
    InitializationError,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InitializationError => f.write_str(
                "Could not initialize BPF object, ensure you're using Linux kernel >= 4.18",
            ),
        }
    }
}

use std::ffi::CStr;
use std::os::raw::c_char;
fn transform_string(val: Vec<c_char>) -> String {
    unsafe { CStr::from_ptr(val.as_ptr()).to_string_lossy().into_owned() }
}

fn int_to_string(v: u32) -> String {
    v.to_string()
}

pub struct Probe<'a> {
    ctx: Option<*mut ffi::state>,
    // store the closures so that we make sure it has
    // the same lifetime as the state wrapper
    _bprm_check_security_handler: Option<Box<dyn 'a + Fn(ffi::bprm_check_security_event_t)>>,

    filtered_uid: u32,
    debug: bool,
}

#[derive(Debug)]
pub enum SerializationError {
    Json(PrintError),
    Bytes(ProtobufError),
    Transform(String),
}

impl fmt::Display for SerializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(_e) => write!(f, "json serialization failed"),
            Self::Bytes(e) => std::fmt::Display::fmt(&e, f),
            Self::Transform(e) => std::fmt::Display::fmt(&e, f),
        }
    }
}

impl error::Error for SerializationError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Json(_) => None,
            Self::Bytes(e) => Some(e),
            Self::Transform(_) => None,
        }
    }
}

pub type SerializableResult<T> = Result<T, SerializationError>;
pub trait SerializableEvent {
    fn to_json(&self) -> SerializableResult<String>;
    fn to_bytes(&self) -> SerializableResult<Vec<u8>>;
    fn update_id(&mut self, id: &mut str);
    fn update_sequence(&mut self, seq: u64);
    fn suffix(&self) -> &'static str;
}

impl From<ffi::bprm_check_security_event_process_target_t> for BprmCheckSecurityEventProcessTarget {
    fn from(e: ffi::bprm_check_security_event_process_target_t) -> Self {
        let mut event = Self::default();
        event.set_executable(transform_string(e.executable.into()));
        event.set_args_count(e.args_count);
        event
    }
}

impl From<ffi::bprm_check_security_event_process_t> for BprmCheckSecurityEventProcess {
    fn from(e: ffi::bprm_check_security_event_process_t) -> Self {
        let mut event = Self::default();
        event.set_pid(e.pid);
        event.set_entity_id(transform_string(e.entity_id.into()));
        event.set_name(transform_string(e.name.into()));
        event.set_ppid(e.ppid);
        event.set_thread_id(e.thread__id);
        event.target = Some(e.target.into()).into();
        event
    }
}

impl From<ffi::bprm_check_security_event_user_group_t> for BprmCheckSecurityEventUserGroup {
    fn from(e: ffi::bprm_check_security_event_user_group_t) -> Self {
        let mut event = Self::default();
        event.set_id(int_to_string(e.id.into()));
        event
    }
}

impl From<ffi::bprm_check_security_event_user_t> for BprmCheckSecurityEventUser {
    fn from(e: ffi::bprm_check_security_event_user_t) -> Self {
        let mut event = Self::default();
        event.set_id(int_to_string(e.id.into()));
        event.group = Some(e.group.into()).into();
        event
    }
}

impl From<ffi::bprm_check_security_event_t> for BprmCheckSecurityEvent {
    fn from(e: ffi::bprm_check_security_event_t) -> Self {
        let mut event = Self::default();
        event.set_timestamp(e.__timestamp);
        event.event = Some(Default::default()).into();
        event.process = Some(e.process.into()).into();
        event.user = Some(e.user.into()).into();
        event
    }
}

impl SerializableEvent for BprmCheckSecurityEvent {
    fn to_json(&self) -> SerializableResult<String> {
        match print_to_string(self) {
            Ok(result) => Ok(result),
            Err(e) => Err(SerializationError::Json(e)),
        }
    }

    fn to_bytes(&self) -> SerializableResult<Vec<u8>> {
        let mut event = Event::new();
        event.bprm_check_security_event_t = Some(self.clone()).into();
        event.set_event_type(event::EventType::BPRMCHECKSECURITYEVENT);
        match event.write_to_bytes() {
            Ok(result) => Ok(result),
            Err(e) => Err(SerializationError::Bytes(e)),
        }
    }

    fn update_id(&mut self, id: &mut str) {
        self.event.as_mut().and_then(|e| {
            e.set_id(id.to_string().to_owned());
            Some(e)
        });
    }

    fn update_sequence(&mut self, seq: u64) {
        self.event.as_mut().and_then(|e| {
            e.set_sequence(seq);
            Some(e)
        });
    }

    fn suffix(&self) -> &'static str {
        "bprm_check_security"
    }
}

pub trait ProbeHandler<U> {
    fn enqueue<T>(&self, event: &mut T) -> Result<(), U>
    where
        T: SerializableEvent + std::fmt::Debug;
}

pub trait TransformationHandler {
    fn enrich_bprm_check_security<'a>(
        &self,
        e: &'a mut BprmCheckSecurityEvent,
    ) -> SerializableResult<&'a mut BprmCheckSecurityEvent>;
}

pub struct Transformer<T> {
    handler: T,
}

impl<T: TransformationHandler> Transformer<T> {
    pub fn new(handler: T) -> Self {
        Self { handler: handler }
    }

    pub fn transform(&self, data: Vec<u8>) -> SerializableResult<String> {
        let e = Event::parse_from_bytes(&data).unwrap();
        match e.get_event_type() {
            event::EventType::BPRMCHECKSECURITYEVENT => self
                .handler
                .enrich_bprm_check_security(&mut e.bprm_check_security_event_t.unwrap())?
                .to_json(),
        }
    }
}

impl<'a> Probe<'a> {
    pub fn new() -> Self {
        Self {
            ctx: None,
            _bprm_check_security_handler: None,

            filtered_uid: std::u32::MAX,
            debug: false,
        }
    }

    pub fn filter(&mut self, uid: u32) -> &mut Self {
        self.filtered_uid = uid;
        self
    }

    pub fn debug(&mut self, debug: bool) -> &mut Self {
        self.debug = debug;
        self
    }

    pub fn run<F: 'a, U>(&mut self, handler: F) -> Result<&mut Self, Error>
    where
        F: 'a + ProbeHandler<U> + panic::RefUnwindSafe,
        U: std::fmt::Display,
    {
        let mut bprm_check_security_wrapper = move |e: ffi::bprm_check_security_event_t| {
            let result = panic::catch_unwind(|| {
                handler
                    .enqueue(&mut BprmCheckSecurityEvent::from(e))
                    .unwrap_or_else(|e| warn!("error enqueuing data: {}", e));
            });
            if result.is_err() {
                debug!("panic while handling event");
            }
        };
        let (bprm_check_security_closure, bprm_check_security_callback) =
            unsafe { ffi::unpack_bprm_check_security_closure(&mut bprm_check_security_wrapper) };

        let state_config = ffi::state_configuration {
            filtered_uid: self.filtered_uid,
            debug: self.debug,
            bprm_check_security_ctx: bprm_check_security_closure,
            bprm_check_security_handler: bprm_check_security_callback,
        };
        let state = unsafe { ffi::new_state(state_config) };
        if state.is_null() {
            return Err(Error::InitializationError);
        }
        self.ctx = Some(state);
        self._bprm_check_security_handler = Some(Box::new(bprm_check_security_wrapper));

        Ok(self)
    }

    pub fn poll(&self, timeout: i32) {
        match self.ctx {
            Some(ctx) => unsafe { ffi::poll_state(ctx, timeout as c_int) },
            _ => return,
        }
    }
}

impl<'a> Drop for Probe<'a> {
    fn drop(&mut self) {
        match self.ctx {
            Some(ctx) => unsafe { ffi::destroy_state(ctx) },
            _ => return,
        }
    }
}
