#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unused_imports)]

mod constants;
mod errors;
mod helpers;
mod query_writer;
mod traits;

// import all of the generated modules
mod struct_pb;
mod compiler_generated;
mod ffi_generated;
mod probe_generated;
mod serial_generated;
mod transform_generated;

pub use errors::{Error, SerializableResult, SerializationError};
pub use probe_generated::Probe;
pub use serial_generated::*;
pub use struct_pb::*;
pub use traits::{ProbeHandler, SerializableEvent};
pub use transform_generated::{TransformationHandler, Transformer};

static USERS_CACHE: Lazy<Mutex<UsersCache>> = Lazy::new(|| Mutex::new(UsersCache::new()));
