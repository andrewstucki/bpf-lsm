use once_cell::sync::Lazy;
use std::sync::Mutex;
use users::UsersCache;

mod constants;
mod errors;
mod helpers;
mod query_writer;
mod traits;

// import all of the generated modules
mod struct_pb;
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[rustfmt::skip]
mod compiler_generated;
#[rustfmt::skip]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
mod ffi_generated;
#[rustfmt::skip]
mod probe_generated;
#[rustfmt::skip]
mod serial_generated;
#[rustfmt::skip]
mod transform_generated;

pub use errors::{Error, SerializableResult, SerializationError};
pub use probe_generated::Probe;
pub use serial_generated::*;
pub use struct_pb::*;
pub use traits::{ProbeHandler, SerializableEvent};
pub use transform_generated::{TransformationHandler, Transformer};
// for tests
pub use query_writer::BpfQueryWriterFactory;

static USERS_CACHE: Lazy<Mutex<UsersCache>> = Lazy::new(|| Mutex::new(UsersCache::new()));
