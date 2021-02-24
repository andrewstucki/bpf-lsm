use std::collections::HashMap;
use std::format;
use std::sync::Mutex;

use once_cell::sync::{Lazy, OnceCell};
use sled::Db;

static DB_INSTANCE: OnceCell<Db> = OnceCell::new();

pub fn global_database() -> &'static Db {
    DB_INSTANCE.get().expect("database is not initialized")
}

pub fn initialize_global_database(db: Db) {
    DB_INSTANCE
        .set(db)
        .expect("database could not be initialized");
}

static TEMPLATES: Lazy<Mutex<HashMap<&'static str, &'static [u8]>>> = Lazy::new(|| {
    let mut m = HashMap::new();
    let bprm_check_security_data = include_bytes!("../elasticsearch/bprm_check_security.json");
    m.insert("bprm_check_security", &bprm_check_security_data[..]);
    let inode_unlink_data = include_bytes!("../elasticsearch/inode_unlink.json");
    m.insert("inode_unlink", &inode_unlink_data[..]);
    Mutex::new(m)
});

pub fn get_template(name: &str) -> Result<&'static [u8], String> {
    let registry = TEMPLATES.lock().unwrap();
    match registry.get(name) {
        Some(data) => Ok(data),
        None => Err(format!("invalid template name {}", name)),
    }
}
