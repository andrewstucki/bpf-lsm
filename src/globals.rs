use once_cell::sync::OnceCell;

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
