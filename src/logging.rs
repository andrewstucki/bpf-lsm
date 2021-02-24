use fern::Dispatch;
use log::LevelFilter;

pub fn setup_logger(level: LevelFilter) {
    let mut dispatch = Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(level);
    if level != LevelFilter::Debug {
        // ureq logs at too high of a log level by default
        dispatch = dispatch.level_for("ureq", LevelFilter::Warn);
    }
    let result = dispatch.chain(std::io::stderr()).apply();
    if result.is_err() {
        eprintln!(
            "Error initializing logging: {:}",
            result.unwrap_err().to_string()
        );
        std::process::exit(1);
    }
}
