use env_logger::{Builder, Target};
use log::LevelFilter;
use std::io::Write;

pub struct Logger;

impl Logger {
    pub fn init() -> Result<(), log::SetLoggerError> {
        Self::init_with_level(LevelFilter::Info)
    }

    pub fn init_with_level(level: LevelFilter) -> Result<(), log::SetLoggerError> {
        let mut builder = Builder::from_default_env();
        
        builder
            .target(Target::Stdout)
            .filter_level(level)
            .format(|buf, record| {
                let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
                
                // Extract crate name from file path
                let file_path = record.file().unwrap_or("unknown");
                let crate_name = Self::extract_crate_name(file_path);
                
                // Color codes for different log levels
                let (level_color, reset) = match record.level() {
                    log::Level::Error => ("\x1b[31m", "\x1b[0m"), // Red
                    log::Level::Warn => ("\x1b[33m", "\x1b[0m"),  // Yellow
                    log::Level::Info => ("\x1b[32m", "\x1b[0m"),  // Green
                    log::Level::Debug => ("\x1b[36m", "\x1b[0m"), // Cyan
                    log::Level::Trace => ("\x1b[35m", "\x1b[0m"), // Magenta
                };
                
                writeln!(
                    buf,
                    "\x1b[90m[{}]\x1b[0m {}{:>5}{} \x1b[94m[{}]\x1b[0m \x1b[90m{}:{}\x1b[0m {}",
                    timestamp,
                    level_color,
                    record.level(),
                    reset,
                    crate_name,
                    record.file().unwrap_or("unknown"),
                    record.line().unwrap_or(0),
                    record.args()
                )
            });

        builder.try_init()
    }

    pub fn init_debug() -> Result<(), log::SetLoggerError> {
        Self::init_with_level(LevelFilter::Debug)
    }

    pub fn init_trace() -> Result<(), log::SetLoggerError> {
        Self::init_with_level(LevelFilter::Trace)
    }

    pub fn init_simple() -> Result<(), log::SetLoggerError> {
        let mut builder = Builder::from_default_env();
        
        builder
            .target(Target::Stdout)
            .filter_level(LevelFilter::Debug)
            .format(|buf, record| {
                let crate_name = Self::extract_crate_name(record.file().unwrap_or("unknown"));
                let (level_color, reset) = match record.level() {
                    log::Level::Error => ("\x1b[31m", "\x1b[0m"),
                    log::Level::Warn => ("\x1b[33m", "\x1b[0m"),
                    log::Level::Info => ("\x1b[32m", "\x1b[0m"),
                    log::Level::Debug => ("\x1b[36m", "\x1b[0m"),
                    log::Level::Trace => ("\x1b[35m", "\x1b[0m"),
                };
                
                writeln!(
                    buf,
                    "{}{:>5}{} \x1b[94m[{}]\x1b[0m {}",
                    level_color,
                    record.level(),
                    reset,
                    crate_name,
                    record.args()
                )
            });

        builder.try_init()
    }

    pub fn is_enabled(level: log::Level) -> bool {
        log::log_enabled!(level)
    }
    
    /// Extract crate name from file path
    fn extract_crate_name(file_path: &str) -> &str {
        // Handle different path separators (Windows/Unix)
        let path_parts: Vec<&str> = file_path.split(['/', '\\']).collect();
        
        // Look for crates directory structure
        if let Some(crates_index) = path_parts.iter().position(|&part| part == "crates") {
            if crates_index + 1 < path_parts.len() {
                return path_parts[crates_index + 1];
            }
        }
        
        // Fallback: try to get from the beginning of the path
        if path_parts.len() >= 2 {
            path_parts[path_parts.len() - 2]
        } else {
            "unknown"
        }
    }
}
