use clap::{Arg, ArgAction, Command};
use common::{error, info, Logger};
use log::LevelFilter;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process;

fn load_file(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut file = File::open(path)
        .map_err(|e| format!("Failed to open file '{}': {}", path.display(), e))?;
    
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(|e| format!("Failed to read file '{}': {}", path.display(), e))?;
    
    if buffer.is_empty() {
        return Err(format!("File '{}' is empty", path.display()).into());
    }
    
    Ok(buffer)
}

fn save_file(path: &Path, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create output directory '{}': {}", parent.display(), e))?;
    }
    
    let mut file = File::create(path)
        .map_err(|e| format!("Failed to create output file '{}': {}", path.display(), e))?;
    
    file.write_all(data)
        .map_err(|e| format!("Failed to write to output file '{}': {}", path.display(), e))?;
    
    Ok(())
}

fn validate_file_exists(path: &Path, file_type: &str) -> Result<(), String> {
    if !path.exists() {
        return Err(format!("{} file '{}' does not exist", file_type, path.display()));
    }
    
    if !path.is_file() {
        return Err(format!("{} path '{}' is not a file", file_type, path.display()));
    }
    
    Ok(())
}

fn generate_output_path(input_path: &Path) -> PathBuf {
    let parent = input_path.parent().unwrap_or(Path::new("."));
    let stem = input_path.file_stem().unwrap_or(std::ffi::OsStr::new("output"));
    let extension = input_path.extension().unwrap_or(std::ffi::OsStr::new("exe"));
    
    parent.join(format!("{}_obfuscated.{}", 
        stem.to_string_lossy(), 
        extension.to_string_lossy()))
}

fn main() {
    let app = Command::new("bin-obfuscator")
        .version("0.1.0")
        .author("vasie1337")
        .arg(Arg::new("binary")
            .help("Path to the PE binary file to obfuscate")
            .long_help("Path to the Windows PE executable file (.exe, .dll) that will be obfuscated.\n\
                       The file must be a valid x86-64 PE binary.")
            .required(true)
            .value_name("BINARY_PATH")
            .index(1))
        .arg(Arg::new("pdb")
            .help("Path to the corresponding PDB debug file")
            .long_help("Path to the Program Database (.pdb) file that contains debug information\n\
                       for the binary. This file is essential for the obfuscation process.")
            .required(true)
            .value_name("PDB_PATH")
            .index(2))
        .arg(Arg::new("output")
            .short('o')
            .long("output")
            .help("Output path for the obfuscated binary")
            .long_help("Specify the output path for the obfuscated binary.\n\
                       If not provided, defaults to '<input_name>_obfuscated.<ext>' in the same directory.")
            .value_name("OUTPUT_PATH"))
        .arg(Arg::new("verbose")
            .short('v')
            .long("verbose")
            .help("Enable verbose output")
            .long_help("Increase verbosity level. Use multiple times for more detailed output:\n\
                       -v: Show detailed information\n\
                       -vv: Show debug information\n\
                       -vvv: Show trace information")
            .action(ArgAction::Count))
        .arg(Arg::new("quiet")
            .short('q')
            .long("quiet")
            .help("Suppress non-error output")
            .long_help("Run in quiet mode, only showing error messages.\n\
                       Cannot be used together with verbose flags.")
            .action(ArgAction::SetTrue)
            .conflicts_with("verbose"));

    let matches = app.get_matches();

    let log_level = if matches.get_flag("quiet") {
        LevelFilter::Error
    } else {
        match matches.get_count("verbose") {
            0 => LevelFilter::Info,
            1 => LevelFilter::Debug,
            _ => LevelFilter::Trace,
        }
    };
    
    Logger::ensure_init_with_level(log_level);

    let binary_path = Path::new(matches.get_one::<String>("binary").unwrap());
    let pdb_path = Path::new(matches.get_one::<String>("pdb").unwrap());
    
    let output_path = if let Some(output) = matches.get_one::<String>("output") {
        PathBuf::from(output)
    } else {
        generate_output_path(binary_path)
    };

    info!("x86-64 PE Binary Obfuscator v0.1.0");
    
    if let Err(e) = validate_file_exists(binary_path, "Binary") {
        error!("{}", e);
        process::exit(1);
    }
    
    if let Err(e) = validate_file_exists(pdb_path, "PDB") {
        error!("{}", e);
        process::exit(1);
    }

    info!("Input binary: {}", binary_path.display());
    info!("PDB file: {}", pdb_path.display());
    
    info!("Loading input files...");
    
    let pe_data = match load_file(binary_path) {
        Ok(data) => {
            info!("Loaded binary: {:.2} MB", data.len() as f64 / 1024.0 / 1024.0);
            data
        }
        Err(e) => {
            error!("Failed to load binary: {}", e);
            process::exit(1);
        }
    };

    let pdb_data = match load_file(pdb_path) {
        Ok(data) => {
            info!("Loaded PDB: {:.2} MB", data.len() as f64 / 1024.0 / 1024.0);
            data
        }
        Err(e) => {
            error!("Failed to load PDB: {}", e);
            process::exit(1);
        }
    };

    info!("Starting obfuscation process...");
    
    let obfuscated_data = match core::obfuscate_binary(&pe_data, &pdb_data) {
        Ok(data) => {
            info!("Obfuscation completed successfully");
            data
        }
        Err(e) => {
            error!("Obfuscation failed: {}", e);
            process::exit(1);
        }
    };

    info!("Saving obfuscated binary...");
    
    if let Err(e) = save_file(&output_path, &obfuscated_data) {
        error!("Failed to save output: {}", e);
        process::exit(1);
    }

    info!("Successfully created obfuscated binary: {}", output_path.display());
    info!("Original size: {:.2} MB, Obfuscated size: {:.2} MB", 
          pe_data.len() as f64 / 1024.0 / 1024.0,
          obfuscated_data.len() as f64 / 1024.0 / 1024.0);
}