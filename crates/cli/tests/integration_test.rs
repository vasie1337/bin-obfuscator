//! Integration tests for the binary obfuscator.
//!
//! These tests build the test-binary, run the obfuscator on it,
//! and verify the obfuscated binary produces identical output.
//!
//! NOTE: These tests only run on Windows as the obfuscator targets Windows PE binaries.

#![cfg(target_os = "windows")]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn target_dir() -> PathBuf {
    workspace_root().join("target").join("debug")
}

/// Build a package and return the path to the built executable
fn build_package(package: &str) -> PathBuf {
    let status = Command::new("cargo")
        .args(["build", "--package", package])
        .current_dir(workspace_root())
        .status()
        .expect("Failed to execute cargo build");

    assert!(status.success(), "Failed to build {}", package);

    target_dir().join(format!("{}.exe", package.replace('-', "_")))
}

/// Get paths to the test binary and its PDB
fn get_test_binary_paths() -> (PathBuf, PathBuf) {
    let exe_path = target_dir().join("test-binary.exe");
    let pdb_path = target_dir().join("test_binary.pdb");
    (exe_path, pdb_path)
}

/// Run an executable and return (stdout, exit_success)
fn run_executable(path: &PathBuf) -> (String, bool) {
    let output = Command::new(path)
        .output()
        .unwrap_or_else(|e| panic!("Failed to execute {}: {}", path.display(), e));

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    (stdout, output.status.success())
}

/// Check if output indicates all tests passed
fn verify_test_output(output: &str, binary_name: &str) -> bool {
    // Check for the success marker
    if !output.contains("RESULT: SUCCESS") {
        println!("{} output does not contain SUCCESS marker", binary_name);
        return false;
    }

    // Check there are no failures
    if output.contains("[FAIL]") {
        println!("{} has failed tests", binary_name);
        return false;
    }

    true
}

#[test]
fn test_obfuscation_preserves_functionality() {
    // Build test-binary
    println!("Building test-binary...");
    build_package("test-binary");

    let (exe_path, pdb_path) = get_test_binary_paths();
    let obfuscated_path = target_dir().join("test-binary_obfuscated.exe");

    assert!(exe_path.exists(), "test-binary.exe not found");
    assert!(pdb_path.exists(), "test_binary.pdb not found");

    // Run original binary first to verify it works
    println!("Running original binary...");
    let (original_output, original_success) = run_executable(&exe_path);
    
    assert!(original_success, "Original binary failed to execute properly");
    assert!(
        verify_test_output(&original_output, "Original"),
        "Original binary tests failed:\n{}",
        original_output
    );

    // Run the obfuscator
    println!("Running obfuscator...");
    let pe_data = fs::read(&exe_path).expect("Failed to read test binary");
    let pdb_data = fs::read(&pdb_path).expect("Failed to read PDB file");

    let obfuscated_data = core::run(&pe_data, &pdb_data).expect("Obfuscation failed");

    // Write obfuscated binary
    fs::write(&obfuscated_path, &obfuscated_data).expect("Failed to write obfuscated binary");

    // Run obfuscated binary
    println!("Running obfuscated binary...");
    let (obfuscated_output, obfuscated_success) = run_executable(&obfuscated_path);

    // Verify obfuscated binary succeeded
    assert!(
        obfuscated_success,
        "Obfuscated binary exited with failure:\n{}",
        obfuscated_output
    );

    assert!(
        verify_test_output(&obfuscated_output, "Obfuscated"),
        "Obfuscated binary tests failed:\n{}",
        obfuscated_output
    );

    // Verify outputs match exactly
    assert_eq!(
        original_output, obfuscated_output,
        "Outputs differ!\n--- Original ---\n{}\n--- Obfuscated ---\n{}",
        original_output, obfuscated_output
    );

    println!("\n=== SUCCESS ===");
    println!("Original size: {} bytes", pe_data.len());
    println!("Obfuscated size: {} bytes", obfuscated_data.len());
    println!("Size increase: {:.1}%", 
        (obfuscated_data.len() as f64 / pe_data.len() as f64 - 1.0) * 100.0);
}

#[test]
fn test_original_binary_passes_all_tests() {
    // Build test-binary
    build_package("test-binary");

    let (exe_path, _) = get_test_binary_paths();
    assert!(exe_path.exists(), "test-binary.exe not found");

    let (output, success) = run_executable(&exe_path);

    assert!(success, "Test binary exited with failure");
    assert!(
        output.contains("RESULT: SUCCESS"),
        "Test binary did not report success:\n{}",
        output
    );
    
    // Count passed tests
    let pass_count = output.matches("[PASS]").count();
    println!("Original binary: {} tests passed", pass_count);
    assert!(pass_count >= 20, "Expected at least 20 tests, got {}", pass_count);
}

#[test]
fn test_obfuscation_increases_binary_size() {
    // Build test-binary
    build_package("test-binary");

    let (exe_path, pdb_path) = get_test_binary_paths();

    let pe_data = fs::read(&exe_path).expect("Failed to read test binary");
    let pdb_data = fs::read(&pdb_path).expect("Failed to read PDB file");

    let obfuscated_data = core::run(&pe_data, &pdb_data).expect("Obfuscation failed");

    // Obfuscation should increase the binary size (mutations expand instructions)
    assert!(
        obfuscated_data.len() > pe_data.len(),
        "Obfuscated binary should be larger: {} <= {}",
        obfuscated_data.len(),
        pe_data.len()
    );

    let increase_pct = (obfuscated_data.len() as f64 / pe_data.len() as f64 - 1.0) * 100.0;
    println!(
        "Size: {} -> {} bytes ({:.1}% increase)",
        pe_data.len(),
        obfuscated_data.len(),
        increase_pct
    );
}
