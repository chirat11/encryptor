use std::process::Command;
use std::io::{self, Write};

mod env_setup;
mod package_managers; 
mod installers;
mod utils;

use env_setup::{setup_openssl_environment, setup_cmake_environment};
use installers::{install_openssl};

pub fn check_all_requirements() -> Result<(), Box<dyn std::error::Error>> {
    println!("Checking system requirements...");
    
    let mut missing_components = Vec::new();
    
    if check_openssl().is_err() {
        missing_components.push("OpenSSL");
    }
    
    if missing_components.is_empty() {
        println!("All system requirements satisfied!");
        
        println!("Configuring build environment...");
        let _ = setup_cmake_environment();
        
        return Ok(());
    }
    
    println!("Missing components detected. Attempting automatic installation...");
    
    print!("This will attempt to install missing components on your system. Continue? (y/N): ");
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    if !input.trim().to_lowercase().starts_with('y') {
        println!("Installation cancelled by user.");
        show_manual_installation_guidance(&missing_components);
        return Err("User cancelled automatic installation. Please install missing components manually.".into());
    }
    
    println!("Starting installation process...");
    
    let mut failed_installations = Vec::new();
    
    for component in &missing_components {
        match *component {
            "OpenSSL" => {
                if let Err(e) = install_openssl() {
                    failed_installations.push(("OpenSSL", e));
                }
            }
            _ => {}
        }
    }
    
    // Re-check after installation attempts
    println!("Verifying installations...");
    let mut still_missing = Vec::new();
    
    for component in &missing_components {
        match *component {
            "OpenSSL" => {
                if check_openssl().is_err() {
                    still_missing.push("OpenSSL");
                }
            }
            _ => {}
        }
    }
    
    if still_missing.is_empty() {
        println!("All components successfully installed!");
        println!("You may need to restart your terminal for PATH changes to take effect.");
        return Ok(());
    }
    
    println!("  Some components could not be installed automatically:");
    for component in &still_missing {
        println!("   - {}", component);
    }
    
    if !failed_installations.is_empty() {
        println!("\nInstallation error details:");
        for (component, error) in &failed_installations {
            println!("   - {}: {}", component, error);
        }
    }
    
    show_manual_installation_guidance(&still_missing);
    
    Err("  Some system requirements could not be installed automatically. Please install them manually and try again.".into())
}

fn check_openssl() -> Result<(), String> {
    println!("   Running OpenSSL validation...");
    
    // Step 1: Check if environment variables are already properly set
    if let Ok(existing_dir) = std::env::var("OPENSSL_DIR") {
        println!("     Found existing OPENSSL_DIR: {}", existing_dir);
        if validate_openssl_installation(&existing_dir).is_ok() {
            println!("     Existing OpenSSL environment validated successfully");
            return Ok(());
        } else {
            println!("   Existing OPENSSL_DIR points to invalid installation, searching for alternatives...");
        }
    }
    
    // Step 2: Try to find OpenSSL command and validate version
    match find_and_validate_openssl_command() {
        Ok(openssl_info) => {
            println!("   OpenSSL command: {} ({})", openssl_info.version, openssl_info.path);
            
            // Try to derive installation directory from command location
            if let Some(install_dir) = derive_install_directory(&openssl_info.path) {
                if validate_openssl_installation(&install_dir).is_ok() {
                    if setup_openssl_environment_with_validation(&install_dir).is_ok() {
                        println!("   OpenSSL environment configured and validated");
                        return Ok(());
                    }
                }
            }
        }
        Err(e) => {
            println!("   OpenSSL command not found or invalid: {}", e);
        }
    }
    
    // Step 3: Try pkg-config detection (Linux/macOS)
    if !cfg!(target_os = "windows") {
        match detect_openssl_via_pkg_config() {
            Ok(pkg_info) => {
                println!("   OpenSSL via pkg-config: {}", pkg_info.version);
                if setup_openssl_environment_with_validation(&pkg_info.prefix).is_ok() {
                    println!("   OpenSSL environment configured via pkg-config");
                    return Ok(());
                }
            }
            Err(e) => {
                println!("   pkg-config detection failed: {}", e);
            }
        }
    }
    
    // Step 4: Comprehensive filesystem search with validation
    println!("   Searching filesystem for OpenSSL installations...");
    match find_openssl_installations() {
        Ok(installations) => {
            if installations.is_empty() {
                println!("   No OpenSSL installations found");
            } else {
                println!("   Found {} potential OpenSSL installation(s)", installations.len());
                
                // Try each installation, prioritizing by completeness and version
                for installation in installations {
                    println!("   Validating: {}", installation.path);
                    match validate_openssl_installation(&installation.path) {
                        Ok(validation) => {
                            println!("   Valid installation found: {} ({})", installation.path, validation.summary);
                            if setup_openssl_environment_with_validation(&installation.path).is_ok() {
                                println!("   OpenSSL environment configured and validated");
                                return Ok(());
                            }
                        }
                        Err(e) => {
                            println!("   Installation invalid: {}", e);
                        }
                    }
                }
            }
        }
        Err(e) => {
            println!("   Filesystem search failed: {}", e);
        }
    }
    
    // Step 5: Check for partial installations that might be fixable
    println!("   Checking for partial OpenSSL installations...");
    if let Some(fixable_path) = find_fixable_openssl_installation() {
        println!("   Found partial installation at: {}", fixable_path);
        println!("   This will be noted for potential repair during installation");
    }
    
    Err("No usable OpenSSL installation found".to_string())
}

#[derive(Debug)]
struct OpenSSLCommandInfo {
    path: String,
    version: String,
    major_version: u32,
}

#[derive(Debug)]
struct OpenSSLPkgInfo {
    prefix: String,
    version: String,
    lib_flags: String,
    include_flags: String,
}

#[derive(Debug)]
struct OpenSSLInstallation {
    path: String,
    confidence: u32, // 0-100, higher is better
    has_headers: bool,
    has_libs: bool,
    has_pkgconfig: bool,
    architecture: Option<String>,
}

#[derive(Debug)]
struct OpenSSLValidation {
    summary: String,
    has_development_files: bool,
    version: Option<String>,
    architecture: Option<String>,
}

fn find_and_validate_openssl_command() -> Result<OpenSSLCommandInfo, String> {
    match Command::new("openssl").arg("version").output() {
        Ok(output) if output.status.success() => {
            let version_output = String::from_utf8_lossy(&output.stdout);
            let version = version_output.trim().to_string();
            
            if version.is_empty() {
                return Err("OpenSSL command found but version output is empty".to_string());
            }
            
            let major_version = parse_openssl_major_version(&version).unwrap_or(0);
            if major_version == 0 {
                return Err(format!("Unable to parse OpenSSL version: {}", version));
            }
            
            // Check if this is a compatible version (1.1.1+ or 3.0+)
            if major_version < 1 || (major_version == 1 && !version.contains("1.1.1")) {
                return Err(format!("OpenSSL version {} is too old (need 1.1.1+ or 3.0+)", version));
            }
            
            let path = match which::which("openssl") {
                Ok(path) => path.to_string_lossy().to_string(),
                Err(_) => "openssl".to_string(),
            };
            
            Ok(OpenSSLCommandInfo { path, version, major_version })
        }
        Ok(_) => Err("OpenSSL command found but failed to execute".to_string()),
        Err(e) => Err(format!("OpenSSL command not found: {}", e)),
    }
}

fn parse_openssl_major_version(version: &str) -> Option<u32> {
    // Extract version number from strings like "OpenSSL 3.0.0 7 sep 2021"
    if let Some(version_part) = version.split_whitespace().nth(1) {
        if let Some(major) = version_part.split('.').next() {
            return major.parse().ok();
        }
    }
    None
}

fn derive_install_directory(openssl_command_path: &str) -> Option<String> {
    let path = std::path::Path::new(openssl_command_path);
    
    if let Some(bin_dir) = path.parent() {
        if bin_dir.file_name().and_then(|n| n.to_str()) == Some("bin") {
            if let Some(install_root) = bin_dir.parent() {
                return Some(install_root.to_string_lossy().to_string());
            }
        }
    }
    
    None
}

fn detect_openssl_via_pkg_config() -> Result<OpenSSLPkgInfo, String> {
    if !command_exists("pkg-config") {
        return Err("pkg-config not available".to_string());
    }
    
    match Command::new("pkg-config").args(&["--exists", "openssl"]).output() {
        Ok(output) if output.status.success() => {},
        _ => return Err("OpenSSL package not found via pkg-config".to_string()),
    }
    
    let version = match Command::new("pkg-config").args(&["--modversion", "openssl"]).output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        _ => return Err("Failed to get OpenSSL version via pkg-config".to_string()),
    };
    
    let prefix = match Command::new("pkg-config").args(&["--variable=prefix", "openssl"]).output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        _ => return Err("Failed to get OpenSSL prefix via pkg-config".to_string()),
    };
    
    let lib_flags = match Command::new("pkg-config").args(&["--libs", "openssl"]).output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        _ => String::new(),
    };
    
    let include_flags = match Command::new("pkg-config").args(&["--cflags", "openssl"]).output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        _ => String::new(),
    };
    
    Ok(OpenSSLPkgInfo { prefix, version, lib_flags, include_flags })
}

fn find_openssl_installations() -> Result<Vec<OpenSSLInstallation>, String> {
    let mut installations = Vec::new();
    
    let search_paths = if cfg!(target_os = "windows") {
        vec![
            // Standard installation paths
            "C:\\Program Files\\OpenSSL-Win64",
            "C:\\Program Files\\OpenSSL",
            "C:\\Program Files (x86)\\OpenSSL-Win32",
            "C:\\Program Files (x86)\\OpenSSL",
            "C:\\OpenSSL-Win64",
            "C:\\OpenSSL-Win32", 
            "C:\\OpenSSL",
            
            // Developer tool paths
            "C:\\tools\\openssl",
            "C:\\dev\\openssl",
            
            // vcpkg paths
            "C:\\vcpkg\\installed\\x64-windows",
            "C:\\vcpkg\\installed\\x86-windows",
            "C:\\tools\\vcpkg\\installed\\x64-windows",
            "C:\\tools\\vcpkg\\installed\\x86-windows",
            "C:\\dev\\vcpkg\\installed\\x64-windows",
            "C:\\dev\\vcpkg\\installed\\x86-windows",
            
            // Visual Studio paths
            "C:\\Program Files (x86)\\Windows Kits\\10\\Include\\*\\um",
            "C:\\Program Files\\Microsoft Visual Studio\\*\\*\\VC\\Tools\\MSVC\\*\\include",
        ]
    } else if cfg!(target_os = "macos") {
        vec![
            "/usr/local/opt/openssl@3",
            "/usr/local/opt/openssl@1.1",
            "/usr/local/opt/openssl",
            "/opt/homebrew/opt/openssl@3", 
            "/opt/homebrew/opt/openssl@1.1",
            "/opt/homebrew/opt/openssl",
            "/usr/local",
            "/opt/local",
            "/usr",
        ]
    } else {
        vec![
            "/usr/local",
            "/usr",
            "/opt/openssl",
            "/usr/local/ssl",
            "/opt/local",
        ]
    };
    
    for &path_pattern in &search_paths {
        if path_pattern.contains('*') {
            match glob::glob(path_pattern) {
                Ok(paths) => {
                    for path_result in paths {
                        if let Ok(path) = path_result {
                            if let Some(installation) = analyze_potential_installation(&path.to_string_lossy()) {
                                installations.push(installation);
                            }
                        }
                    }
                }
                Err(_) => continue,
            }
        } else {
            if let Some(installation) = analyze_potential_installation(path_pattern) {
                installations.push(installation);
            }
        }
    }
    
    installations.sort_by(|a, b| b.confidence.cmp(&a.confidence));
    
    Ok(installations)
}

fn analyze_potential_installation(path: &str) -> Option<OpenSSLInstallation> {
    let base_path = std::path::Path::new(path);
    if !base_path.exists() {
        return None;
    }
    
    let mut confidence: u32 = 10; // Base confidence for existing path
    let mut has_headers = false;
    let mut has_libs = false;
    let mut has_pkgconfig = false;
    let mut architecture = None;
    
    let include_paths = [
        base_path.join("include").join("openssl").join("opensslv.h"),
        base_path.join("include").join("openssl").join("ssl.h"),
        base_path.join("include").join("openssl").join("crypto.h"),
    ];
    
    for include_path in &include_paths {
        if include_path.exists() {
            has_headers = true;
            confidence += 20;
            break;
        }
    }
    
    let lib_paths = if cfg!(target_os = "windows") {
        vec![
            base_path.join("lib").join("libssl.lib"),
            base_path.join("lib").join("libcrypto.lib"),
            base_path.join("lib").join("ssl.lib"),
            base_path.join("lib").join("crypto.lib"),
            base_path.join("lib").join("VC").join("x64").join("MD").join("libssl.lib"),
            base_path.join("lib").join("VC").join("x64").join("MT").join("libssl.lib"),
        ]
    } else {
        vec![
            base_path.join("lib").join("libssl.so"),
            base_path.join("lib").join("libcrypto.so"),
            base_path.join("lib").join("libssl.a"),
            base_path.join("lib").join("libcrypto.a"),
            base_path.join("lib64").join("libssl.so"),
            base_path.join("lib64").join("libcrypto.so"),
            base_path.join("lib").join("libssl.dylib"),
            base_path.join("lib").join("libcrypto.dylib"),
        ]
    };
    
    for lib_path in &lib_paths {
        if lib_path.exists() {
            has_libs = true;
            confidence += 20;
            
            // Try to determine architecture
            if cfg!(target_os = "windows") {
                if lib_path.to_string_lossy().contains("x64") {
                    architecture = Some("x64".to_string());
                } else if lib_path.to_string_lossy().contains("x86") || lib_path.to_string_lossy().contains("Win32") {
                    architecture = Some("x86".to_string());
                }
            }
            break;
        }
    }
    
    let pkgconfig_paths = [
        base_path.join("lib").join("pkgconfig").join("openssl.pc"),
        base_path.join("lib64").join("pkgconfig").join("openssl.pc"),
    ];
    
    for pkgconfig_path in &pkgconfig_paths {
        if pkgconfig_path.exists() {
            has_pkgconfig = true;
            confidence += 10;
            break;
        }
    }
    
    if has_headers && has_libs {
        confidence += 30;
    }
    
    if !has_headers && !has_libs {
        confidence = confidence.saturating_sub(30);
    }
    
    if confidence > 20 {
        Some(OpenSSLInstallation {
            path: path.to_string(),
            confidence,
            has_headers,
            has_libs,
            has_pkgconfig,
            architecture,
        })
    } else {
        None
    }
}

fn validate_openssl_installation(path: &str) -> Result<OpenSSLValidation, String> {
    let base_path = std::path::Path::new(path);
    
    if !base_path.exists() {
        return Err(format!("Path does not exist: {}", path));
    }
    
    let mut validation_errors = Vec::new();
    let mut has_development_files = false;
    let mut version = None;
    let mut architecture = None;
    
    // Check for essential header files
    let required_headers = [
        "openssl/opensslv.h",
        "openssl/ssl.h", 
        "openssl/crypto.h",
        "openssl/evp.h",
    ];
    
    let include_dir = base_path.join("include");
    if include_dir.exists() {
        let mut missing_headers = Vec::new();
        for header in &required_headers {
            let header_path = include_dir.join(header);
            if !header_path.exists() {
                missing_headers.push(*header);
            }
        }
        
        if missing_headers.is_empty() {
            has_development_files = true;
            
            if let Ok(content) = std::fs::read_to_string(include_dir.join("openssl/opensslv.h")) {
                version = extract_version_from_header(&content);
            }
        } else {
            validation_errors.push(format!("Missing headers: {}", missing_headers.join(", ")));
        }
    } else {
        validation_errors.push("Include directory not found".to_string());
    }
    
    let lib_dirs = [
        base_path.join("lib"),
        base_path.join("lib64"),
        base_path.join("lib").join("VC").join("x64").join("MD"),
        base_path.join("lib").join("VC").join("x64").join("MT"),
    ];
    
    let mut lib_found = false;
    for lib_dir in &lib_dirs {
        if lib_dir.exists() {
            let required_libs = if cfg!(target_os = "windows") {
                vec!["libssl.lib", "libcrypto.lib"]
            } else {
                vec!["libssl.so", "libcrypto.so", "libssl.a", "libcrypto.a", "libssl.dylib", "libcrypto.dylib"]
            };
            
            let mut found_any = false;
            for lib_name in &required_libs {
                if lib_dir.join(lib_name).exists() {
                    found_any = true;
                    lib_found = true;
                    
                    if architecture.is_none() {
                        if lib_dir.to_string_lossy().contains("x64") {
                            architecture = Some("x64".to_string());
                        } else if lib_dir.to_string_lossy().contains("x86") {
                            architecture = Some("x86".to_string());
                        }
                    }
                    break;
                }
            }
            
            if found_any {
                break;
            }
        }
    }
    
    if !lib_found {
        validation_errors.push("Required library files not found".to_string());
    }
    
    if !validation_errors.is_empty() {
        return Err(validation_errors.join("; "));
    }
    
    let summary = format!(
        "Complete installation with {} files{}",
        if has_development_files { "development" } else { "runtime" },
        version.as_ref().map(|v| format!(" ({})", v)).unwrap_or_default()
    );
    
    Ok(OpenSSLValidation {
        summary,
        has_development_files,
        version,
        architecture,
    })
}

fn extract_version_from_header(content: &str) -> Option<String> {
    for line in content.lines() {
        if line.contains("OPENSSL_VERSION_TEXT") && line.contains('"') {
            if let Some(start) = line.find('"') {
                if let Some(end) = line.rfind('"') {
                    if end > start {
                        return Some(line[start+1..end].to_string());
                    }
                }
            }
        }
    }
    None
}

fn setup_openssl_environment_with_validation(openssl_dir: &str) -> Result<(), String> {
    setup_openssl_environment()?;
    
    validate_openssl_environment(openssl_dir)
}

fn validate_openssl_environment(openssl_dir: &str) -> Result<(), String> {
    println!("   Validating OpenSSL environment with compilation test...");
    
    let test_code = r#"
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <stdio.h>

int main() {
    printf("OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);
    SSL_library_init();
    return 0;
}
"#;
    
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("openssl_test.c");
    let test_exe = temp_dir.join(if cfg!(target_os = "windows") { "openssl_test.exe" } else { "openssl_test" });
    
    std::fs::write(&test_file, test_code).map_err(|e| format!("Failed to write test file: {}", e))?;
    
    let compile_result = if cfg!(target_os = "windows") {
        compile_test_windows(&test_file, &test_exe, openssl_dir)
    } else {
        compile_test_unix(&test_file, &test_exe, openssl_dir)
    };
    
    let _ = std::fs::remove_file(&test_file);
    let _ = std::fs::remove_file(&test_exe);
    
    match compile_result {
        Ok(_) => {
            println!("   OpenSSL environment validation successful");
            Ok(())
        }
        Err(e) => {
            println!("   Environment validation failed: {}", e);
            Err(format!("OpenSSL environment validation failed: {}", e))
        }
    }
}

fn compile_test_windows(test_file: &std::path::Path, test_exe: &std::path::Path, openssl_dir: &str) -> Result<(), String> {
    let output = Command::new("cl")
        .args(&[
            test_file.to_str().unwrap(),
            &format!("/I{}/include", openssl_dir),
            &format!("/Fe:{}", test_exe.to_str().unwrap()),
            &format!("{}/lib/libssl.lib", openssl_dir),
            &format!("{}/lib/libcrypto.lib", openssl_dir),
        ])
        .output();
        
    match output {
        Ok(result) if result.status.success() => return Ok(()),
        Ok(result) => {
            let stderr = String::from_utf8_lossy(&result.stderr);
            let alt_lib_paths = [
                format!("{}/lib/VC/x64/MD", openssl_dir),
                format!("{}/lib/VC/x64/MT", openssl_dir),
            ];
            
            for lib_path in &alt_lib_paths {
                let output = Command::new("cl")
                    .args(&[
                        test_file.to_str().unwrap(),
                        &format!("/I{}/include", openssl_dir),
                        &format!("/Fe:{}", test_exe.to_str().unwrap()),
                        &format!("{}/libssl.lib", lib_path),
                        &format!("{}/libcrypto.lib", lib_path),
                    ])
                    .output();
                    
                if let Ok(result) = output {
                    if result.status.success() {
                        return Ok(());
                    }
                }
            }
            
            return Err(format!("MSVC compilation failed: {}", stderr));
        }
        Err(_) => {
            // MSVC not available, try GCC/MinGW
            let output = Command::new("gcc")
                .args(&[
                    test_file.to_str().unwrap(),
                    "-o", test_exe.to_str().unwrap(),
                    &format!("-I{}/include", openssl_dir),
                    &format!("-L{}/lib", openssl_dir),
                    "-lssl", "-lcrypto",
                ])
                .output();
                
            match output {
                Ok(result) if result.status.success() => Ok(()),
                Ok(result) => {
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    Err(format!("GCC compilation failed: {}", stderr))
                }
                Err(_) => Err("No suitable compiler found (tried cl, gcc)".to_string()),
            }
        }
    }
}

fn compile_test_unix(test_file: &std::path::Path, test_exe: &std::path::Path, openssl_dir: &str) -> Result<(), String> {
    let output = Command::new("cc")
        .args(&[
            test_file.to_str().unwrap(),
            "-o", test_exe.to_str().unwrap(),
            &format!("-I{}/include", openssl_dir),
            &format!("-L{}/lib", openssl_dir),
            &format!("-L{}/lib64", openssl_dir),
            "-lssl", "-lcrypto",
        ])
        .output();
        
    match output {
        Ok(result) if result.status.success() => Ok(()),
        Ok(result) => {
            let stderr = String::from_utf8_lossy(&result.stderr);
            Err(format!("Compilation failed: {}", stderr))
        }
        Err(e) => Err(format!("Compilation command failed: {}", e)),
    }
}

fn find_fixable_openssl_installation() -> Option<String> {
    // Look for installations that have some components but not others
    // This could guide repair during installation
    
    let search_paths = if cfg!(target_os = "windows") {
        vec![
            "C:\\Program Files\\OpenSSL-Win64",
            "C:\\Program Files\\OpenSSL",
            "C:\\vcpkg\\installed\\x64-windows",
        ]
    } else {
        vec![
            "/usr/local",
            "/usr", 
            "/opt/local",
        ]
    };
    
    for path in search_paths {
        let base_path = std::path::Path::new(path);
        if base_path.exists() {
            let has_some_headers = base_path.join("include").exists();
            let has_some_libs = base_path.join("lib").exists() || base_path.join("lib64").exists();
            
            // If it has some components but validation fails, it might be fixable
            if has_some_headers || has_some_libs {
                if validate_openssl_installation(path).is_err() {
                    return Some(path.to_string());
                }
            }
        }
    }
    
    None
}

// Helper function to check if a command exists
fn command_exists(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn show_manual_installation_guidance(missing_components: &[&str]) {
    println!("\nManual installation required for:");
    for component in missing_components {
        println!("   - {}", component);
    }
    
    println!("\nSearch online for installation guides:");
    for component in missing_components {
        match *component {
            "OpenSSL" => {
                println!("   - 'OpenSSL installation {} development headers'", std::env::consts::OS);
                if cfg!(target_os = "windows") {
                    println!("     Also search for 'OPENSSL_DIR environment variable Windows'");
                }
            }
            _ => {}
        }
    }
    
    println!("\nCommon solutions:");
    println!("   1. Run this program as administrator/sudo");
    println!("   2. Install a package manager if you don't have one");
    println!("   3. Add installed components to your PATH");
    println!("   4. Restart your terminal after installation");
    
    if cfg!(target_os = "windows") {
        println!("\nWindows-specific troubleshooting:");
        println!("   1. If vcpkg detection fails:");
        println!("      - Install Git: https://git-scm.com/download/win");
        println!("      - Install Visual Studio Build Tools or Visual Studio Community");
        println!("      - Run PowerShell as Administrator");
        println!("   2. If package managers aren't working:");
        println!("      - Install Chocolatey: https://chocolatey.org/install");
        println!("      - Install Scoop: https://scoop.sh");
        println!("   3. PATH issues:");
        println!("      - Close and restart your terminal");
        println!("      - Check if components are in System > Environment Variables > PATH");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_openssl_check() {
        // This test might fail if OpenSSL is not installed
        // but it should not panic
        let _ = check_openssl();
    }
} 
