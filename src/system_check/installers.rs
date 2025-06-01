use std::process::Command;
use super::utils::{
    command_exists, run_command_with_retry, run_command_with_retry_sudo
};
use super::package_managers::{
    install_chocolatey, install_scoop, install_homebrew
};

pub fn install_openssl() -> Result<(), String> {
    println!("Installing OpenSSL with comprehensive validation...");
    
    let mut installation_attempts = Vec::new();
    let mut last_error = String::new();
    
    if cfg!(target_os = "windows") {
        let methods = vec![
            ("Existing Chocolatey", Box::new(|| install_via_chocolatey_existing()) as Box<dyn Fn() -> Result<String, String>>),
            ("Install Chocolatey + OpenSSL", Box::new(|| install_via_chocolatey_new())),
            ("Existing Scoop", Box::new(|| install_via_scoop_existing())),
            ("Install Scoop + OpenSSL", Box::new(|| install_via_scoop_new())),
            ("Existing vcpkg", Box::new(|| install_via_vcpkg_existing())),
        ];
        
        for (method_name, install_fn) in methods {
            println!("   Trying: {}", method_name);
            match install_fn() {
                Ok(install_path) => {
                    installation_attempts.push((method_name.to_string(), Ok(install_path.clone())));
                    
                    // Validate the installation
                    match validate_and_setup_installation(&install_path) {
                        Ok(_) => {
                            println!("   OpenSSL successfully installed via {}", method_name);
                            return Ok(());
                        }
                        Err(e) => {
                            println!("   Installation succeeded but validation failed: {}", e);
                            last_error = format!("Validation failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    installation_attempts.push((method_name.to_string(), Err(e.clone())));
                    println!("   {} failed: {}", method_name, e);
                    last_error = e;
                }
            }
        }
    } else if cfg!(target_os = "macos") {
        let methods = vec![
            ("Existing Homebrew", Box::new(|| install_via_homebrew_existing()) as Box<dyn Fn() -> Result<String, String>>),
            ("Install Homebrew + OpenSSL", Box::new(|| install_via_homebrew_new())),
            ("MacPorts", Box::new(|| install_via_macports())),
        ];
        
        for (method_name, install_fn) in methods {
            println!("   Trying: {}", method_name);
            match install_fn() {
                Ok(install_path) => {
                    installation_attempts.push((method_name.to_string(), Ok(install_path.clone())));
                    
                    match validate_and_setup_installation(&install_path) {
                        Ok(_) => {
                            println!("   OpenSSL successfully installed via {}", method_name);
                            return Ok(());
                        }
                        Err(e) => {
                            println!("   Installation succeeded but validation failed: {}", e);
                            last_error = format!("Validation failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    installation_attempts.push((method_name.to_string(), Err(e.clone())));
                    println!("   {} failed: {}", method_name, e);
                    last_error = e;
                }
            }
        }
    } else {
        let methods = vec![
            ("apt-get (Debian/Ubuntu)", Box::new(|| install_via_apt()) as Box<dyn Fn() -> Result<String, String>>),
            ("dnf (Fedora/RHEL)", Box::new(|| install_via_dnf())),
            ("yum (CentOS/RHEL)", Box::new(|| install_via_yum())),
            ("pacman (Arch)", Box::new(|| install_via_pacman())),
            ("zypper (openSUSE)", Box::new(|| install_via_zypper())),
        ];
        
        for (method_name, install_fn) in methods {
            println!("   Trying: {}", method_name);
            match install_fn() {
                Ok(install_path) => {
                    installation_attempts.push((method_name.to_string(), Ok(install_path.clone())));
                    
                    match validate_and_setup_installation(&install_path) {
                        Ok(_) => {
                            println!("   OpenSSL successfully installed via {}", method_name);
                            return Ok(());
                        }
                        Err(e) => {
                            println!("   Installation succeeded but validation failed: {}", e);
                            last_error = format!("Validation failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    installation_attempts.push((method_name.to_string(), Err(e.clone())));
                    println!("   {} failed: {}", method_name, e);
                    last_error = e;
                }
            }
        }
    }
    
    // All methods failed - provide comprehensive error report and guidance
    println!("   All installation methods failed");
    println!("   Installation attempt summary:");
    for (method, result) in &installation_attempts {
        match result {
            Ok(_) => println!("       {}: Succeeded but validation failed", method),
            Err(e) => println!("       {}: {}", method, e),
        }
    }
    
    provide_manual_installation_guidance();
    
    Err(format!("All {} installation attempts failed. Last error: {}", 
               installation_attempts.len(), last_error))
}

fn install_via_chocolatey_existing() -> Result<String, String> {
    if !command_exists("choco") {
        return Err("Chocolatey not found".to_string());
    }
    
    println!("     Installing OpenSSL via Chocolatey...");
    run_command_with_retry("choco", &["install", "openssl", "-y"], 3)?;
    
    // Try to find the installation
    let possible_paths = [
        "C:\\Program Files\\OpenSSL-Win64",
        "C:\\Program Files\\OpenSSL",
        "C:\\tools\\openssl",
    ];
    
    for path in &possible_paths {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }
    
    Err("OpenSSL installed but could not locate installation directory".to_string())
}

fn install_via_chocolatey_new() -> Result<String, String> {
    println!("     Installing Chocolatey...");
    install_chocolatey()?;
    
    println!("     Installing OpenSSL via newly installed Chocolatey...");
    std::thread::sleep(std::time::Duration::from_secs(2));
    run_command_with_retry("choco", &["install", "openssl", "-y"], 3)?;
    
    let possible_paths = [
        "C:\\Program Files\\OpenSSL-Win64",
        "C:\\Program Files\\OpenSSL",
        "C:\\tools\\openssl",
    ];
    
    for path in &possible_paths {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }
    
    Err("OpenSSL installed but could not locate installation directory".to_string())
}

fn install_via_scoop_existing() -> Result<String, String> {
    if !command_exists("scoop") {
        return Err("Scoop not found".to_string());
    }
    
    println!("     Installing OpenSSL via Scoop...");
    run_command_with_retry("scoop", &["install", "openssl"], 3)?;
    
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        let scoop_path = format!("{}\\scoop\\apps\\openssl\\current", userprofile);
        if std::path::Path::new(&scoop_path).exists() {
            return Ok(scoop_path);
        }
    }
    
    Err("OpenSSL installed via Scoop but could not locate installation directory".to_string())
}

fn install_via_scoop_new() -> Result<String, String> {
    println!("     Installing Scoop...");
    install_scoop()?;
    
    println!("     Installing OpenSSL via newly installed Scoop...");
    std::thread::sleep(std::time::Duration::from_secs(2));
    run_command_with_retry("scoop", &["install", "openssl"], 3)?;
    
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        let scoop_path = format!("{}\\scoop\\apps\\openssl\\current", userprofile);
        if std::path::Path::new(&scoop_path).exists() {
            return Ok(scoop_path);
        }
    }
    
    Err("OpenSSL installed via Scoop but could not locate installation directory".to_string())
}

fn install_via_vcpkg_existing() -> Result<String, String> {
    let vcpkg_paths = [
        "C:\\vcpkg\\vcpkg.exe",
        "C:\\tools\\vcpkg\\vcpkg.exe",
        "C:\\dev\\vcpkg\\vcpkg.exe",
    ];
    
    let mut vcpkg_root = None;
    for path in &vcpkg_paths {
        if std::path::Path::new(path).exists() {
            vcpkg_root = Some(path.trim_end_matches("\\vcpkg.exe"));
            break;
        }
    }
    
    let vcpkg_root = vcpkg_root.ok_or("vcpkg not found")?;
    
    println!("     Installing OpenSSL via vcpkg...");
    let vcpkg_exe = format!("{}\\vcpkg.exe", vcpkg_root);
    run_command_with_retry(&vcpkg_exe, &["install", "openssl:x64-windows"], 5)?;
    
    let install_path = format!("{}\\installed\\x64-windows", vcpkg_root);
    if std::path::Path::new(&install_path).exists() {
        Ok(install_path)
    } else {
        Err("vcpkg installation completed but path not found".to_string())
    }
}

fn install_via_homebrew_existing() -> Result<String, String> {
    if !command_exists("brew") {
        return Err("Homebrew not found".to_string());
    }
    
    println!("     Installing OpenSSL via Homebrew...");
    run_command_with_retry("brew", &["install", "openssl@3"], 3)?;
    
    let possible_paths = [
        "/opt/homebrew/opt/openssl@3",
        "/opt/homebrew/opt/openssl",
        "/usr/local/opt/openssl@3",
        "/usr/local/opt/openssl",
    ];
    
    for path in &possible_paths {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }
    
    Err("OpenSSL installed via Homebrew but could not locate installation directory".to_string())
}

fn install_via_homebrew_new() -> Result<String, String> {
    println!("     Installing Homebrew...");
    install_homebrew()?;
    
    println!("     Installing OpenSSL via newly installed Homebrew...");
    std::thread::sleep(std::time::Duration::from_secs(2));
    run_command_with_retry("brew", &["install", "openssl@3"], 3)?;
    
    let possible_paths = [
        "/opt/homebrew/opt/openssl@3",
        "/opt/homebrew/opt/openssl",
        "/usr/local/opt/openssl@3",
        "/usr/local/opt/openssl",
    ];
    
    for path in &possible_paths {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }
    
    Err("OpenSSL installed via Homebrew but could not locate installation directory".to_string())
}

fn install_via_macports() -> Result<String, String> {
    if !command_exists("port") {
        return Err("MacPorts not found".to_string());
    }
    
    println!("     Installing OpenSSL via MacPorts...");
    run_command_with_retry_sudo("port", &["install", "openssl3"], 3)?;
    
    let possible_paths = [
        "/opt/local",
    ];
    
    for path in &possible_paths {
        if std::path::Path::new(path).join("include").join("openssl").exists() {
            return Ok(path.to_string());
        }
    }
    
    Err("OpenSSL installed via MacPorts but could not locate installation directory".to_string())
}

fn install_via_apt() -> Result<String, String> {
    if !command_exists("apt-get") {
        return Err("apt-get not found".to_string());
    }
    
    println!("     Updating package list...");
    run_command_with_retry_sudo("apt-get", &["update"], 2)?;
    
    println!("     Installing OpenSSL development packages...");
    run_command_with_retry_sudo("apt-get", &["install", "-y", "libssl-dev", "openssl"], 3)?;
    
    Ok("/usr".to_string())
}

fn install_via_dnf() -> Result<String, String> {
    if !command_exists("dnf") {
        return Err("dnf not found".to_string());
    }
    
    println!("     Installing OpenSSL development packages...");
    run_command_with_retry_sudo("dnf", &["install", "-y", "openssl-devel", "openssl"], 3)?;
    
    Ok("/usr".to_string())
}

fn install_via_yum() -> Result<String, String> {
    if !command_exists("yum") {
        return Err("yum not found".to_string());
    }
    
    println!("     Installing OpenSSL development packages...");
    run_command_with_retry_sudo("yum", &["install", "-y", "openssl-devel", "openssl"], 3)?;
    
    Ok("/usr".to_string())
}

fn install_via_pacman() -> Result<String, String> {
    if !command_exists("pacman") {
        return Err("pacman not found".to_string());
    }
    
    println!("     Installing OpenSSL packages...");
    run_command_with_retry_sudo("pacman", &["-S", "--noconfirm", "openssl"], 3)?;
    
    Ok("/usr".to_string())
}

fn install_via_zypper() -> Result<String, String> {
    if !command_exists("zypper") {
        return Err("zypper not found".to_string());
    }
    
    println!("     Installing OpenSSL development packages...");
    run_command_with_retry_sudo("zypper", &["install", "-y", "libopenssl-devel", "openssl"], 3)?;
    
    Ok("/usr".to_string())
}

fn validate_and_setup_installation(install_path: &str) -> Result<(), String> {
    println!("     Validating installation at: {}", install_path);
    
    validate_installation_structure(install_path)?;
    
    println!("     Setting up environment variables...");
    std::env::set_var("OPENSSL_DIR", install_path);
    
    update_path_for_openssl(install_path)?;
    
    test_openssl_compilation(install_path)?;
    
    make_environment_persistent(install_path)?;
    
    println!("     Installation validation completed");
    
    Ok(())
}

fn validate_installation_structure(install_path: &str) -> Result<(), String> {
    let base_path = std::path::Path::new(install_path);
    
    if !base_path.exists() {
        return Err(format!("Installation path does not exist: {}", install_path));
    }
    
    let include_dir = base_path.join("include");
    let lib_dir = base_path.join("lib");
    let lib64_dir = base_path.join("lib64");
    
    if !include_dir.exists() {
        return Err("Include directory not found".to_string());
    }
    
    let openssl_include = include_dir.join("openssl");
    if !openssl_include.exists() {
        return Err("OpenSSL include directory not found".to_string());
    }
    
    let required_headers = ["opensslv.h", "ssl.h", "crypto.h"];
    for header in &required_headers {
        let header_path = openssl_include.join(header);
        if !header_path.exists() {
            return Err(format!("Required header {} not found", header));
        }
    }
    
    if !lib_dir.exists() && !lib64_dir.exists() {
        return Err("Library directory not found (checked both lib and lib64)".to_string());
    }
    
    let lib_dirs = [&lib_dir, &lib64_dir];
    let mut lib_found = false;
    
    for lib_dir in &lib_dirs {
        if lib_dir.exists() {
            let lib_extensions = if cfg!(target_os = "windows") {
                vec!["lib"]
            } else if cfg!(target_os = "macos") {
                vec!["dylib", "a"]
            } else {
                vec!["so", "a"]
            };
            
            for ext in &lib_extensions {
                let ssl_lib = lib_dir.join(format!("libssl.{}", ext));
                let crypto_lib = lib_dir.join(format!("libcrypto.{}", ext));
                
                if ssl_lib.exists() && crypto_lib.exists() {
                    lib_found = true;
                    break;
                }
            }
            
            if lib_found {
                break;
            }
        }
    }
    
    if !lib_found {
        return Err("Required OpenSSL library files not found".to_string());
    }
    
    println!("     Installation structure validated");
    Ok(())
}

fn update_path_for_openssl(install_path: &str) -> Result<(), String> {
    use super::utils::add_to_path;
    
    let bin_dir = std::path::Path::new(install_path).join("bin");
    if bin_dir.exists() {
        let bin_path = bin_dir.to_string_lossy().to_string();
        if let Err(_e) = add_to_path(&bin_path) {
            // Don't fail completely if PATH update fails
            println!("     OpenSSL binary not found, PATH not updated");
            return Ok(());
        }
    } else {
        println!("     OpenSSL binary not found, PATH not updated");
    }
    
    println!("     Testing OpenSSL with compilation test...");
    test_openssl_compilation(install_path)
}

fn test_openssl_compilation(install_path: &str) -> Result<(), String> {
    // Create a simple test program
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
    let test_file = temp_dir.join("openssl_install_test.c");
    let test_exe = temp_dir.join(if cfg!(target_os = "windows") { 
        "openssl_install_test.exe" 
    } else { 
        "openssl_install_test" 
    });
    
    std::fs::write(&test_file, test_code)
        .map_err(|e| format!("Failed to write test file: {}", e))?;
    
    let compile_result = if cfg!(target_os = "windows") {
        test_compile_windows(&test_file, &test_exe, install_path)
    } else {
        test_compile_unix(&test_file, &test_exe, install_path)
    };
    
    let _ = std::fs::remove_file(&test_file);
    let _ = std::fs::remove_file(&test_exe);
    
    match compile_result {
        Ok(_) => {
            println!("     Compilation test passed");
            Ok(())
        }
        Err(e) => {
            println!("     Compilation test failed: {}", e);
            Err(format!("OpenSSL compilation test failed: {}", e))
        }
    }
}

fn test_compile_windows(test_file: &std::path::Path, test_exe: &std::path::Path, openssl_dir: &str) -> Result<(), String> {
    // Try MSVC first
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
        Ok(_) => {
            // Try alternative lib paths for vcpkg
            let alt_lib_paths = [
                format!("{}/lib", openssl_dir),
                format!("{}/debug/lib", openssl_dir),
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
        }
        Err(_) => {
            // Try GCC/MinGW
            let output = Command::new("gcc")
                .args(&[
                    test_file.to_str().unwrap(),
                    "-o", test_exe.to_str().unwrap(),
                    &format!("-I{}/include", openssl_dir),
                    &format!("-L{}/lib", openssl_dir),
                    "-lssl", "-lcrypto",
                ])
                .output();
                
            if let Ok(result) = output {
                if result.status.success() {
                    return Ok(());
                }
            }
        }
    }
    
    Err("Could not compile test program with any available compiler".to_string())
}

fn test_compile_unix(test_file: &std::path::Path, test_exe: &std::path::Path, openssl_dir: &str) -> Result<(), String> {
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

fn make_environment_persistent(install_path: &str) -> Result<(), String> {
    println!("     Making environment variables persistent...");
    
    if cfg!(target_os = "windows") {
        // Use setx to make OPENSSL_DIR persistent on Windows
        let _ = Command::new("setx")
            .args(&["OPENSSL_DIR", install_path])
            .output();
    }
    
    println!("     Environment configured for current session");
    println!("     Note: You may need to restart your terminal for changes to take effect");
    
    Ok(())
}

fn provide_manual_installation_guidance() {
    println!("\n=== MANUAL INSTALLATION GUIDANCE ===");
    
    if cfg!(target_os = "windows") {
        println!("Windows Options:");
        println!("   1. Download from: https://slproweb.com/products/Win32OpenSSL.html");
        println!("   2. Install via Visual Studio: Install 'MSVC v143 - VS 2022 C++ x64/x86 build tools'");
        println!("   3. Install Chocolatey: https://chocolatey.org/install");
        println!("   4. Install vcpkg: https://github.com/Microsoft/vcpkg");
    } else if cfg!(target_os = "macos") {
        println!("macOS Options:");
        println!("   1. Install Homebrew: /bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"");
        println!("   2. Install via Homebrew: brew install openssl@3");
        println!("   3. Install MacPorts: https://www.macports.org/install.php");
        println!("   4. Install via MacPorts: sudo port install openssl3");
    } else {
        println!("Linux Options:");
        println!("   Ubuntu/Debian: sudo apt-get install libssl-dev openssl");
        println!("   Fedora/RHEL: sudo dnf install openssl-devel openssl");
        println!("   CentOS: sudo yum install openssl-devel openssl");
        println!("   Arch: sudo pacman -S openssl");
        println!("   openSUSE: sudo zypper install libopenssl-devel openssl");
    }
    
    println!("\nAfter installation:");
    println!("   1. Restart your terminal");
    println!("   2. Set OPENSSL_DIR environment variable to the installation path");
    println!("   3. Add OpenSSL bin directory to your PATH");
    println!("   4. Re-run this program");
} 