use std::env;
use std::process::Command;
use std::path::Path;

pub fn setup_openssl_environment() -> Result<(), String> {
    if cfg!(target_os = "windows") {
        setup_openssl_environment_windows()
    } else if cfg!(target_os = "macos") {
        setup_openssl_environment_macos()
    } else {
        setup_openssl_environment_linux()
    }
}

pub fn setup_cmake_environment() -> Result<(), String> {
    if cfg!(target_os = "windows") {
        setup_cmake_environment_windows()
    } else if cfg!(target_os = "macos") {
        setup_cmake_environment_macos()
    } else {
        setup_cmake_environment_linux()
    }
}

fn setup_openssl_environment_windows() -> Result<(), String> {
    println!("   Configuring OpenSSL environment for Windows...");
    
    // Common OpenSSL installation paths on Windows
    let openssl_paths = [
        "C:\\Program Files\\OpenSSL-Win64",
        "C:\\Program Files\\OpenSSL",
        "C:\\OpenSSL-Win64",
        "C:\\OpenSSL",
        "C:\\tools\\openssl",
        "C:\\vcpkg\\installed\\x64-windows",
        "C:\\tools\\vcpkg\\installed\\x64-windows",
        "C:\\dev\\vcpkg\\installed\\x64-windows",
    ];
    
    let mut openssl_dir = None;
    
    for base_path in &openssl_paths {
        if Path::new(base_path).exists() {
            let include_path = Path::new(base_path).join("include");
            if include_path.exists() {
                openssl_dir = Some(base_path.to_string());
                break;
            }
        }
    }
    
    if let Some(dir) = openssl_dir {
        env::set_var("OPENSSL_DIR", &dir);
        println!("   OPENSSL_DIR: {}", dir);
        
        let _ = set_persistent_env_var_windows("OPENSSL_DIR", &dir);
        
        Ok(())
    } else {
        Err("Could not locate OpenSSL installation".to_string())
    }
}

fn setup_openssl_environment_macos() -> Result<(), String> {
    println!("   Configuring OpenSSL environment for macOS...");
    
    if let Ok(output) = Command::new("pkg-config").args(&["--variable=prefix", "openssl"]).output() {
        if output.status.success() {
            let prefix = String::from_utf8_lossy(&output.stdout).trim().to_string();
            env::set_var("OPENSSL_DIR", &prefix);
            println!("   OPENSSL_DIR: {}", prefix);
            return Ok(());
        }
    }
    
    // Check common macOS OpenSSL installation paths
    let common_paths = [
        "/opt/homebrew/opt/openssl@3",
        "/opt/homebrew/opt/openssl@1.1",
        "/opt/homebrew/opt/openssl",
        "/usr/local/opt/openssl@3",
        "/usr/local/opt/openssl@1.1",
        "/usr/local/opt/openssl",
        "/usr/local",
    ];
    
    for path in &common_paths {
        let include_path = Path::new(path).join("include");
        let openssl_h = include_path.join("openssl").join("opensslv.h");
        if openssl_h.exists() {
            env::set_var("OPENSSL_DIR", path);
            println!("   OPENSSL_DIR: {}", path);
            return Ok(());
        }
    }
    
    Err("Could not locate OpenSSL installation".to_string())
}

fn setup_openssl_environment_linux() -> Result<(), String> {
    println!("   Configuring OpenSSL environment for Linux...");
    
    if let Ok(output) = Command::new("pkg-config").args(&["--variable=prefix", "openssl"]).output() {
        if output.status.success() {
            let prefix = String::from_utf8_lossy(&output.stdout).trim().to_string();
            env::set_var("OPENSSL_DIR", &prefix);
            println!("   OPENSSL_DIR: {}", prefix);
            return Ok(());
        }
    }
    
    // Check common Linux OpenSSL paths
    let common_paths = [
        "/usr",
        "/usr/local",
        "/opt/openssl",
        "/usr/local/ssl",
    ];
    
    for path in &common_paths {
        let include_path = Path::new(path).join("include");
        let openssl_h = include_path.join("openssl").join("opensslv.h");
        if openssl_h.exists() {
            env::set_var("OPENSSL_DIR", path);
            println!("   OPENSSL_DIR: {}", path);
            return Ok(());
        }
    }
    
    Err("Could not locate OpenSSL installation".to_string())
}

fn setup_cmake_environment_windows() -> Result<(), String> {
    println!("   Configuring CMake environment for Windows...");
    
    // Common CMake installation paths on Windows
    let cmake_paths = [
        "C:\\Program Files\\CMake\\bin",
        "C:\\Program Files (x86)\\CMake\\bin",
        "C:\\tools\\cmake\\bin",
        "C:\\cmake\\bin",
    ];
    
    for path in &cmake_paths {
        if Path::new(path).join("cmake.exe").exists() {
            add_to_path_windows(path)?;
            println!("   Added CMake to PATH: {}", path);
            return Ok(());
        }
    }
    
    if let Ok(output) = Command::new("cmake").arg("--version").output() {
        if output.status.success() {
            println!("   CMake: Already available in PATH");
            return Ok(());
        }
    }
    
    Err("Could not locate CMake installation".to_string())
}

fn setup_cmake_environment_macos() -> Result<(), String> {
    println!("   Configuring CMake environment for macOS...");
    
    if let Ok(output) = Command::new("cmake").arg("--version").output() {
        if output.status.success() {
            println!("   CMake: Available");
            return Ok(());
        }
    }
    
    if let Ok(output) = Command::new("brew").args(&["install", "cmake"]).output() {
        if output.status.success() {
            println!("   CMake: Installed via Homebrew");
            return Ok(());
        }
    }
    
    Err("Could not locate or install CMake".to_string())
}

fn setup_cmake_environment_linux() -> Result<(), String> {
    println!("   Configuring CMake environment for Linux...");
    
    if let Ok(output) = Command::new("cmake").arg("--version").output() {
        if output.status.success() {
            println!("   CMake: Available");
            return Ok(());
        }
    }
    
    Err("CMake not available - please install via package manager".to_string())
}

#[cfg(target_os = "windows")]
fn set_persistent_env_var_windows(name: &str, value: &str) -> Result<(), String> {
    use std::process::Command;
    
    match Command::new("setx")
        .args(&[name, value])
        .output()
    {
        Ok(output) if output.status.success() => {
            println!("   Environment variable {} set persistently", name);
            Ok(())
        }
        Ok(_) => {
            println!("   Failed to set {} persistently, but available for current session", name);
            Ok(())
        }
        Err(e) => {
            println!("   Could not set {} persistently: {}", name, e);
            Ok(()) // Don't fail the whole process for this
        }
    }
}

#[cfg(target_os = "windows")]
fn add_to_path_windows(new_path: &str) -> Result<(), String> {
    if let Ok(current_path) = env::var("PATH") {
        if !current_path.contains(new_path) {
            let new_full_path = format!("{};{}", current_path, new_path);
            env::set_var("PATH", &new_full_path);
            
            let _ = set_persistent_env_var_windows("PATH", &new_full_path);
        }
    }
    
    Ok(())
} 