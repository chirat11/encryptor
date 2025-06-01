use std::process::Command;
use super::utils::{
    run_powershell_command, run_shell_command, refresh_environment_variables
};

pub fn install_chocolatey() -> Result<(), String> {
    println!("   Installing Chocolatey package manager...");
    
    let script = "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))";
    
    match run_powershell_command(script) {
        Ok(_) => {
            println!("   Chocolatey installation completed");
            refresh_environment_variables();
            
            match Command::new("choco").arg("--version").output() {
                Ok(output) if output.status.success() => {
                    let version = String::from_utf8_lossy(&output.stdout);
                    println!("   Chocolatey verification successful: {}", version.trim());
                    Ok(())
                }
                Ok(_) => Err("Chocolatey installed but verification failed".to_string()),
                Err(e) => Err(format!("Chocolatey installed but not found in PATH: {}", e))
            }
        }
        Err(e) => Err(format!("Chocolatey installation failed: {}", e))
    }
}

pub fn install_scoop() -> Result<(), String> {
    println!("   Installing Scoop package manager...");
    
    let script = "Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force; irm get.scoop.sh | iex";
    
    match run_powershell_command(script) {
        Ok(_) => {
            println!("   Scoop installation completed");
            refresh_environment_variables();
            
            // Verify installation
            match Command::new("scoop").arg("--version").output() {
                Ok(output) if output.status.success() => {
                    let version = String::from_utf8_lossy(&output.stdout);
                    println!("   Scoop verification successful: {}", version.trim());
                    Ok(())
                }
                Ok(_) => Err("Scoop installed but verification failed".to_string()),
                Err(e) => Err(format!("Scoop installed but not found in PATH: {}", e))
            }
        }
        Err(e) => Err(format!("Scoop installation failed: {}", e))
    }
}

pub fn install_homebrew() -> Result<(), String> {
    println!("   Installing Homebrew package manager...");
    
    let script = r#"/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)""#;
    
    match run_shell_command(script) {
        Ok(_) => {
            let _ = super::utils::add_to_path_unix("/opt/homebrew/bin");
            let _ = super::utils::add_to_path_unix("/usr/local/bin");
            Ok(())
        }
        Err(e) => Err(format!("Homebrew installation failed: {}", e))
    }
}