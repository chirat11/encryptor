use std::process::Command;

pub fn command_exists(cmd: &str) -> bool {
    // Try both --version and just running the command to see if it exists
    let version_check = Command::new(cmd)
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
    
    if version_check {
        return true;
    }
    
    // For some commands, --version might not work, try other common flags
    let help_check = Command::new(cmd)
        .arg("--help")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
    
    if help_check {
        return true;
    }
    
    // Last resort: try to run the command with no args (might show usage)
    Command::new(cmd)
        .output()
        .map(|output| {
            // Even if it returns an error code, if it ran, the command exists
            output.status.code().is_some()
        })
        .unwrap_or(false)
}

pub fn run_command(cmd: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to execute command: {}", e))?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        println!("   Output: {}", stdout.trim());
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Command failed: {}", stderr))
    }
}

pub fn run_command_with_sudo(cmd: &str, args: &[&str]) -> Result<(), String> {
    if cfg!(unix) {
        let mut sudo_args = vec!["sudo"];
        sudo_args.push(cmd);
        sudo_args.extend(args);
        
        let output = Command::new("sudo")
            .args(&[cmd])
            .args(args)
            .output()
            .map_err(|e| format!("Failed to execute '{}' with sudo: {}", cmd, e))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if !stdout.trim().is_empty() {
                println!("   {}", stdout.trim());
            }
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            
            let mut error_msg = format!("Command '{}' failed (exit code: {:?})", cmd, output.status.code());
            
            if !stderr.trim().is_empty() {
                error_msg.push_str(&format!("\n   Error output: {}", stderr.trim()));
            }
            
            if !stdout.trim().is_empty() {
                error_msg.push_str(&format!("\n   Standard output: {}", stdout.trim()));
            }
            
            Err(error_msg)
        }
    } else {
        match run_command(cmd, args) {
            Ok(_) => Ok(()),
            Err(e) => Err(e)
        }
    }
}

pub fn run_command_with_retry(cmd: &str, args: &[&str], retries: usize) -> Result<String, String> {
    for attempt in 1..=retries {
        println!("   Attempt {} of {}", attempt, retries);
        
        match run_command(cmd, args) {
            Ok(output) => return Ok(output),
            Err(e) => {
                if attempt < retries {
                    println!("   Attempt {} failed, retrying in 2 seconds...", attempt);
                    std::thread::sleep(std::time::Duration::from_secs(2));
                } else {
                    println!("   All {} attempts failed", retries);
                    return Err(e);
                }
            }
        }
    }
    
    unreachable!()
}

pub fn run_command_with_retry_sudo(cmd: &str, args: &[&str], retries: usize) -> Result<(), String> {
    let mut last_error = String::new();
    
    for attempt in 1..=retries {
        println!("   Attempt {} of {}", attempt, retries);
        match run_command_with_sudo(cmd, args) {
            Ok(_) => return Ok(()),
            Err(e) => {
                last_error = e.clone();
                if attempt < retries {
                    println!("   Attempt {} failed, retrying in 2 seconds...", attempt);
                    std::thread::sleep(std::time::Duration::from_secs(2));
                } else {
                    println!("   All {} attempts failed", retries);
                }
            }
        }
    }
    Err(last_error)
}

pub fn run_powershell_command(script: &str) -> Result<String, String> {
    let output = Command::new("powershell")
        .args(&["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script])
        .output()
        .map_err(|e| format!("Failed to execute PowerShell command: {}", e))?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        println!("   PowerShell output: {}", stdout.trim());
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("PowerShell command failed: {}", stderr))
    }
}

pub fn run_shell_command(cmd: &str) -> Result<String, String> {
    let shell = if cfg!(target_os = "windows") { "cmd" } else { "sh" };
    let flag = if cfg!(target_os = "windows") { "/C" } else { "-c" };
    
    let output = Command::new(shell)
        .args(&[flag, cmd])
        .output()
        .map_err(|e| format!("Failed to execute command: {}", e))?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        println!("   Output: {}", stdout.trim());
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Command failed: {}", stderr))
    }
}

pub fn refresh_environment_variables() {
    // On Windows, try to refresh environment variables
    if cfg!(target_os = "windows") {
        let _ = Command::new("cmd")
            .args(&["/c", "refreshenv"])
            .output();
    }
}

pub fn add_to_path(path: &str) -> Result<(), String> {
    if cfg!(target_os = "windows") {
        add_to_path_windows(path)
    } else {
        add_to_path_unix(path)
    }
}

fn add_to_path_windows(path: &str) -> Result<(), String> {
    println!("   Adding {} to PATH...", path);
    
    if let Ok(current_path) = std::env::var("PATH") {
        if !current_path.contains(path) {
            let new_path = format!("{};{}", current_path, path);
            std::env::set_var("PATH", &new_path);
            println!("   PATH updated for current session");
        } else {
            println!("   Path already in PATH variable");
        }
    }
    
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        
        let output = Command::new("reg")
            .args(&["query", "HKCU\\Environment", "/v", "PATH"])
            .output();
            
        if let Ok(output) = output {
            let current_path = String::from_utf8_lossy(&output.stdout);
            let path_line = current_path.lines()
                .find(|line| line.contains("PATH"))
                .unwrap_or("");
                
            if !path_line.contains(path) {
                let new_path = if path_line.is_empty() {
                    path.to_string()
                } else {
                    format!("{};{}", path_line.split_whitespace().last().unwrap_or(""), path)
                };
                
                match Command::new("setx")
                    .args(&["PATH", &new_path])
                    .output()
                {
                    Ok(_) => println!("   PATH updated in user environment (persistent)"),
                    Err(e) => println!("   Could not update persistent PATH: {}", e)
                }
            }
        }
    }
    
    Ok(())
}

pub fn add_to_path_unix(path: &str) -> Result<(), String> {
    if cfg!(unix) {
        std::env::set_var("PATH", format!("{}:{}", path, std::env::var("PATH").unwrap_or_default()));
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn run_shell_command_unix(cmd: &str) -> Result<String, String> {
    let output = Command::new("sh")
        .args(&["-c", cmd])
        .output()
        .map_err(|e| format!("Failed to execute shell command: {}", e))?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        println!("   Shell output: {}", stdout.trim());
        Ok(stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Shell command failed: {}", stderr))
    }
}