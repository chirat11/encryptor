use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use zeroize::Zeroize;

mod system_check;
mod crypto;

use pqcrypto_traits::kem::{SecretKey as SecretKeyTrait, PublicKey as KemPublicKey, Ciphertext as CiphertextTrait, SharedSecret as SharedSecretTrait};
use pqcrypto_traits::sign::{PublicKey as PublicKeyTrait, SecretKey as SignSecretKeyTrait};

fn main() {
    if let Err(e) = system_check::check_all_requirements() {
        eprintln!("\nSystem check failed: {}", e);
        eprintln!("Please install the missing requirements and try again.");
        std::process::exit(1);
    }

    if let Err(e) = ensure_keys_exist() {
        eprintln!("Failed to setup keys: {}", e);
        std::process::exit(1);
    }

    loop {
        show_menu();
        
        print!("\nSelect an option (1-5): ");
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            continue;
        }
        
        let choice = input.trim();
        println!();
        
        let result = match choice {
            "1" => handle_protect_file(),
            "2" => handle_unprotect_file(),
            "3" => handle_protect_text(),
            "4" => handle_unprotect_text(),
            "5" => {
                println!("Goodbye!\n");
                break;
            }
            _ => {
                println!("Invalid option. Please select 1-5.");
                continue;
            }
        };

        if let Err(e) = result {
            eprintln!("Error: {}", e);
        }
        
        println!("\nPress Enter to continue...");
        let mut _input = String::new();
        io::stdin().read_line(&mut _input).unwrap();
    }
}

fn show_menu() {
    println!("\n=== encryptor ===");
    println!();
    println!("1. Protect a file (encrypt it)");
    println!("2. Unprotect a file (decrypt it)");
    println!("3. Protect text (encrypt it)");
    println!("4. Unprotect text (decrypt it)");
    println!("5. Exit");
    println!();
}

fn ensure_keys_exist() -> Result<(), Box<dyn std::error::Error>> {
    let private_key_path = PathBuf::from("encryptor.key");
    let public_key_path = PathBuf::from("encryptor.pub");
    
    if !private_key_path.exists() || !public_key_path.exists() {
        println!("Setting up security keys for first-time use...");
        
        let keypair = crypto::hybrid_signatures::HybridKeyPair::generate()?;
        let public_key = keypair.public_key()?;
        let public_key_b64 = public_key.to_base64()?;
        
        println!("\n\nYou need to set a master password.");
        let mut master_password = prompt_secure_password("\n\nEnter master password (Remember this password, it cannot be recovered!): ", true)?;
        
        let private_key_b64 = keypair.to_base64()?;
        let encrypted_private_key = encrypt_private_key(&private_key_b64, &master_password)?;
        
        fs::write(&public_key_path, public_key_b64)?;
        fs::write(&private_key_path, encrypted_private_key)?;
        
        master_password.zeroize();
        
        println!("  Security keys created successfully!");
        println!("   Files: encryptor.key (private, encrypted) and encryptor.pub (public)");
        println!("   Important: Keep your master password safe.");
    }
    
    Ok(())
}

fn validate_password_strength(password: &str, is_master_password: bool) -> Result<(), String> {
    // Different requirements for master vs protection passwords
    let min_length = if is_master_password { 12 } else { 8 };
    let password_type = if is_master_password { "Master password" } else { "Protection password" };
    
    if password.is_empty() {
        return Err(format!("{} cannot be empty", password_type));
    }
    
    if password.len() < min_length {
        return Err(format!("{} must be at least {} characters long", password_type, min_length));
    }
    
    if password.len() > 128 {
        return Err(format!("{} cannot exceed 128 characters", password_type));
    }
    
    let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
    let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".chars().any(|sc| sc == c));
    
    let mut char_types = 0;
    if has_lowercase { char_types += 1; }
    if has_uppercase { char_types += 1; }
    if has_digit { char_types += 1; }
    if has_special { char_types += 1; }
    
    let required_types = if is_master_password { 3 } else { 2 };
    if char_types < required_types {
        let mut missing = Vec::new();
        if !has_lowercase { missing.push("lowercase letters"); }
        if !has_uppercase { missing.push("uppercase letters"); }
        if !has_digit { missing.push("numbers"); }
        if !has_special { missing.push("special characters (!@#$%^&*()_+-=[]{}|;:,.<>?)"); }
        
        return Err(format!("{} must contain at least {} different character types. Missing: {}", 
                          password_type, required_types, missing.join(", ")));
    }
    
    if password.to_lowercase().contains("password") ||
       password.to_lowercase().contains("123456") ||
       password.to_lowercase().contains("qwerty") ||
       password.to_lowercase().contains("admin") {
        return Err(format!("{} contains common weak patterns. Please choose a more secure password", password_type));
    }
    
    let chars: Vec<char> = password.chars().collect();
    for window in chars.windows(4) {
        if window[0] == window[1] && window[1] == window[2] && window[2] == window[3] {
            return Err(format!("{} cannot contain more than 3 consecutive identical characters", password_type));
        }
    }
    
    Ok(())
}

fn prompt_secure_password(prompt: &str, is_master_password: bool) -> Result<String, Box<dyn std::error::Error>> {
    let password_type = if is_master_password { "master password" } else { "protection password" };
    let min_length = if is_master_password { 12 } else { 8 };
    let required_types = if is_master_password { 3 } else { 2 };
    
    loop {
        let mut password = rpassword::prompt_password(prompt)?;
        
        match validate_password_strength(&password, is_master_password) {
            Ok(_) => {
                if is_master_password {
                    let mut confirm_password = rpassword::prompt_password("Confirm master password: ")?;
                    if password != confirm_password {
                        password.zeroize();
                        confirm_password.zeroize();
                        println!("Passwords don't match. Please try again.");
                        continue;
                    }
                    confirm_password.zeroize();
                }
                return Ok(password);
            }
            Err(e) => {
                password.zeroize();
                println!(" Password validation failed: {}", e);
                println!("\nPlease try again with a stronger {}.", password_type);
                println!("\n{} requirements:", if is_master_password { "Master password" } else { "Protection password" });
                println!("  • At least {} characters long", min_length);
                println!("  • Contains at least {} of: uppercase, lowercase, numbers, special characters", required_types);
                println!("  • No common weak patterns (password, 123456, qwerty, etc.)");
                println!("  • No more than 3 consecutive identical characters");
                continue;
            }
        }
    }
}

fn encrypt_private_key(private_key_b64: &str, master_password: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let (kyber_public, kyber_secret) = crypto::hybrid_encryption::generate_kyber_keypair();
    
    // Kyber1024 KEM + AES-256-GCM
    let (shared_secret, kyber_ciphertext) = pqcrypto_kyber::kyber1024::encapsulate(&kyber_public);
    
    let salt = crypto::generate_salt();
    let mut password_key = crypto::derive_key_from_password(master_password, &salt, 100000)?;
    
    let mut combined_key = combine_quantum_resistant_keys(&password_key, shared_secret.as_bytes())?;
    
    use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
    let nonce_bytes = crypto::generate_random_bytes(12)?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_bytes);
    
    let aes_key = Key::<Aes256Gcm>::from_slice(&combined_key);
    let cipher = Aes256Gcm::new(aes_key);
    let encrypted = cipher.encrypt(Nonce::from_slice(&nonce), private_key_b64.as_bytes())
        .map_err(|e| format!("Failed to encrypt private key: {}", e))?;
    
    // Format: [16 bytes salt][kyber_ciphertext_len (4 bytes)][kyber_ciphertext][kyber_secret_len (4 bytes)][kyber_secret][12 bytes nonce][encrypted_data]
    let mut result = Vec::new();
    result.extend_from_slice(&salt);
    
    let kyber_ct_bytes = kyber_ciphertext.as_bytes();
    let kyber_ct_len = (kyber_ct_bytes.len() as u32).to_le_bytes();
    result.extend_from_slice(&kyber_ct_len);
    result.extend_from_slice(kyber_ct_bytes);
    
    let kyber_secret_bytes = kyber_secret.as_bytes();
    let kyber_secret_len = (kyber_secret_bytes.len() as u32).to_le_bytes();
    result.extend_from_slice(&kyber_secret_len);
    result.extend_from_slice(kyber_secret_bytes);
    
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&encrypted);
    
    // Clear sensitive data from memory
    password_key.zeroize();
    combined_key.zeroize();
    nonce.zeroize();
    
    Ok(result)
}

fn decrypt_private_key(encrypted_data: &[u8], master_password: &str) -> Result<String, Box<dyn std::error::Error>> {
    if encrypted_data.len() < 32 {
        return Err("Invalid encrypted private key format".into());
    }
    
    let mut offset = 0;
    
    let salt = &encrypted_data[offset..offset + 16];
    offset += 16;
    
    let kyber_ct_len = u32::from_le_bytes([
        encrypted_data[offset], encrypted_data[offset + 1], 
        encrypted_data[offset + 2], encrypted_data[offset + 3]
    ]) as usize;
    offset += 4;
    
    if encrypted_data.len() < offset + kyber_ct_len + 4 {
        return Err("Invalid encrypted private key format".into());
    }
    
    let kyber_ct_bytes = &encrypted_data[offset..offset + kyber_ct_len];
    offset += kyber_ct_len;
    
    let kyber_secret_len = u32::from_le_bytes([
        encrypted_data[offset], encrypted_data[offset + 1], 
        encrypted_data[offset + 2], encrypted_data[offset + 3]
    ]) as usize;
    offset += 4;
    
    if encrypted_data.len() < offset + kyber_secret_len + 12 {
        return Err("Invalid encrypted private key format".into());
    }
    
    let kyber_secret_bytes = &encrypted_data[offset..offset + kyber_secret_len];
    offset += kyber_secret_len;
    
    let nonce = &encrypted_data[offset..offset + 12];
    offset += 12;
    let ciphertext = &encrypted_data[offset..];
    
    let kyber_ct = pqcrypto_kyber::kyber1024::Ciphertext::from_bytes(kyber_ct_bytes)
        .map_err(|_| "Invalid Kyber ciphertext")?;
    let kyber_secret = pqcrypto_kyber::kyber1024::SecretKey::from_bytes(kyber_secret_bytes)
        .map_err(|_| "Invalid Kyber secret key")?;
    
    let shared_secret = pqcrypto_kyber::kyber1024::decapsulate(&kyber_ct, &kyber_secret);
    
    let mut password_key = crypto::derive_key_from_password(master_password, salt, 100000)?;
    let mut combined_key = combine_quantum_resistant_keys(&password_key, shared_secret.as_bytes())?;
    
    use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
    let aes_key = Key::<Aes256Gcm>::from_slice(&combined_key);
    let cipher = Aes256Gcm::new(aes_key);
    let decrypted = cipher.decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| "Failed to decrypt private key - incorrect master password or corrupted file")?;
    
    let result = String::from_utf8(decrypted)
        .map_err(|e| format!("Invalid private key data: {}", e))?;
    
    password_key.zeroize();
    combined_key.zeroize();
    
    Ok(result)
}

fn combine_quantum_resistant_keys(password_key: &[u8; 32], shared_secret: &[u8]) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    use argon2::Argon2;

    let info = b"quantum-resistant-key-protection-v1";
    let mut combined_input = Vec::new();
    combined_input.extend_from_slice(password_key);
    combined_input.extend_from_slice(shared_secret);

    let mut combined_key = [0u8; 32];
    Argon2::default()
        .hash_password_into(&combined_input, info, &mut combined_key)
        .map_err(|e| format!("Argon2 key combination failed: {}", e))?;

    Ok(combined_key)
}

fn load_all_keys_with_single_prompt() -> Result<((pqcrypto_kyber::kyber1024::PublicKey, pqcrypto_kyber::kyber1024::SecretKey), crypto::hybrid_signatures::HybridKeyPair), Box<dyn std::error::Error>> {
    let mut master_password = rpassword::prompt_password("Enter master password: ")?;
    
    let kyber_key_path = PathBuf::from("encryptor.kyber");
    let kyber_keys = if !kyber_key_path.exists() {
        // Generate new Kyber keys on first use
        println!("Generating master encryption keys...");
        let (public_key, secret_key) = crypto::hybrid_encryption::generate_kyber_keypair();
        
        // Create combined key data 
        let mut key_data = Vec::new();
        let public_bytes = public_key.as_bytes();
        let secret_bytes = secret_key.as_bytes();
        
        let public_len = (public_bytes.len() as u32).to_le_bytes();
        key_data.extend_from_slice(&public_len);
        key_data.extend_from_slice(public_bytes);
        key_data.extend_from_slice(secret_bytes);
        
        let key_data_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &key_data);
        
        // Use quantum-resistant encryption for master keys
        let encrypted_keys = encrypt_private_key(&key_data_b64, &master_password)?;
        
        fs::write(&kyber_key_path, encrypted_keys)?;
        
        println!("✓ Master encryption keys created with quantum-resistant protection!");
        (public_key, secret_key)
    } else {
        let encrypted_data = fs::read(&kyber_key_path)?;
        let key_data_b64 = decrypt_private_key(&encrypted_data, &master_password)?;
        
        let key_data = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &key_data_b64)
            .map_err(|e| format!("Failed to decode key data: {}", e))?;
        
        if key_data.len() < 4 {
            return Err("Invalid key data format".into());
        }
        
        let public_len = u32::from_le_bytes([key_data[0], key_data[1], key_data[2], key_data[3]]) as usize;
        if key_data.len() < 4 + public_len {
            return Err("Invalid key data format".into());
        }
        
        let public_bytes = &key_data[4..4 + public_len];
        let secret_bytes = &key_data[4 + public_len..];
        
        let public_key = pqcrypto_kyber::kyber1024::PublicKey::from_bytes(public_bytes)
            .map_err(|_| "Invalid public key data")?;
        let secret_key = pqcrypto_kyber::kyber1024::SecretKey::from_bytes(secret_bytes)
            .map_err(|_| "Invalid secret key data")?;
        
        (public_key, secret_key)
    };
    
    // Load private signing key with the same password
    let private_key_path = PathBuf::from("encryptor.key");
    
    if !private_key_path.exists() {
        master_password.zeroize();
        return Err("Private key file not found. Please run the program to generate keys first.".into());
    }
    
    let encrypted_data = fs::read(&private_key_path)?;
    
    let private_key_b64 = decrypt_private_key(&encrypted_data, &master_password)?;
    let signing_keypair = crypto::hybrid_signatures::HybridKeyPair::from_base64(&private_key_b64.trim())
        .map_err(|e| format!("Failed to parse private key: {}", e))?;
    
    master_password.zeroize();
    
    Ok((kyber_keys, signing_keypair))
}

fn handle_protect_file() -> Result<(), Box<dyn std::error::Error>> {
    print!("Enter the file path to protect (e.g., c:/temp/my_file.txt): ");
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let file_path = PathBuf::from(input.trim());
    
    if !file_path.exists() {
        return Err("File does not exist".into());
    }
    
    if file_path.is_dir() {
        return Err("Cannot protect directories, only files".into());
    }
    
    let data = fs::read(&file_path)?;
    let output_path = file_path.with_extension("encrypted");
    
    let password = prompt_secure_password("\nEnter protection password: ", false)?;

    let ((encryption_public_key, _), keypair) = load_all_keys_with_single_prompt()?;
    
    let signature = keypair.sign(&data)?;
    let signature_bytes = signature.to_bytes();
    
    let sig_len = (signature_bytes.len() as u32).to_le_bytes();
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&sig_len);
    signed_data.extend_from_slice(&signature_bytes);
    signed_data.extend_from_slice(&data);
    
    let encrypted_data = crypto::hybrid_encryption::encrypt_data(&signed_data, &encryption_public_key, &password)?;
    
    // Store only the ciphertext (no secret keys in file!)
    fs::write(&output_path, encrypted_data.to_bytes())?;

    println!("   \nFile protected successfully.");
    println!("   Original: {}", file_path.display());
    println!("   Protected: {}", output_path.display());

    Ok(())
}

fn handle_unprotect_file() -> Result<(), Box<dyn std::error::Error>> {
    print!("Enter the protected file path (.encrypted file) (e.g., c:/temp/my_file.encrypted): ");
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let file_path = PathBuf::from(input.trim());
    
    if !file_path.exists() {
        return Err("File does not exist".into());
    }
    
    let file_data = fs::read(&file_path)?;
    
    let output_path = if let Some(stem) = file_path.file_stem() {
        let stem_str = stem.to_string_lossy();
        if stem_str.ends_with(".encrypted") {
            PathBuf::from(&stem_str[..stem_str.len()-10])
        } else {
            PathBuf::from(format!("{}_unprotected", stem_str))
        }
    } else {
        PathBuf::from("unprotected_file")
    };

    let password = prompt_secure_password("\nEnter protection password: ", false)?;

    let ((_, encryption_secret_key), keypair) = load_all_keys_with_single_prompt()?;
    
    let ciphertext = crypto::hybrid_encryption::HybridCiphertext::from_bytes(&file_data)?;

    let signed_data = crypto::hybrid_encryption::decrypt_data(&ciphertext, &encryption_secret_key, &password)?;
    
    if signed_data.len() < 4 {
        return Err("Invalid protected file format".into());
    }
    
    let sig_len = u32::from_le_bytes([signed_data[0], signed_data[1], signed_data[2], signed_data[3]]) as usize;
    if signed_data.len() < 4 + sig_len {
        return Err("Invalid protected file format".into());
    }
    
    let signature_bytes = &signed_data[4..4 + sig_len];
    let original_data = &signed_data[4 + sig_len..];
    
    let public_key = keypair.public_key()?;
    let signature = crypto::hybrid_signatures::HybridSignature::from_bytes(signature_bytes)?;
    
    let is_valid = public_key.verify(original_data, &signature)?;
    
    if !is_valid {
        return Err("SIGNATURE VERIFICATION FAILED - File may be tampered with!".into());
    }
    
    fs::write(&output_path, original_data)?;

    println!("   \nFile unprotected and verified successfully.");
    println!("   Protected: {}", file_path.display());
    println!("   Restored: {}", output_path.display());

    Ok(())
}

fn read_multiline_input(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    #[cfg(windows)]
    println!("{} (When finished: press Enter, then Ctrl+Z)", prompt);
    #[cfg(not(windows))]
    println!("{} (Press Ctrl+D when finished)", prompt);
    
    let mut input = String::new();
    loop {
        let mut line = String::new();
        match io::stdin().read_line(&mut line) {
            Ok(0) => break, // EOF reached
            Ok(_) => {
                // Check for our special termination sequence
                if line.trim() == "--END--" {
                    break;
                }
                input.push_str(&line);
            },
            Err(_) => break,
        }
    }
    
    if input.trim().is_empty() {
        return Err("No input provided".into());
    }
    
    Ok(input)
}

fn fix_base64_padding(input: &str) -> String {
    let mut result = input.to_string();
    
    // Base64 strings must be multiples of 4 characters
    let padding_needed = (4 - (result.len() % 4)) % 4;
    
    // Add padding if needed
    for _ in 0..padding_needed {
        result.push('=');
    }
    
    result
}

fn handle_protect_text() -> Result<(), Box<dyn std::error::Error>> {
    let text_input = read_multiline_input("Enter the text to protect:")?;
    let data = text_input.as_bytes();
    
    let password = prompt_secure_password("\nEnter protection password: ", false)?;

    let ((encryption_public_key, _), keypair) = load_all_keys_with_single_prompt()?;
    
    let signature = keypair.sign(data)?;
    let signature_bytes = signature.to_bytes();
    
    let sig_len = (signature_bytes.len() as u32).to_le_bytes();
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&sig_len);
    signed_data.extend_from_slice(&signature_bytes);
    signed_data.extend_from_slice(data);
    
    let encrypted_data = crypto::hybrid_encryption::encrypt_data(&signed_data, &encryption_public_key, &password)?;
    
    use base64::{Engine as _, engine::general_purpose};
    let encrypted_base64 = general_purpose::STANDARD.encode(encrypted_data.to_bytes());
    
    #[cfg(windows)]
    {
        // Windows: File-only approach due to console limitations
        let default_filename = {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            format!("protected_{}.txt", timestamp)
        };
        
        print!("\nEnter filename that the protected text will be saved to (or press Enter for '{}'): ", default_filename);
        io::stdout().flush()?;
        let mut filename = String::new();
        io::stdin().read_line(&mut filename)?;
        
        let final_filename = if filename.trim().is_empty() {
            default_filename
        } else {
            filename.trim().to_string()
        };
        
        let file_path = PathBuf::from(&final_filename);
        match fs::write(&file_path, &encrypted_base64) {
            Ok(_) => {
                println!("     \nProtected text saved to: {}", std::env::current_dir().unwrap_or_default().join(&file_path).display());
            }
            Err(e) => {
                println!("     Failed to save file: {}", e);
                // Fallback: show the text
                println!("\n--- PROTECTED TEXT (Base64 encoded) ---");
                println!("{}", encrypted_base64);
                println!("--- END OF PROTECTED TEXT ---");
            }
        }
        
        println!("\nTo decrypt this text later:");
        println!("1. Use option 4 (Unprotect text)");
        println!("2. Choose 'Load from file' and enter: {}", std::env::current_dir().unwrap_or_default().join(&file_path).display());
    }
    
    #[cfg(not(windows))]
    {
        // Non-Windows: Offer choice between file save or clipboard/display
        println!("\nHow would you like to store the protected text?");
        println!("1. Save to file (recommended for large text)");
        println!("2. Copy to clipboard and display");
        print!("\nSelect option (1-2): ");
        io::stdout().flush()?;
        
        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        
        match choice.trim() {
            "1" => {
                // File save option
                let default_filename = {
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    format!("protected_{}.txt", timestamp)
                };
                
                print!("\nEnter filename (or press Enter for '{}'): ", default_filename);
                io::stdout().flush()?;
                let mut filename = String::new();
                io::stdin().read_line(&mut filename)?;
                
                let final_filename = if filename.trim().is_empty() {
                    default_filename
                } else {
                    filename.trim().to_string()
                };
                
                let file_path = PathBuf::from(&final_filename);
                match fs::write(&file_path, &encrypted_base64) {
                    Ok(_) => {
                        println!("  \nProtected text saved to: {}", std::env::current_dir().unwrap_or_default().join(&file_path).display());
                        
                        // Also try clipboard as bonus
                        if copy_to_clipboard(&encrypted_base64).is_ok() {
                            println!("  Also copied to clipboard as backup");
                        }
                    }
                    Err(e) => {
                        println!("  Failed to save file: {}", e);
                        // Fallback to display
                        println!("\n--- PROTECTED TEXT (Base64 encoded) ---");
                        println!("{}", encrypted_base64);
                        println!("--- END OF PROTECTED TEXT ---");
                    }
                }
                
                println!("\nTo decrypt this text later:");
                println!("1. Use option 4 (Unprotect text)");
                println!("2. Choose 'Load from file' and enter: {}", std::env::current_dir().unwrap_or_default().join(&file_path).display());
                println!("   OR choose 'Type/paste manually' or 'Try paste from clipboard'");
            }
            "2" | _ => {
                // Clipboard and display option
                match copy_to_clipboard(&encrypted_base64) {
                    Ok(_) => {
                        println!("  Protected text copied to clipboard");
                    }
                    Err(_) => {
                        println!("  Could not copy to clipboard");
                    }
                }
                
                println!("\n--- PROTECTED TEXT (Base64 encoded) ---");
                println!("{}", encrypted_base64);
                println!("--- END OF PROTECTED TEXT ---");
                
                println!("\nTo decrypt this text later:");
                println!("1. Use option 4 (Unprotect text)");
                println!("2. Choose 'Paste from clipboard' or 'Type/paste manually' to copy the text above");
                println!("   OR choose 'Load from file' if you save this text to a file");
            }
        }
    }

    Ok(())
}

fn copy_to_clipboard(text: &str) -> Result<(), Box<dyn std::error::Error>> {
    use arboard::Clipboard;
    let mut clipboard = Clipboard::new()?;
    clipboard.set_text(text)?;
    Ok(())
}

fn handle_unprotect_text() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        print!("\nEnter file path that the protected text will be loaded from (e.g., c:/temp/my_protected_file.txt): ");
        io::stdout().flush()?;
        
        let mut file_path = String::new();
        io::stdin().read_line(&mut file_path)?;
        
        let path = PathBuf::from(file_path.trim());
        let base64_input = match fs::read_to_string(&path) {
            Ok(text) => {
                println!("    Loaded {} characters from {}", text.len(), path.display());
                text
            }
            Err(e) => {
                return Err(format!("Failed to read file {}: {}", path.display(), e).into());
            }
        };
        
        process_base64_input(base64_input)
    }
    
    #[cfg(not(windows))]
    {
        println!("How would you like to provide the protected text?");
        println!("1. Load from file (recommended)");
        println!("2. Type/paste manually");
        println!("3. Try paste from clipboard");
        
        print!("\nSelect option (1-3): ");
        io::stdout().flush()?;
        
        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        
        let base64_input = match choice.trim() {
            "1" => {
                print!("Enter file path: ");
                io::stdout().flush()?;
                let mut file_path = String::new();
                io::stdin().read_line(&mut file_path)?;
                
                let path = PathBuf::from(file_path.trim());
                match fs::read_to_string(&path) {
                    Ok(text) => {
                        println!("  ✓ Loaded {} characters from {}", text.len(), path.display());
                        text
                    }
                    Err(e) => {
                        return Err(format!("Failed to read file {}: {}", path.display(), e).into());
                    }
                }
            }
            "2" => {
                println!("Note: Encrypted text is typically large due to cryptographic overhead.");
                read_multiline_input("Paste the protected text:")?
            }
            "3" => {
                println!("Attempting to load from clipboard...");
                match load_from_clipboard() {
                    Ok(text) => {
                        if text.trim().is_empty() {
                            return Err("Clipboard is empty or contains no text".into());
                        }
                        println!("  ✓ Loaded {} characters from clipboard", text.len());
                        text
                    }
                    Err(e) => {
                        println!("  ✗ Failed to load from clipboard: {}", e);
                        println!("Falling back to manual input...");
                        read_multiline_input("Paste the protected text:")?
                    }
                }
            }
            _ => {
                println!("Note: Encrypted text is typically large due to cryptographic overhead.");
                read_multiline_input("Paste the protected text:")?
            }
        };
        
        process_base64_input(base64_input)
    }
}

fn process_base64_input(base64_input: String) -> Result<(), Box<dyn std::error::Error>> {
    let cleaned_input = base64_input
        .lines()
        .filter(|line| !line.starts_with("---") && !line.trim().is_empty())
        .map(|line| line.trim())
        .collect::<Vec<&str>>()
        .join("")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .collect::<String>();
    
    if cleaned_input.is_empty() {
        return Err("No valid base64 content found in the input".into());
    }
    
    let original_len = cleaned_input.len();
    let _padding_needed = (4 - (original_len % 4)) % 4;
    
    let fixed_input = fix_base64_padding(&cleaned_input);
    
    use base64::{Engine as _, engine::general_purpose};
    let file_data = general_purpose::STANDARD.decode(&fixed_input)
        .map_err(|e| {
            eprintln!("Base64 decode error details: {}", e);
            eprintln!("Input length: {}", fixed_input.len());
            eprintln!("Input length mod 4: {}", fixed_input.len() % 4);
            
            // Check for common truncation indicators
            let error_msg = e.to_string();
            if error_msg.contains("Invalid last symbol") || 
               error_msg.contains("Invalid padding") ||
               (original_len > 1000 && !cleaned_input.ends_with("==") && !cleaned_input.ends_with("=")) {
                #[cfg(windows)]
                return format!(
                    "The protected text appears to be incomplete or truncated.\n\n\
                    This typically happens when the file is corrupted or incomplete.\n\n\
                    Solutions:\n\
                    • Ensure the file contains the complete protected text\n\
                    • Try saving the protected text again to a new file\n\
                    • Verify the file wasn't modified or corrupted\n\n\
                    Original error: {}", error_msg
                );
                
                #[cfg(not(windows))]
                return format!(
                    "The protected text appears to be incomplete or truncated.\n\n\
                    Most likely cause: Console paste limitations or file corruption\n\n\
                    Solutions:\n\
                    • Use option 1 (Load from file) - this is the most reliable method\n\
                    • If you don't have a file, try protecting the text again and save to file\n\
                    • For manual paste: ensure you copy the ENTIRE text including ending '=' signs\n\n\
                    Original error: {}", error_msg
                );
            }
            
            format!("Invalid base64 data: {}. Try using a file-based approach for best results.", error_msg)
        })?;

    let password = prompt_secure_password("\nEnter protection password: ", false)?;

    let ((_, encryption_secret_key), keypair) = load_all_keys_with_single_prompt()?;
    
    let ciphertext = crypto::hybrid_encryption::HybridCiphertext::from_bytes(&file_data)?;

    let signed_data = crypto::hybrid_encryption::decrypt_data(&ciphertext, &encryption_secret_key, &password)?;
    
    if signed_data.len() < 4 {
        return Err("Invalid protected file format".into());
    }
    
    let sig_len = u32::from_le_bytes([signed_data[0], signed_data[1], signed_data[2], signed_data[3]]) as usize;
    if signed_data.len() < 4 + sig_len {
        return Err("Invalid protected file format".into());
    }
    
    let signature_bytes = &signed_data[4..4 + sig_len];
    let original_data = &signed_data[4 + sig_len..];
    
    let public_key = keypair.public_key()?;
    let signature = crypto::hybrid_signatures::HybridSignature::from_bytes(signature_bytes)?;
    
    let is_valid = public_key.verify(original_data, &signature)?;
    
    if !is_valid {
        return Err("SIGNATURE VERIFICATION FAILED - Text may be tampered with!".into());
    }
    
    let decrypted_text = String::from_utf8_lossy(original_data);
    
    println!("   \nText unprotected and verified successfully.");
    println!("\n--- DECRYPTED TEXT ---");
    println!("{}", decrypted_text);
    println!("--- END OF TEXT ---");

    Ok(())
}

fn load_from_clipboard() -> Result<String, Box<dyn std::error::Error>> {
    use arboard::Clipboard;
    let mut clipboard = Clipboard::new()?;
    let text = clipboard.get_text()?;
    Ok(text)
}