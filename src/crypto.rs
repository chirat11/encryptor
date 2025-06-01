use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
use rand::Rng;
use std::error::Error;
use pqcrypto_kyber::kyber1024;
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::kem::{Ciphertext as CiphertextTrait, SharedSecret as SharedSecretTrait, PublicKey as KemPublicKey, SecretKey as KemSecretKey};
use pqcrypto_traits::sign::{PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait, SignedMessage as SignedMessageTrait};
use zeroize::{Zeroize, ZeroizeOnDrop};
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use base64::{Engine as _, engine::general_purpose};

#[derive(Debug)]
pub enum CryptoError {
    InvalidData(String),
    EncryptionFailed(String),
    DecryptionFailed(String),
    KeyGeneration(String),
    Signature(String),
    Io(std::io::Error),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
            CryptoError::EncryptionFailed(msg) => write!(f, "Encryption failed: {}", msg),
            CryptoError::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
            CryptoError::KeyGeneration(msg) => write!(f, "Key generation failed: {}", msg),
            CryptoError::Signature(msg) => write!(f, "Signature operation failed: {}", msg),
            CryptoError::Io(err) => write!(f, "IO error: {}", err),
        }
    }
}

impl Error for CryptoError {}

impl From<std::io::Error> for CryptoError {
    fn from(err: std::io::Error) -> Self {
        CryptoError::Io(err)
    }
}

// Hybrid encryption using Kyber1024 + AES-256-GCM
pub mod hybrid_encryption {
    use super::*;

    #[derive(Clone)]
    pub struct HybridCiphertext {
        pub kyber_ciphertext: Vec<u8>,
        pub aes_ciphertext: Vec<u8>,
        pub nonce: [u8; 12],
        pub salt: [u8; 16],
    }

    impl HybridCiphertext {
        pub fn to_bytes(&self) -> Vec<u8> {
            let mut result = Vec::new();
            
            // Format: [16 bytes salt][12 bytes nonce][4 bytes kyber_len][kyber_ct][aes_ct]
            result.extend_from_slice(&self.salt);
            result.extend_from_slice(&self.nonce);
            
            let kyber_len = (self.kyber_ciphertext.len() as u32).to_le_bytes();
            result.extend_from_slice(&kyber_len);
            result.extend_from_slice(&self.kyber_ciphertext);
            result.extend_from_slice(&self.aes_ciphertext);
            
            result
        }

        pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
            if data.len() < 32 {
                return Err(CryptoError::InvalidData("Ciphertext too short".into()));
            }

            let mut salt = [0u8; 16];
            salt.copy_from_slice(&data[0..16]);

            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&data[16..28]);

            let kyber_len = u32::from_le_bytes([data[28], data[29], data[30], data[31]]) as usize;
            if data.len() < 32 + kyber_len {
                return Err(CryptoError::InvalidData("Invalid kyber ciphertext length".into()));
            }

            let kyber_ciphertext = data[32..32 + kyber_len].to_vec();
            let aes_ciphertext = data[32 + kyber_len..].to_vec();

            Ok(HybridCiphertext {
                kyber_ciphertext,
                aes_ciphertext,
                nonce,
                salt,
            })
        }
    }

    pub fn generate_kyber_keypair() -> (kyber1024::PublicKey, kyber1024::SecretKey) {
        kyber1024::keypair()
    }

    pub fn encrypt_data(data: &[u8], public_key: &kyber1024::PublicKey, password: &str) -> Result<HybridCiphertext, CryptoError> {
        let (shared_secret, kyber_ciphertext) = kyber1024::encapsulate(public_key);

        let salt = generate_salt();
        let mut password_key = derive_key_from_password(password, &salt, 100000)?;
        
        let mut combined_key = combine_keys(&password_key, shared_secret.as_bytes())?;

        let nonce_bytes = generate_random_bytes(12)?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_bytes);
        
        let key = Key::<Aes256Gcm>::from_slice(&combined_key);
        let cipher = Aes256Gcm::new(key);
        let aes_ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), data)
            .map_err(|e| CryptoError::EncryptionFailed(format!("AES encryption failed: {}", e)))?;

        password_key.zeroize();
        combined_key.zeroize();

        Ok(HybridCiphertext {
            kyber_ciphertext: kyber_ciphertext.as_bytes().to_vec(),
            aes_ciphertext,
            nonce,
            salt,
        })
    }

    pub fn decrypt_data(ciphertext: &HybridCiphertext, secret_key: &kyber1024::SecretKey, password: &str) -> Result<Vec<u8>, CryptoError> {
        let kyber_ct = <kyber1024::Ciphertext as CiphertextTrait>::from_bytes(&ciphertext.kyber_ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed("Invalid Kyber ciphertext".into()))?;
        let shared_secret = kyber1024::decapsulate(&kyber_ct, secret_key);

        let mut password_key = derive_key_from_password(password, &ciphertext.salt, 100000)?;
        let mut combined_key = combine_keys(&password_key, shared_secret.as_bytes())?;

        let key = Key::<Aes256Gcm>::from_slice(&combined_key);
        let cipher = Aes256Gcm::new(key);
        let plaintext = cipher.decrypt(Nonce::from_slice(&ciphertext.nonce), ciphertext.aes_ciphertext.as_ref())
            .map_err(|e| CryptoError::DecryptionFailed(format!("AES decryption failed: {}", e)))?;

        password_key.zeroize();
        combined_key.zeroize();

        Ok(plaintext)
    }

    fn combine_keys(password_key: &[u8; 32], shared_secret: &[u8]) -> Result<[u8; 32], CryptoError> {
        use argon2::Argon2;

        let info = b"hybrid-encryption-key-v2";
        let mut combined_input = Vec::new();
        combined_input.extend_from_slice(password_key);
        combined_input.extend_from_slice(shared_secret);

        let mut combined_key = [0u8; 32];
        Argon2::default()
            .hash_password_into(&combined_input, info, &mut combined_key)
            .map_err(|e| CryptoError::KeyGeneration(format!("Argon2 key combination failed: {}", e)))?;

        Ok(combined_key)
    }
}

// Hybrid signatures using Dilithium5 + Ed448
pub mod hybrid_signatures {
    use super::*;
    use openssl::pkey::{PKey, Private, Public};
    use openssl::sign::{Signer, Verifier};

    #[derive(Clone)]
    pub struct HybridSignature {
        pub dilithium_signature: Vec<u8>,
        pub ed448_signature: Vec<u8>,
    }

    impl HybridSignature {
        pub fn to_bytes(&self) -> Vec<u8> {
            let mut result = Vec::new();
            
            // Format: [4 bytes dilithium_len][dilithium_sig][ed448_sig]
            let dilithium_len = (self.dilithium_signature.len() as u32).to_le_bytes();
            result.extend_from_slice(&dilithium_len);
            result.extend_from_slice(&self.dilithium_signature);
            result.extend_from_slice(&self.ed448_signature);
            
            result
        }

        pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
            if data.len() < 4 {
                return Err(CryptoError::InvalidData("Signature data too short".into()));
            }

            let dilithium_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
            if data.len() < 4 + dilithium_len {
                return Err(CryptoError::InvalidData("Invalid dilithium signature length".into()));
            }

            let dilithium_signature = data[4..4 + dilithium_len].to_vec();
            let ed448_signature = data[4 + dilithium_len..].to_vec();

            Ok(HybridSignature {
                dilithium_signature,
                ed448_signature,
            })
        }
    }

    #[derive(Clone)]
    pub struct HybridKeyPair {
        pub dilithium_public: dilithium5::PublicKey,
        pub dilithium_secret: dilithium5::SecretKey,
        pub ed448_private: PKey<Private>,
    }

    impl HybridKeyPair {
        pub fn generate() -> Result<Self, CryptoError> {
            let (dilithium_public, dilithium_secret) = dilithium5::keypair();
            let ed448_private = PKey::generate_ed448()
                .map_err(|e| CryptoError::KeyGeneration(format!("Ed448 key generation failed: {}", e)))?;

            Ok(HybridKeyPair {
                dilithium_public,
                dilithium_secret,
                ed448_private,
            })
        }

        pub fn public_key(&self) -> Result<HybridPublicKey, CryptoError> {
            let ed448_public_bytes = self.ed448_private.raw_public_key()
                .map_err(|e| CryptoError::KeyGeneration(format!("Failed to extract Ed448 public key: {}", e)))?;
            let ed448_public = PKey::public_key_from_raw_bytes(&ed448_public_bytes, openssl::pkey::Id::ED448)
                .map_err(|e| CryptoError::KeyGeneration(format!("Failed to create Ed448 public key: {}", e)))?;

            Ok(HybridPublicKey {
                dilithium_public: self.dilithium_public.clone(),
                ed448_public,
            })
        }

        pub fn sign(&self, data: &[u8]) -> Result<HybridSignature, CryptoError> {
            // Dilithium signature
            let dilithium_signed_msg = dilithium5::sign(data, &self.dilithium_secret);

            // Ed448 signature
            let mut signer = Signer::new_without_digest(&self.ed448_private)
                .map_err(|e| CryptoError::Signature(format!("Ed448 signer creation failed: {}", e)))?;
            let ed448_signature = signer.sign_oneshot_to_vec(data)
                .map_err(|e| CryptoError::Signature(format!("Ed448 signing failed: {}", e)))?;

            Ok(HybridSignature {
                dilithium_signature: dilithium_signed_msg.as_bytes().to_vec(),
                ed448_signature,
            })
        }

        pub fn to_base64(&self) -> Result<String, CryptoError> {
            let mut result = Vec::new();
            
            // Format: [4 bytes dilithium_public_len][dilithium_public][4 bytes dilithium_secret_len][dilithium_secret][ed448_private]
            let dilithium_public_bytes = self.dilithium_public.as_bytes();
            let dilithium_secret_bytes = self.dilithium_secret.as_bytes();
            let ed448_private_bytes = self.ed448_private.raw_private_key()
                .map_err(|e| CryptoError::KeyGeneration(format!("Failed to extract Ed448 private key: {}", e)))?;

            let dilithium_public_len = (dilithium_public_bytes.len() as u32).to_le_bytes();
            result.extend_from_slice(&dilithium_public_len);
            result.extend_from_slice(dilithium_public_bytes);

            let dilithium_secret_len = (dilithium_secret_bytes.len() as u32).to_le_bytes();
            result.extend_from_slice(&dilithium_secret_len);
            result.extend_from_slice(dilithium_secret_bytes);

            result.extend_from_slice(&ed448_private_bytes);

            Ok(general_purpose::STANDARD.encode(result))
        }

        pub fn from_base64(encoded: &str) -> Result<Self, CryptoError> {
            let bytes = general_purpose::STANDARD.decode(encoded)
                .map_err(|e| CryptoError::InvalidData(format!("Base64 decode error: {}", e)))?;

            if bytes.len() < 8 {
                return Err(CryptoError::InvalidData("Encoded keypair too short".into()));
            }

            let dilithium_public_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
            if bytes.len() < 4 + dilithium_public_len + 4 {
                return Err(CryptoError::InvalidData("Invalid dilithium public key length".into()));
            }

            let dilithium_public_bytes = &bytes[4..4 + dilithium_public_len];
            let dilithium_public = dilithium5::PublicKey::from_bytes(dilithium_public_bytes)
                .map_err(|_| CryptoError::InvalidData("Invalid dilithium public key".into()))?;

            let dilithium_secret_len_pos = 4 + dilithium_public_len;
            let dilithium_secret_len = u32::from_le_bytes([
                bytes[dilithium_secret_len_pos],
                bytes[dilithium_secret_len_pos + 1],
                bytes[dilithium_secret_len_pos + 2],
                bytes[dilithium_secret_len_pos + 3]
            ]) as usize;

            let dilithium_secret_start = dilithium_secret_len_pos + 4;
            if bytes.len() < dilithium_secret_start + dilithium_secret_len {
                return Err(CryptoError::InvalidData("Invalid dilithium secret key length".into()));
            }

            let dilithium_secret_bytes = &bytes[dilithium_secret_start..dilithium_secret_start + dilithium_secret_len];
            let dilithium_secret = dilithium5::SecretKey::from_bytes(dilithium_secret_bytes)
                .map_err(|_| CryptoError::InvalidData("Invalid dilithium secret key".into()))?;

            let ed448_private_bytes = &bytes[dilithium_secret_start + dilithium_secret_len..];
            let ed448_private = PKey::private_key_from_raw_bytes(ed448_private_bytes, openssl::pkey::Id::ED448)
                .map_err(|e| CryptoError::InvalidData(format!("Invalid Ed448 private key: {}", e)))?;

            Ok(HybridKeyPair {
                dilithium_public,
                dilithium_secret,
                ed448_private,
            })
        }
    }

    #[derive(Clone)]
    pub struct HybridPublicKey {
        pub dilithium_public: dilithium5::PublicKey,
        pub ed448_public: PKey<Public>,
    }

    impl HybridPublicKey {
        pub fn verify(&self, data: &[u8], signature: &HybridSignature) -> Result<bool, CryptoError> {
            // Verify Dilithium signature
            let dilithium_signed_msg = dilithium5::SignedMessage::from_bytes(&signature.dilithium_signature)
                .map_err(|_| CryptoError::Signature("Invalid dilithium signature".into()))?;
            let dilithium_valid = dilithium5::open(&dilithium_signed_msg, &self.dilithium_public)
                .map(|recovered_data| recovered_data == data)
                .unwrap_or(false);

            // Verify Ed448 signature
            let mut verifier = Verifier::new_without_digest(&self.ed448_public)
                .map_err(|e| CryptoError::Signature(format!("Ed448 verifier creation failed: {}", e)))?;
            let ed448_valid = verifier.verify_oneshot(&signature.ed448_signature, data)
                .map_err(|e| CryptoError::Signature(format!("Ed448 verification failed: {}", e)))?;

            Ok(dilithium_valid && ed448_valid)
        }

        pub fn to_base64(&self) -> Result<String, CryptoError> {
            let mut result = Vec::new();
            
            // Format: [4 bytes dilithium_public_len][dilithium_public][ed448_public]
            let dilithium_public_bytes = self.dilithium_public.as_bytes();
            let ed448_public_bytes = self.ed448_public.raw_public_key()
                .map_err(|e| CryptoError::KeyGeneration(format!("Failed to extract Ed448 public key: {}", e)))?;

            let dilithium_public_len = (dilithium_public_bytes.len() as u32).to_le_bytes();
            result.extend_from_slice(&dilithium_public_len);
            result.extend_from_slice(dilithium_public_bytes);
            result.extend_from_slice(&ed448_public_bytes);

            Ok(general_purpose::STANDARD.encode(result))
        }
    }
}

// Utility functions
pub fn generate_random_bytes(length: usize) -> Result<Vec<u8>, CryptoError> {
    let mut rng = rand::thread_rng();
    let mut bytes = vec![0u8; length];
    rng.fill(&mut bytes[..]);
    Ok(bytes)
}

pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    let mut rng = rand::thread_rng();
    rng.fill(&mut salt);
    salt
}

pub fn derive_key_from_password(password: &str, salt: &[u8], _iterations: u32) -> Result<[u8; 32], CryptoError> {
    use argon2::Argon2;
    
    let mut output_key_material = [0u8; 32];
    
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut output_key_material)
        .map_err(|e| CryptoError::KeyGeneration(format!("Argon2 failed: {}", e)))?;
    
    Ok(output_key_material)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_encryption_roundtrip() {
        let (public_key, secret_key) = hybrid_encryption::generate_kyber_keypair();
        let data = b"Hello, post-quantum world!";
        let password = "test_password";

        let ciphertext = hybrid_encryption::encrypt_data(data, &public_key, password).unwrap();
        let decrypted = hybrid_encryption::decrypt_data(&ciphertext, &secret_key, password).unwrap();

        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_hybrid_signature_roundtrip() {
        let keypair = hybrid_signatures::HybridKeyPair::generate().unwrap();
        let public_key = keypair.public_key().unwrap();
        let data = b"Sign this message";

        let signature = keypair.sign(data).unwrap();
        let is_valid = public_key.verify(data, &signature).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_key_serialization() {
        let keypair = hybrid_signatures::HybridKeyPair::generate().unwrap();
        let encoded = keypair.to_base64().unwrap();
        let decoded = hybrid_signatures::HybridKeyPair::from_base64(&encoded).unwrap();

        let public_key = keypair.public_key().unwrap();
        let decoded_public_key = decoded.public_key().unwrap();

        let data = b"Test serialization";
        let signature1 = keypair.sign(data).unwrap();
        let signature2 = decoded.sign(data).unwrap();

        assert!(public_key.verify(data, &signature1).unwrap());
        assert!(decoded_public_key.verify(data, &signature2).unwrap());
    }
} 