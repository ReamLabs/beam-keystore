use serde::{Deserialize, Serialize};
use serde_json;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::{Aead};
use rand::{thread_rng, RngCore};
use argon2::{Argon2, Params, Version, Algorithm};
use uuid::Uuid;
use std::fs::File;
use std::io::Write;
use std::error::Error;

// Keystore JSON structure following Web3 Secret Storage Definition
#[derive(Serialize, Deserialize, Debug)]
pub struct Keystore {
    pub version: u32,
    pub id: String,
    pub address: String,
    pub crypto: CryptoParams,
    pub quantum_secure: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CryptoParams {
    pub cipher: String,
    pub cipherparams: CipherParams,
    pub ciphertext: String,
    pub kdf: String,
    pub kdfparams: KdfParams,
    pub mac: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CipherParams {
    pub nonce: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KdfParams {
    pub dklen: u32,
    pub m_cost: u32,    // Memory cost (in KB)
    pub t_cost: u32,    // Time cost (iterations)
    pub p_cost: u32,    // Parallelism
    pub salt: String,
}

// Input structure for keystore generation
#[derive(Deserialize, Debug)]
pub struct KeystoreInput {
    pub private_key: String,
    pub password: String,
    pub address: Option<String>,
    pub kdf_params: Option<InputKdfParams>,
}

#[derive(Deserialize, Debug)]
pub struct InputKdfParams {
    pub m_cost: Option<u32>,  // Memory cost in KB
    pub t_cost: Option<u32>,  // Time cost (iterations)
    pub p_cost: Option<u32>,  // Parallelism
    pub dklen: Option<u32>,   // Derived key length
}

pub struct KeystoreGenerator;

impl KeystoreGenerator {
    pub fn new() -> Self {
        KeystoreGenerator
    }

    pub fn generate_keystore(&self, input: KeystoreInput) -> Result<Keystore, Box<dyn Error>> {
        // Validate and process private key
        let private_key = self.process_private_key(&input.private_key)?;
        
        // Generate or use provided address
        let address = match input.address {
            Some(addr) => self.validate_address(addr)?,
            None => self.derive_address_from_private_key(&private_key)?,
        };

        // Generate random salt and nonce
        let mut salt = [0u8; 32];
        thread_rng().fill_bytes(&mut salt);

        // KDF parameters with defaults for Argon2id
        let kdf_params = KdfParams {
            dklen: input.kdf_params.as_ref().and_then(|p| p.dklen).unwrap_or(32), // 32 bytes for AES-256 key
            m_cost: input.kdf_params.as_ref().and_then(|p| p.m_cost).unwrap_or(65536), // 64 MB
            t_cost: input.kdf_params.as_ref().and_then(|p| p.t_cost).unwrap_or(3),     // 3 iterations
            p_cost: input.kdf_params.as_ref().and_then(|p| p.p_cost).unwrap_or(1),     // 1 thread
            salt: hex::encode(&salt),
        };

        // Derive key using Argon2id (32 bytes for AES-256)
        let mut derived_key = vec![0u8; 32];
        let argon2_params = Params::new(
            kdf_params.m_cost,
            kdf_params.t_cost,
            kdf_params.p_cost,
            Some(32) // Always 32 bytes for AES-256
        ).map_err(|e| e.to_string())?;
        
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
        
        argon2.hash_password_into(
            input.password.as_bytes(),
            &salt,
            &mut derived_key
        ).map_err(|e| e.to_string())?;

        // Generate random nonce for AES-256-GCM (12 bytes)
        let mut nonce_bytes = [0u8; 12];
        thread_rng().fill_bytes(&mut nonce_bytes);

        // Encrypt private key using AES-256-GCM
        let ciphertext = self.encrypt_private_key(&private_key, &derived_key, &nonce_bytes)?;

        // Create keystore structure
        let keystore = Keystore {
            version: 5,
            id: Uuid::new_v4().to_string(),
            address: address.to_lowercase(),
            quantum_secure: true,
            crypto: CryptoParams {
                cipher: "aes-256-gcm".to_string(),
                cipherparams: CipherParams {
                    nonce: hex::encode(&nonce_bytes),
                },
                ciphertext: hex::encode(&ciphertext),
                kdf: "argon2id".to_string(),
                kdfparams: kdf_params,
                mac: "".to_string(), // Not needed with GCM as it provides authentication
            },
        };

        Ok(keystore)
    }

    fn process_private_key(&self, private_key: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let key = if private_key.starts_with("0x") {
            &private_key[2..]
        } else {
            private_key
        };

        if key.len() != 64 {
            return Err("Private key must be 32 bytes (64 hex characters)".into());
        }

        Ok(hex::decode(key)?)
    }

    fn validate_address(&self, address: String) -> Result<String, Box<dyn Error>> {
        let addr = if address.starts_with("0x") {
            &address[2..]
        } else {
            &address
        };

        if addr.len() != 40 {
            return Err("Address must be 20 bytes (40 hex characters)".into());
        }

        hex::decode(addr)?; // Validate hex encoding
        Ok(address)
    }

    fn derive_address_from_private_key(&self, private_key: &[u8]) -> Result<String, Box<dyn Error>> {
        // This is a simplified version - in production, you'd use proper secp256k1
        // to derive the public key and then the address
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(private_key);
        let hash = hasher.finalize();
        
        // Take last 20 bytes as address (simplified)
        let address = &hash[12..32];
        Ok(format!("0x{}", hex::encode(address)))
    }

    fn encrypt_private_key(&self, private_key: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        // AES-256-GCM encryption
        let cipher_key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(cipher_key);
        let nonce = Nonce::from_slice(nonce);
        
        let ciphertext = cipher.encrypt(nonce, private_key)
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        Ok(ciphertext)
    }

    pub fn save_keystore(&self, keystore: &Keystore, filename: &str) -> Result<(), Box<dyn Error>> {
        let json = serde_json::to_string_pretty(keystore)?;
        let mut file = File::create(filename)?;
        file.write_all(json.as_bytes())?;
        println!("Keystore saved to: {}", filename);
        Ok(())
    }

    pub fn load_and_generate_from_json(&self, json_input: &str) -> Result<Keystore, Box<dyn Error>> {
        let input: KeystoreInput = serde_json::from_str(json_input)?;
        self.generate_keystore(input)
    }
}