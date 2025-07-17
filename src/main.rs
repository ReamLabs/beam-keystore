use std::error::Error;
use beam_keystore::keystore::{
    KeystoreInput, InputKdfParams, KeystoreGenerator,
};

fn main() -> Result<(), Box<dyn Error>> {
    // Example JSON input structure with Argon2id parameters
    let json_input = r#"
    {
        "private_key": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "password": "your_secure_password",
        "address": "0x742d35Cc6633C0532925a3b8D136CC35dc0f7D61",
        "kdf_params": {
            "m_cost": 65536,
            "t_cost": 3,
            "p_cost": 1,
            "dklen": 32
        }
    }
    "#;

    let generator = KeystoreGenerator::new();
    
    println!("Generating keystore from JSON input...");
    
    // Generate keystore from JSON
    let keystore = generator.load_and_generate_from_json(json_input)?;
    
    // Print the generated keystore
    println!("\nGenerated Keystore:");
    println!("{}", serde_json::to_string_pretty(&keystore)?);
    
    // Save to file
    let filename = format!("keystore_{}.json", keystore.id);
    generator.save_keystore(&keystore, &filename)?;

    // Example of creating keystore directly from struct
    println!("\n--- Creating another keystore ---");
    
    let input2 = KeystoreInput {
        private_key: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
        password: "another_password".to_string(),
        address: None, // Will derive from private key
        kdf_params: Some(InputKdfParams {
            m_cost: Some(32768), // 32 MB
            t_cost: Some(2),     // 2 iterations
            p_cost: Some(1),     // 1 thread
            dklen: Some(32),
        }),
    };

    let keystore2 = generator.generate_keystore(input2)?;
    println!("Second keystore generated:");
    println!("{}", serde_json::to_string_pretty(&keystore2)?);
    
    let filename2 = format!("keystore_{}.json", keystore2.id);
    generator.save_keystore(&keystore2, &filename2)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keystore_generation() {
        let generator = KeystoreGenerator::new();
        let input = KeystoreInput {
            private_key: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            password: "test_password".to_string(),
            address: Some("0x742d35Cc6633C0532925a3b8D136CC35dc0f7D61".to_string()),
            kdf_params: None,
        };

        let result = generator.generate_keystore(input);
        assert!(result.is_ok());
        
        let keystore = result.unwrap();
        assert_eq!(keystore.version, 5);
        assert_eq!(keystore.crypto.cipher, "aes-256-gcm");
        assert_eq!(keystore.crypto.kdf, "argon2id");
        assert_eq!(keystore.keytype, "xmss-poisedon2-ots");
    }

    #[test]
    fn test_json_parsing() {
        let json = r#"
        {
            "private_key": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "password": "test",
            "address": "0x742d35Cc6633C0532925a3b8D136CC35dc0f7D61"
        }
        "#;

        let input: Result<KeystoreInput, _> = serde_json::from_str(json);
        assert!(input.is_ok());
    }

    #[test]
    fn test_private_key_validation() {
        let generator = KeystoreGenerator::new();
        
        // Valid key
        let result = generator.process_private_key("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        assert!(result.is_ok());
        
        // Valid key with 0x prefix
        let result = generator.process_private_key("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        assert!(result.is_ok());
        
        // Invalid key (too short)
        let result = generator.process_private_key("1234");
        assert!(result.is_err());
    }
}