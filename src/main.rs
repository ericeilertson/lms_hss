use clap::{Parser, Subcommand};
use std::fs;

#[derive(Parser)]
#[command(name = "lms-cli")]
#[command(about = "A CLI for LMS (Lamport Merkle Signature) operations")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new LMS tree and save the public key and private tree
    CreateTree {
        /// Path to save the public key file
        #[arg(short, long, default_value = "public_key.hex")]
        public_key_file: String,

        /// Path to save the private tree file (JSON format)
        #[arg(short = 't', long, default_value = "private_tree.json")]
        private_tree_file: String,

        /// LMS algorithm type (H5, H10, H15, H20, H25)
        #[arg(short = 'l', long, default_value = "H10")]
        lms_height: String,

        /// Hash width (24 or 32)
        #[arg(short = 'w', long, default_value = "32")]
        hash_width: u8,

        /// LMOTS W parameter (1, 2, 4, 8)
        #[arg(short = 's', long, default_value = "4")]
        ots_w: u8,
    },

    /// Sign a message using an LMS tree
    Sign {
        /// Message to sign (or file path if --file is used)
        message: String,

        /// Read message from file instead of command line
        #[arg(short, long)]
        file: bool,

        /// Path to the private tree file
        #[arg(short = 't', long, default_value = "private_tree.json")]
        private_tree_file: String,

        /// Path to save the signature file
        #[arg(short, long, default_value = "signature.hex")]
        signature_file: String,

        /// The q value (key index) to use for signing
        #[arg(short, long)]
        q: Option<u32>,
    },

    /// Verify a signature
    Verify {
        /// Message that was signed (or file path if --file is used)
        message: String,

        /// Read message from file instead of command line
        #[arg(short, long)]
        file: bool,

        /// Path to the public key file
        #[arg(short, long, default_value = "public_key.hex")]
        public_key_file: String,

        /// Path to the signature file
        #[arg(short, long, default_value = "signature.hex")]
        signature_file: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::CreateTree {
            public_key_file,
            private_tree_file,
            lms_height,
            hash_width,
            ots_w,
        } => {
            match create_tree_command(
                &public_key_file,
                &private_tree_file,
                &lms_height,
                hash_width,
                ots_w,
            ) {
                Ok(_) => println!("LMS tree created successfully!"),
                Err(e) => {
                    eprintln!("Error creating tree: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::Sign {
            message,
            file,
            private_tree_file,
            signature_file,
            q,
        } => match sign_command(&message, file, &private_tree_file, &signature_file, q) {
            Ok(_) => println!("Message signed successfully!"),
            Err(e) => {
                eprintln!("Error signing message: {e}");
                std::process::exit(1);
            }
        },

        Commands::Verify {
            message,
            file,
            public_key_file,
            signature_file,
        } => match verify_command(&message, file, &public_key_file, &signature_file) {
            Ok(valid) => {
                if valid {
                    println!("Signature is VALID");
                } else {
                    println!("Signature is INVALID");
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("Error verifying signature: {e}");
                std::process::exit(1);
            }
        },
    }
}

fn create_tree_command(
    public_key_file: &str,
    private_tree_file: &str,
    lms_height: &str,
    hash_width: u8,
    ots_w: u8,
) -> Result<(), String> {
    match hash_width {
        32 => create_tree_inner::<32>(public_key_file, private_tree_file, lms_height, ots_w),
        24 => create_tree_inner::<24>(public_key_file, private_tree_file, lms_height, ots_w),
        _ => Err("Hash width must be 24 or 32".to_string()),
    }
}

fn create_tree_inner<const N: usize>(
    public_key_file: &str,
    private_tree_file: &str,
    lms_height: &str,
    ots_w: u8,
) -> Result<(), String> {
    // Parse LMS algorithm type
    let lms_type = match (N, lms_height) {
        (32, "H5") => lms_hss::LmsAlgorithmType::LmsSha256N32H5,
        (32, "H10") => lms_hss::LmsAlgorithmType::LmsSha256N32H10,
        (32, "H15") => lms_hss::LmsAlgorithmType::LmsSha256N32H15,
        (32, "H20") => lms_hss::LmsAlgorithmType::LmsSha256N32H20,
        (32, "H25") => lms_hss::LmsAlgorithmType::LmsSha256N32H25,
        (24, "H5") => lms_hss::LmsAlgorithmType::LmsSha256N24H5,
        (24, "H10") => lms_hss::LmsAlgorithmType::LmsSha256N24H10,
        (24, "H15") => lms_hss::LmsAlgorithmType::LmsSha256N24H15,
        (24, "H20") => lms_hss::LmsAlgorithmType::LmsSha256N24H20,
        (24, "H25") => lms_hss::LmsAlgorithmType::LmsSha256N24H25,
        _ => {
            return Err(format!(
                "Invalid combination: hash_width={N}, height={lms_height}"
            ))
        }
    };

    // Parse LMOTS algorithm type
    let ots_type = match (N, ots_w) {
        (32, 1) => lms_hss::LmotsAlgorithmType::LmotsSha256N32W1,
        (32, 2) => lms_hss::LmotsAlgorithmType::LmotsSha256N32W2,
        (32, 4) => lms_hss::LmotsAlgorithmType::LmotsSha256N32W4,
        (32, 8) => lms_hss::LmotsAlgorithmType::LmotsSha256N32W8,
        (24, 1) => lms_hss::LmotsAlgorithmType::LmotsSha256N24W1,
        (24, 2) => lms_hss::LmotsAlgorithmType::LmotsSha256N24W2,
        (24, 4) => lms_hss::LmotsAlgorithmType::LmotsSha256N24W4,
        (24, 8) => lms_hss::LmotsAlgorithmType::LmotsSha256N24W8,
        _ => {
            return Err(format!(
                "Invalid combination: hash_width={N}, ots_w={ots_w}"
            ))
        }
    };

    // Create the LMS tree
    let (public_key, private_tree) = lms_hss::create_lms_tree::<N>(&lms_type, &ots_type)?;

    // Serialize and save public key
    let public_key_bytes = lms_hss::serialize_public_key(&public_key);
    let public_key_hex = hex::encode(&public_key_bytes);
    fs::write(public_key_file, public_key_hex)
        .map_err(|e| format!("Failed to write public key file: {e}"))?;

    // Serialize and save private tree (as JSON for now - this is a simplified approach)
    let tree_data = PrivateTreeData::from_tree(&private_tree, &lms_type, &ots_type);
    let tree_json = serde_json::to_string_pretty(&tree_data)
        .map_err(|e| format!("Failed to serialize private tree: {e}"))?;
    fs::write(private_tree_file, tree_json)
        .map_err(|e| format!("Failed to write private tree file: {e}"))?;

    println!("Public key saved to: {public_key_file}");
    println!("Private tree saved to: {private_tree_file}");

    Ok(())
}

fn sign_command(
    message: &str,
    from_file: bool,
    private_tree_file: &str,
    signature_file: &str,
    q: Option<u32>,
) -> Result<(), String> {
    // Read message
    let message_bytes = if from_file {
        fs::read(message).map_err(|e| format!("Failed to read message file: {e}"))?
    } else {
        message.as_bytes().to_vec()
    };

    // Load private tree
    let tree_json = fs::read_to_string(private_tree_file)
        .map_err(|e| format!("Failed to read private tree file: {e}"))?;
    let tree_data: PrivateTreeData = serde_json::from_str(&tree_json)
        .map_err(|e| format!("Failed to parse private tree: {e}"))?;

    match tree_data.hash_width {
        32 => sign_inner::<32>(&message_bytes, &tree_data, signature_file, q),
        24 => sign_inner::<24>(&message_bytes, &tree_data, signature_file, q),
        _ => Err("Invalid hash width in tree data".to_string()),
    }
}

fn sign_inner<const N: usize>(
    message_bytes: &[u8],
    tree_data: &PrivateTreeData,
    signature_file: &str,
    q: Option<u32>,
) -> Result<(), String> {
    let tree = tree_data.to_tree::<N>()?;
    let lms_type = tree_data.get_lms_type()?;
    let ots_type = tree_data.get_ots_type()?;

    // Use provided q or the tree's current q
    let q_to_use = q.unwrap_or(tree.q);

    // Check if q is valid
    if q_to_use as usize >= tree.private_keys.len() {
        return Err(format!(
            "q value {} is out of range (max: {})",
            q_to_use,
            tree.private_keys.len() - 1
        ));
    }

    // Sign the message
    let signature = lms_hss::lms_sign_message(
        &ots_type,
        &lms_type,
        message_bytes,
        &tree.private_keys[q_to_use as usize],
        q_to_use,
        &tree,
    )?;

    // Serialize and save signature
    let signature_bytes = lms_hss::serialize_signature(&signature);
    let signature_hex = hex::encode(&signature_bytes);
    fs::write(signature_file, signature_hex)
        .map_err(|e| format!("Failed to write signature file: {e}"))?;

    println!("Signature saved to: {signature_file}");
    println!("Used q value: {q_to_use}");

    Ok(())
}

fn verify_command(
    message: &str,
    from_file: bool,
    public_key_file: &str,
    signature_file: &str,
) -> Result<bool, String> {
    // Read message
    let message_bytes = if from_file {
        fs::read(message).map_err(|e| format!("Failed to read message file: {e}"))?
    } else {
        message.as_bytes().to_vec()
    };

    // Load public key
    let public_key_hex = fs::read_to_string(public_key_file)
        .map_err(|e| format!("Failed to read public key file: {e}"))?;
    let public_key_bytes = hex::decode(public_key_hex.trim())
        .map_err(|e| format!("Failed to decode public key hex: {e}"))?;

    // Load signature
    let signature_hex = fs::read_to_string(signature_file)
        .map_err(|e| format!("Failed to read signature file: {e}"))?;
    let signature_bytes = hex::decode(signature_hex.trim())
        .map_err(|e| format!("Failed to decode signature hex: {e}"))?;

    // Determine hash width from public key
    let hash_width = match public_key_bytes.len() {
        48 => 24, // 24 bytes hash + 24 bytes metadata
        56 => 32, // 32 bytes hash + 24 bytes metadata
        _ => return Err("Invalid public key length".to_string()),
    };

    match hash_width {
        32 => verify_inner::<32>(&message_bytes, &public_key_bytes, &signature_bytes),
        24 => verify_inner::<24>(&message_bytes, &public_key_bytes, &signature_bytes),
        _ => Err("Invalid hash width".to_string()),
    }
}

fn verify_inner<const N: usize>(
    message_bytes: &[u8],
    public_key_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, String> {
    // Parse public key and signature
    let public_key = lms_hss::parse_public_contents::<N>(public_key_bytes)?;
    let signature = lms_hss::parse_signature_contents::<N>(signature_bytes)?;

    // Verify signature
    lms_hss::verify_lms_signature(message_bytes, &public_key, &signature)
}

// Helper structures for serialization
#[derive(serde::Serialize, serde::Deserialize)]
struct PrivateTreeData {
    lms_identifier: [u8; 16],
    q: u32,
    t_tree: Vec<String>,            // hex encoded
    private_keys: Vec<Vec<String>>, // hex encoded
    hash_width: u8,
    lms_type: u32,
    ots_type: u32,
}

impl PrivateTreeData {
    fn from_tree<const N: usize>(
        tree: &lms_hss::LmsTree<N>,
        lms_type: &lms_hss::LmsAlgorithmType,
        ots_type: &lms_hss::LmotsAlgorithmType,
    ) -> Self {
        PrivateTreeData {
            lms_identifier: tree.lms_identifier,
            q: tree.q,
            t_tree: tree
                .t_tree
                .iter()
                .map(|h| hex::encode(h.as_ref()))
                .collect(),
            private_keys: tree
                .private_keys
                .iter()
                .map(|keys| keys.iter().map(|k| hex::encode(k.as_ref())).collect())
                .collect(),
            hash_width: N as u8,
            lms_type: *lms_type as u32,
            ots_type: *ots_type as u32,
        }
    }

    fn to_tree<const N: usize>(&self) -> Result<lms_hss::LmsTree<N>, String> {
        // Convert hex strings back to HashValues
        let t_tree: Result<Vec<_>, _> = self
            .t_tree
            .iter()
            .map(|hex_str| {
                let bytes = hex::decode(hex_str).map_err(|_| "Failed to decode hex in t_tree")?;
                if bytes.len() != N {
                    return Err("Invalid hash length in t_tree".to_string());
                }
                let mut array = [0u8; N];
                array.copy_from_slice(&bytes);
                Ok(lms_hss::HashValue::from(array))
            })
            .collect();
        let t_tree = t_tree?;

        let private_keys: Result<Vec<Vec<_>>, _> = self
            .private_keys
            .iter()
            .map(|key_set| {
                key_set
                    .iter()
                    .map(|hex_str| {
                        let bytes = hex::decode(hex_str)
                            .map_err(|_| "Failed to decode hex in private_keys")?;
                        if bytes.len() != N {
                            return Err("Invalid hash length in private_keys".to_string());
                        }
                        let mut array = [0u8; N];
                        array.copy_from_slice(&bytes);
                        Ok(lms_hss::HashValue::from(array))
                    })
                    .collect()
            })
            .collect();
        let private_keys = private_keys?;

        Ok(lms_hss::LmsTree {
            lms_identifier: self.lms_identifier,
            q: self.q,
            t_tree,
            private_keys,
        })
    }

    fn get_lms_type(&self) -> Result<lms_hss::LmsAlgorithmType, String> {
        lms_hss::lookup_lms_algorithm_type(self.lms_type)
    }

    fn get_ots_type(&self) -> Result<lms_hss::LmotsAlgorithmType, String> {
        lms_hss::lookup_lmots_algorithm_type(self.ots_type)
    }
}
