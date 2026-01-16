# LMS HSS (Lamport Merkle Signature - Hash-based Signatures)

A Rust implementation of LMS (Lamport Merkle Signature) as specified in RFC 8554, including a command-line interface for creating trees, signing documents, and verifying signatures.

## Features

- Create LMS trees with various parameters (hash width: 24/32 bytes, tree heights: H5-H25, LMOTS W parameters: 1,2,4,8)
- Sign messages or files using LMS signatures
- Verify LMS signatures
- Serialization/deserialization of public keys, signatures, and private trees
- Command-line interface for easy usage

## Installation

```bash
cargo build --release
```

## Usage

### Create an LMS Tree

```bash
# Create a tree with default parameters (32-byte hash, H10 height, W=4)
./target/release/lms_hss create-tree

# Create a tree with custom parameters
./target/release/lms_hss create-tree --lms-height H5 --hash-width 24 --ots-w 2 \
    --public-key-file my_public_key.hex --private-tree-file my_tree.json
```

### Sign a Message

```bash
# Sign a string message
./target/release/lms_hss sign "Hello, World!"

# Sign a file
./target/release/lms_hss sign --file document.txt --signature-file document.sig.hex

# Sign with a specific key index (q value)
./target/release/lms_hss sign "Message" --q 5
```

### Verify a Signature

```bash
# Verify a string message
./target/release/lms_hss verify "Hello, World!"

# Verify a file
./target/release/lms_hss verify --file document.txt --signature-file document.sig.hex
```

## LMS Parameters

### Hash Widths
- `24`: 192-bit hash (SHA-256 truncated to 24 bytes)
- `32`: 256-bit hash (full SHA-256)

### Tree Heights
- `H5`: 32 signatures (2^5)
- `H10`: 1024 signatures (2^10) - default
- `H15`: 32768 signatures (2^15)
- `H20`: 1048576 signatures (2^20)
- `H25`: 33554432 signatures (2^25)

### LMOTS W Parameters
- `1`: Maximum security, largest signatures
- `2`: High security, large signatures
- `4`: Balanced security/size - default
- `8`: Smaller signatures, faster operations

## File Formats

- **Public Key**: Hexadecimal encoded binary format
- **Signature**: Hexadecimal encoded binary format
- **Private Tree**: JSON format (for persistence and reuse)

## Security Note

LMS is a quantum-resistant signature scheme. Each private key can only be used once (one-time signatures), so keep track of the `q` value (key index) to avoid reusing keys.

## License

This implementation follows RFC 8554 specification.