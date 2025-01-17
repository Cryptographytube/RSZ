import hashlib
import ecdsa
import base58

def bitcoin_key_conversion(hex_private_key):
    """Convert raw hex private key to Bitcoin formats (WIF, Public Key, Address)."""
    try:
        # Convert hex private key to bytes
        private_key_bytes = bytes.fromhex(hex_private_key)

        # Step 1: Create WIF (Uncompressed)
        extended_key = b'\x80' + private_key_bytes
        checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
        wif_private_key_uncompressed = base58.b58encode(extended_key + checksum).decode()

        # Step 2: Create WIF (Compressed)
        compressed_key = extended_key + b'\x01'
        checksum_compressed = hashlib.sha256(hashlib.sha256(compressed_key).digest()).digest()[:4]
        wif_private_key_compressed = base58.b58encode(compressed_key + checksum_compressed).decode()

        # Step 3: Generate Public Key (Uncompressed)
        sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        public_key_uncompressed = b'\x04' + vk.to_string()

        # Step 4: Generate Public Key (Compressed)
        x = vk.to_string()[:32]
        y = vk.to_string()[32:]
        if int.from_bytes(y, "big") % 2 == 0:
            public_key_compressed = b'\x02' + x
        else:
            public_key_compressed = b'\x03' + x

        # Step 5: Generate Bitcoin Address (Uncompressed)
        sha256_bpk_uncompressed = hashlib.sha256(public_key_uncompressed).digest()
        ripemd160_bpk_uncompressed = hashlib.new('ripemd160', sha256_bpk_uncompressed).digest()
        extended_ripemd160_uncompressed = b'\x00' + ripemd160_bpk_uncompressed
        checksum_uncompressed = hashlib.sha256(hashlib.sha256(extended_ripemd160_uncompressed).digest()).digest()[:4]
        bitcoin_address_uncompressed = base58.b58encode(extended_ripemd160_uncompressed + checksum_uncompressed).decode()

        # Step 6: Generate Bitcoin Address (Compressed)
        sha256_bpk_compressed = hashlib.sha256(public_key_compressed).digest()
        ripemd160_bpk_compressed = hashlib.new('ripemd160', sha256_bpk_compressed).digest()
        extended_ripemd160_compressed = b'\x00' + ripemd160_bpk_compressed
        checksum_compressed_address = hashlib.sha256(hashlib.sha256(extended_ripemd160_compressed).digest()).digest()[:4]
        bitcoin_address_compressed = base58.b58encode(extended_ripemd160_compressed + checksum_compressed_address).decode()

        return {
            "Real Private Key (Hex)": hex_private_key,
            "WIF Uncompressed": wif_private_key_uncompressed,
            "WIF Compressed": wif_private_key_compressed,
            "Public Key Uncompressed": public_key_uncompressed.hex(),
            "Public Key Compressed": public_key_compressed.hex(),
            "Bitcoin Address Uncompressed": bitcoin_address_uncompressed,
            "Bitcoin Address Compressed": bitcoin_address_compressed,
        }
    except Exception as e:
        return f"Error in Bitcoin key conversion: {e}"

def ethereum_key_conversion(hex_private_key):
    """Convert raw hex private key to Ethereum address."""
    try:
        # Convert private key to public address
        private_key_bytes = bytes.fromhex(hex_private_key)
        public_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key.to_string()
        ethereum_address = "0x" + hashlib.sha3_256(public_key).hexdigest()[-40:]
        return ethereum_address
    except Exception as e:
        return f"Error in Ethereum key conversion: {e}"

def main():
    # Prompt user to enter the raw hex private key
    hex_private_key = input("Enter your raw private key (hex format): ").strip()

    if hex_private_key.startswith("0x"):
        hex_private_key = hex_private_key[2:]

    print("\n=== Bitcoin Key Conversion ===")
    bitcoin_results = bitcoin_key_conversion(hex_private_key)
    if isinstance(bitcoin_results, dict):
        for key, value in bitcoin_results.items():
            print(f"{key}: {value}")
    else:
        print(bitcoin_results)

    print("\n=== Ethereum Key Conversion ===")
    ethereum_address = ethereum_key_conversion(hex_private_key)
    if "Error" not in ethereum_address:
        print(f"Ethereum Address: {ethereum_address}")
    else:
        print(ethereum_address)

if __name__ == "__main__":
    main()
