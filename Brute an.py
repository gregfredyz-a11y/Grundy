# Ensure the Colab-safe hashing modules are present
!pip install pycryptodome ecdsa -q

import hashlib
import secrets
import ecdsa
from Crypto.Hash import RIPEMD160

# Base58 mapping definitions
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def base58_encode(b: bytes) -> str:
    n = int.from_bytes(b, 'big')
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(BASE58_ALPHABET[r])
    pad = 0
    for byte in b:
        if byte == 0: pad += 1
        else: break
    return "1" * pad + "".join(reversed(res))

def generate_legacy_address():
    """Generates a random key pair and returns the private hex and true Base58 address string."""
    priv_int = secrets.randbits(256)
    while priv_int >= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 or priv_int == 0:
        priv_int = secrets.randbits(256)
        
    priv_bytes = priv_int.to_bytes(32, 'big')
    sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
    pub_bytes = b'\x04' + sk.verifying_key.to_string()
    
    # Double-hash structure (SHA256 -> RIPEMD160)
    sha256_bp = hashlib.sha256(pub_bytes).digest()
    ripemd160_engine = RIPEMD160.new()
    ripemd160_engine.update(sha256_bp)
    
    # Apply Mainnet protocol version prefix byte
    network_bytes = b'\x00' + ripemd160_engine.digest()
    checksum = hashlib.sha256(hashlib.sha256(network_bytes).digest()).digest()[:4]
    
    return format(priv_int, '064x'), base58_encode(network_bytes + checksum)

# --- Micro Hunt Demonstration ---
target_prefix = "19tv"
found_count = 0
target_matches = 2 # Change this higher if you want to let it run long-term

print(f"[*] Commencing brute-force routine to find {target_matches} instances of {target_prefix}...")

attempts = 0
while found_count < target_matches:
    attempts += 1
    priv_hex, b58_address = generate_legacy_address()
    
    if b58_address.startswith(target_prefix):
        found_count += 1
        print(f"\n[+] Match Found! (#{found_count})")
        print(f"    Attempts required: {attempts:,}")
        print(f"    Private Key (Hex): {priv_hex}")
        print(f"    Bitcoin Address  : {b58_address}")
        attempts = 0 # Reset counter for the next loop tracking interval
