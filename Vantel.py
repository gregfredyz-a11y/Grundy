# 1. Install pycryptodome and ecdsa inside Google Colab
!pip install pycryptodome ecdsa -q

import hashlib
import secrets
import ecdsa
# Import RIPEMD160 cleanly from Crypto.Hash
from Crypto.Hash import RIPEMD160

def generate_random_key_and_address():
    """Generates a random private key integer and its corresponding hex address safely in Colab."""
    priv_int = secrets.randbits(256)
    
    # Ensure it falls within valid secp256k1 parameters
    while priv_int >= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 or priv_int == 0:
        priv_int = secrets.randbits(256)
        
    priv_bytes = priv_int.to_bytes(32, 'big')
    sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    pub_bytes = b'\x04' + vk.to_string()
    
    # Step A: Standard SHA-256 Hash
    sha256_bp = hashlib.sha256(pub_bytes).digest()
    
    # Step B: Safe RIPEMD-160 Hash using pycryptodome (Bypasses Google Colab's native OpenSSL restriction)
    ripemd160_engine = RIPEMD160.new()
    ripemd160_engine.update(sha256_bp)
    ripemd160 = ripemd160_engine.digest()
    
    # Return private integer and network public address string (hex)
    return priv_int, (b'\x00' + ripemd160).hex()

# Target sequential patterns we want to hunt for
target_prefixes = ["000a", "000b", "000c"]
found_addresses = {}

print("Searching for addresses matching custom alphabetical prefixes (Google Colab OpenSSL 3 Fix Active)...\n")

for prefix in target_prefixes:
    print(f"[*] Brute-forcing keys to find an address starting with hex: '{prefix}'...")
    attempts = 0
    while True:
        attempts += 1
        priv_int, address = generate_random_key_and_address()
        
        if address.startswith(prefix):
            print(f"    [+] Found after {attempts:,} attempts!")
            print(f"    Private Key (Hex): {format(priv_int, '064x')}")
            print(f"    Public Address   : {address}\n")
            found_addresses[prefix] = address
            break
