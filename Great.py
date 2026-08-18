import hashlib
import math
import os
import ecdsa

# ... [Keep the ScaledAddressBloomFilter class definition from the previous script here] ...

def private_key_to_address(private_key_int: int) -> str:
    """Derives a legacy Bitcoin-style hex representation from a private key integer."""
    priv_bytes = private_key_int.to_bytes(32, 'big')
    sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    pub_bytes = b'\x04' + vk.to_string()
    
    sha256_bp = hashlib.sha256(pub_bytes).digest()
    ripemd160 = hashlib.new('ripemd160', sha256_bp).digest()
    
    network_ripemd = b'\x00' + ripemd160
    return network_ripemd.hex()

def load_addresses_into_filter(filename: str, expected_count: int) -> ScaledAddressBloomFilter:
    bloom = ScaledAddressBloomFilter(expected_elements=expected_count, false_positive_rate=0.001)
    if not os.path.exists(filename):
        raise FileNotFoundError(f"Please create '{filename}' first.")
        
    print(f"[*] Streaming addresses from {filename} into Bloom Filter...")
    count = 0
    with open(filename, "r") as file:
        for line in file:
            address = line.strip()
            if address:
                bloom.add(address)
                count += 1
    print(f"[+] Load complete. {count:,} addresses loaded into memory successfully.\n")
    return bloom

if __name__ == "__main__":
    TARGET_FILE = "funded_addresses.txt"
    
    # Update this to match the approximate number of entries in your downloaded file
    # Example: If using a 50-million address dump, set this to 50000000
    ESTIMATED_ADDRESSES = 100000 
    
    # Load the filter using the downloaded/mock address database
    filter_db = load_addresses_into_filter(TARGET_FILE, ESTIMATED_ADDRESSES)
    
    # Define your scanning range boundary
    start_range = 2**253
    end_range = start_range + 1000000  # Adjust as needed for execution duration
    
    print(f"[*] Starting range scan from {hex(start_range)}...")
    print("-" * 60)
    
    for current_key in range(start_range, end_range):
        # 1. Derive address from the current private key integer
        derived_address = private_key_to_address(current_key)
        
        # 2. Query the Bloom Filter (Takes less than a microsecond)
        if filter_db.contains(derived_address):
            hex_key = format(current_key, '064x')
            print(f"\n[Bloom Hit] Potential match found at key: {hex_key}")
            print(f"Checking disk database for address: {derived_address}...")
            
            # 3. Confirm against raw data file to rule out false positives
            is_confirmed = False
            with open(TARGET_FILE, "r") as f:
                # Optimized for smaller files; for massive files, use a binary search/indexed DB
                if derived_address in f.read():
                    is_confirmed = True
            
            if is_confirmed:
                print(f"[!!!] SUCCESS: CRITICAL MATCH FOUND [!!!]")
                print(f"Private Key (Hex): {hex_key}")
                print(f"Bitcoin Address  : {derived_address}")
                # Log to an output file immediately so progress isn't lost
                with open("found_keys.txt", "a") as out_file:
                    out_file.write(f"Key: {hex_key} | Addr: {derived_address}\n")
                break  # Stop scanning if a verified match is found
            else:
                print("[-] False positive dismissed. Resuming scan...\n")
                
        # Optional: Print status tracking occasionally so you know the script is alive
        if current_key % 100000 == 0:
            print(f"Currently at key prefix: {format(current_key, '064x')[:16]}...")
