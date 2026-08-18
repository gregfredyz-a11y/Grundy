import hashlib
import math
import os
import multiprocessing
import ecdsa

# --- Keep the ScaledAddressBloomFilter from before but wrap inside the main execution ---
class ScaledAddressBloomFilter:
    def __init__(self, expected_elements: int, false_positive_rate: float = 0.001):
        self.expected_elements = expected_elements
        self.fp_rate = false_positive_rate
        self.size = int(- (expected_elements * math.log(false_positive_rate)) / (math.log(2) ** 2))
        self.num_hashes = max(1, int((self.size / expected_elements) * math.log(2)))
        self.bit_array = bytearray((self.size // 8) + 1)

    def _get_bit_positions(self, address: str):
        addr_clean = address.strip()
        h1 = int(hashlib.sha256(addr_clean.encode()).hexdigest(), 16)
        h2 = int(hashlib.md5(addr_clean.encode()).hexdigest(), 16)
        for i in range(self.num_hashes):
            yield (h1 + i * h2) % self.size

    def add(self, address: str):
        for bit_pos in self._get_bit_positions(address):
            byte_idx = bit_pos // 8
            bit_idx = bit_pos % 8
            self.bit_array[byte_idx] |= (1 << bit_idx)

    def contains(self, address: str) -> bool:
        for bit_pos in self._get_bit_positions(address):
            byte_idx = bit_pos // 8
            bit_idx = bit_pos % 8
            if not (self.bit_array[byte_idx] & (1 << bit_idx)):
                return False
        return True

def private_key_to_address(private_key_int: int) -> str:
    """Fast conversion of an integer to a hex-encoded legacy public address."""
    priv_bytes = private_key_int.to_bytes(32, 'big')
    sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    pub_bytes = b'\x04' + vk.to_string()
    
    sha256_bp = hashlib.sha256(pub_bytes).digest()
    ripemd160 = hashlib.new('ripemd160', sha256_bp).digest()
    return (b'\x00' + ripemd160).hex()

def load_addresses_into_filter(filename: str, expected_count: int) -> ScaledAddressBloomFilter:
    bloom = ScaledAddressBloomFilter(expected_elements=expected_count, false_positive_rate=0.001)
    if not os.path.exists(filename):
        raise FileNotFoundError(f"Please create '{filename}' first.")
    
    print(f"[*] Loading database file: {filename}...")
    with open(filename, "r") as file:
        for line in file:
            address = line.strip()
            if address:
                bloom.add(address)
    return bloom

# --- Worker Function Executed by Each CPU Core ---
def worker_scan_chunk(worker_id: int, start_key: int, chunk_size: int, bloom_filter, target_file: str):
    """Executes range generation locally on a single core."""
    end_key = start_key + chunk_size
    print(f"[Core {worker_id}] Scanning range: {hex(start_key)} -> {hex(end_key)}")
    
    for current_key in range(start_key, end_key):
        derived_address = private_key_to_address(current_key)
        
        # Check the shared filter memory
        if bloom_filter.contains(derived_address):
            hex_key = format(current_key, '064x')
            print(f"\n⚡ [Core {worker_id} - Bloom Hit!] Found match at key: {hex_key}")
            
            # Secondary text verification to drop false positives
            is_confirmed = False
            with open(target_file, "r") as f:
                if derived_address in f.read():
                    is_confirmed = True
            
            if is_confirmed:
                print(f"🎉 [MATCH VERIFIED BY CORE {worker_id}] !!!")
                with open("found_keys.txt", "a") as out_file:
                    out_file.write(f"Key: {hex_key} | Addr: {derived_address}\n")
                return True # Signal chunk completion with hit
                
    return False

# --- Orchestrator ---
if __name__ == "__main__":
    TARGET_FILE = "funded_addresses.txt"
    ESTIMATED_ADDRESSES = 100000 
    
    # 1. Initialize and build the master Bloom filter in parent memory
    master_filter = load_addresses_into_filter(TARGET_FILE, ESTIMATED_ADDRESSES)
    
    # 2. Determine processing scale based on your system hardware
    num_cores = multiprocessing.cpu_count()
    print(f"[*] Detected {num_cores} CPU cores. Initializing parallel workspace...")
    
    # Define globally targeted key ranges
    global_start = 2**253
    chunk_allocation = 50000  # Number of keys checked per core loop sequence
    
    # 3. Create process arguments for each independent core
    process_pool = []
    for i in range(num_cores):
        # Calculate distinct non-overlapping chunk ranges for each worker
        core_start_key = global_start + (i * chunk_allocation)
        
        p = multiprocessing.Process(
            target=worker_scan_chunk, 
            args=(i, core_start_key, chunk_allocation, master_filter, TARGET_FILE)
        )
        process_pool.append(p)
    
    print("[*] Launching worker engines synchronously...")
    print("-" * 60)
    
    # 4. Start all cores simultaneously
    for p in process_pool:
        p.start()
        
    # 5. Maintain alignment until all processes conclude
    for p in process_pool:
        p.join()
        
    print("\n[-] All active CPU core ranges checked successfully.")
