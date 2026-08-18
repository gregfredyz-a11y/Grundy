import hashlib
import math
import os

class ScaledAddressBloomFilter:
    def __init__(self, expected_elements: int, false_positive_rate: float = 0.001):
        """
        Calculates the mathematically optimal size (m) and number of hashes (k)
        to minimize memory usage while keeping false positives low.
        """
        self.expected_elements = expected_elements
        self.fp_rate = false_positive_rate
        
        # Formula for optimal bit array size: m = -(n * ln(p)) / (ln(2)^2)
        self.size = int(- (expected_elements * math.log(false_positive_rate)) / (math.log(2) ** 2))
        
        # Formula for optimal number of hash functions: k = (m / n) * ln(2)
        self.num_hashes = max(1, int((self.size / expected_elements) * math.log(2)))
        
        # Allocate the bit array (using a bytearray to save massive amounts of RAM)
        # 8 bits per byte. size // 8 + 1 bytes.
        self.bit_array = bytearray((self.size // 8) + 1)
        
        print(f"[*] Bloom Filter Initialized:")
        print(f"    - Target Elements: {expected_elements:,}")
        print(f"    - Bit Array Size : {self.size:,} bits (~{len(self.bit_array) / 1024 / 1024:.2f} MB RAM)")
        print(f"    - Hash Functions : {self.num_hashes}")

    def _get_bit_positions(self, address: str):
        """Generates 'k' unique bit positions using a double-hashing technique."""
        # Clean the input address string
        addr_clean = address.strip()
        
        # Primary hashes
        h1 = int(hashlib.sha256(addr_clean.encode()).hexdigest(), 16)
        h2 = int(hashlib.md5(addr_clean.encode()).hexdigest(), 16)
        
        # Enhanced Double Hashing to generate 'k' distinct indexes efficiently
        for i in range(self.num_hashes):
            yield (h1 + i * h2) % self.size

    def add(self, address: str):
        """Flips the targeted bits in the bytearray to 1."""
        for bit_pos in self._get_bit_positions(address):
            byte_idx = bit_pos // 8
            bit_idx = bit_pos % 8
            self.bit_array[byte_idx] |= (1 << bit_idx)

    def contains(self, address: str) -> bool:
        """Returns False if definitely NOT funded. True if PROBABLY funded."""
        for bit_pos in self._get_bit_positions(address):
            byte_idx = bit_pos // 8
            bit_idx = bit_pos % 8
            if not (self.bit_array[byte_idx] & (1 << bit_idx)):
                return False
        return True

# --- 1. Streaming Data Pipeline ---
def load_addresses_into_filter(filename: str, expected_count: int) -> ScaledAddressBloomFilter:
    """Streams addresses from a disk file into the Bloom Filter line-by-line."""
    # Initialize the filter with a 0.1% target false-positive rate
    bloom = ScaledAddressBloomFilter(expected_elements=expected_count, false_positive_rate=0.001)
    
    if not os.path.exists(filename):
        raise FileNotFoundError(f"Please create '{filename}' first.")
        
    print(f"[*] Streaming addresses from {filename} into Bloom Filter...")
    
    count = 0
    with open(filename, "r") as file:
        for line in file:
            address = line.strip()
            if address: # Skip empty lines
                bloom.add(address)
                count += 1
                if count % 100000 == 0:
                    print(f"    - Processed {count:,} addresses...")
                    
    print(f"[+] Load complete. {count:,} addresses loaded into memory successfully.\n")
    return bloom

# --- 2. Execution & Key Verification Pipeline ---
if __name__ == "__main__":
    # Setup a mock file for testing if you don't have one
    MOCK_FILE = "funded_addresses.txt"
    if not os.path.exists(MOCK_FILE):
        with open(MOCK_FILE, "w") as f:
            f.write("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n")
            f.write("112233445566778899aabbccddeeff\n")
    
    # Estimate how many lines/addresses are in your file. 
    # (Set this number close to or slightly higher than your actual line count)
    ESTIMATED_ADDRESSES = 100000 
    
    # Load the filter
    filter_db = load_addresses_into_filter(MOCK_FILE, ESTIMATED_ADDRESSES)
    
    # --- 3. Live Verification Loop ---
    # Simulate a generated key's address to test the filter
    test_address_1 = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" # Inside the file
    test_address_2 = "1XYZPrandomAddressThatIsNotEmpty111" # Not in the file
    
    for test_addr in [test_address_1, test_address_2]:
        print(f"Checking address: {test_addr}")
        
        # Step A: Lightning-fast Bloom Filter check
        if filter_db.contains(test_addr):
            print("  -> [Bloom Hit] Match found in filter. Double-checking file for accuracy...")
            
            # Step B: Secondary confirmation check against raw data (eliminates false positives)
            is_confirmed = False
            with open(MOCK_FILE, "r") as f:
                if test_addr in f.read():
                    is_confirmed = True
                    
            if is_confirmed:
                print("  -> [CONFIRMED] Address is genuinely funded! 🎉")
            else:
                print("  -> [False Positive] Filter matched, but address is not actually in the file.")
        else:
            print("  -> [Bloom Miss] 100% Not funded. Skipping instantly.")
        print("-" * 50)
