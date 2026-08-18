import sys
import time
import signal
import hashlib
import threading
import warnings
import subprocess
import bisect
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import ecdsa
    from Crypto.Hash import RIPEMD160
except ImportError:
    print("[!] Error: Required modules are missing.")
    print("[*] Please run: pip install ecdsa pycryptodome")
    sys.exit(1)

warnings.filterwarnings("ignore", category=DeprecationWarning)

# --- CONFIGURATION & DATABASE TARGETS ---
DB_FILE = "./funded_addresses.txt"
GENERATOR_WORKERS = 4       # We can turn this up now since there is no network lag!
KEYS_PER_PAGE = 128
DISPLAY_DELAY = 0.001       # Tiny pacing delay for visual stream

# Tracking Metrics
total_keys_checked = 0
total_addresses_checked = 0
database_size = 0
ADDRESS_DATABASE = []

# Synchronicity Locks
file_lock = threading.Lock()
print_lock = threading.Lock()

def trigger_termux_alerts(message):
    try:
        subprocess.Popen(["termux-tts-speak", message], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.Popen(["termux-vibrate", "-d", "1000"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception:
        pass

def signal_handler(signal, frame):
    with print_lock:
        print(f"\n\n[+] Offline Scanner stopped cleanly.")
        print(f"[+] Total Keys Analyzed: {total_keys_checked}")
        print(f"[+] Total Local Checks: {total_addresses_checked}")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def load_database():
    """Loads and indexes the sorted text database into memory for microsecond searching."""
    global ADDRESS_DATABASE, database_size
    if not os.path.exists(DB_FILE):
        print(f"[!] Error: Database file '{DB_FILE}' not found!")
        print("[*] Please download it first using the curl command provided.")
        sys.exit(1)
        
    print("[*] Loading and indexing active address database into RAM...")
    start_time = time.time()
    with open(DB_FILE, "r") as f:
        # Strip whitespace and read lines into memory
        ADDRESS_DATABASE = [line.strip() for line in f if line.strip()]
    
    database_size = len(ADDRESS_DATABASE)
    print(f"[+] Successfully indexed {database_size:,} funded addresses in {time.time() - start_time:.2f} seconds!")

def binary_search_check(address):
    """Executes a O(log n) high-speed binary look-up against the loaded addresses."""
    index = bisect.bisect_left(ADDRESS_DATABASE, address)
    if index < len(ADDRESS_DATABASE) and ADDRESS_DATABASE[index] == address:
        return True
    return False

def base58_encode(b):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n = int.from_bytes(b, 'big')
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(alphabet[r])
    pad = 0
    for byte in b:
        if byte == 0: pad += 1
        else: break
    return '1' * pad + ''.join(reversed(res))

def derive_bitcoin_addresses(priv_int):
    priv_bytes = priv_int.to_bytes(32, 'big')
    extended_key = b'\x80' + priv_bytes
    first_sha = hashlib.sha256(extended_key).digest()
    second_sha = hashlib.sha256(first_sha).digest()
    wif_key = base58_encode(extended_key + second_sha[:4])

    sk = ecdsa.SigningKey.from_secret_exponent(priv_int, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    pub_x = vk.pubkey.point.x().to_bytes(32, 'big')
    pub_y = vk.pubkey.point.y().to_bytes(32, 'big')

    # 1. Legacy Uncompressed Address Mapping
    pub_uncompressed = b'\x04' + pub_x + pub_y
    sha_uncomp = hashlib.sha256(pub_uncompressed).digest()
    h_uncomp = RIPEMD160.new()
    h_uncomp.update(sha_uncomp)
    rmd_uncomp = h_uncomp.digest()
    net_uncomp = b'\x00' + rmd_uncomp
    chk_uncomp = hashlib.sha256(hashlib.sha256(net_uncomp).digest()).digest()[:4]
    legacy_uncompressed = base58_encode(net_uncomp + chk_uncomp)

    # 2. Legacy Compressed Address Mapping
    prefix = b'\x02' if vk.pubkey.point.y() % 2 == 0 else b'\x03'
    pub_compressed = prefix + pub_x
    sha_comp = hashlib.sha256(pub_compressed).digest()
    h_comp = RIPEMD160.new()
    h_comp.update(sha_comp)
    rmd_comp = h_comp.digest()
    net_comp = b'\x00' + rmd_comp
    chk_comp = hashlib.sha256(hashlib.sha256(net_comp).digest()).digest()[:4]
    legacy_compressed = base58_encode(net_comp + chk_comp)

    return wif_key, legacy_uncompressed, legacy_compressed

def generate_local_page(page_num, start_time_tracker):
    """Generates and cross-checks addresses instantly using zero storage footprint."""
    global total_keys_checked, total_addresses_checked
    start_index = ((page_num - 1) * KEYS_PER_PAGE) + 1
    
    for i in range(KEYS_PER_PAGE):
        current_private_key_int = start_index + i
        if current_private_key_int >= 115792089237316195423570985008687907852837564279074904382605163141518161494337:
            return "404"
            
        try:
            wif_str, addr_uncomp, addr_comp = derive_bitcoin_addresses(current_private_key_int)
            
            with file_lock:
                total_keys_checked += 1
                total_addresses_checked += 2

            # Microsecond Local Binary Search Map Verification Lookups
            match_uncomp = binary_search_check(addr_uncomp)
            match_comp = binary_search_check(addr_comp)

            # --- REAL-TIME STREAM UI ---
            with print_lock:
                # Green bracket denotes it passed the local database verify check safely
                sys.stdout.write(f"\033[94mKey (WIF):\033[0m {wif_str}\n")
                sys.stdout.write(f" ├── Uncompressed: {addr_uncomp} \033[92m[Checked Offline]\033[0m\n")
                sys.stdout.write(f" └── Compressed:   {addr_comp} \033[92m[Checked Offline]\033[0m\n\n")
                sys.stdout.flush()

            # If either format matches a signature inside your loaded text db:
            if match_uncomp or match_comp:
                matched_addr = addr_uncomp if match_uncomp else addr_comp
                matched_type = "Legacy Uncompressed" if match_uncomp else "Legacy Compressed"
                
                with file_lock:
                    with open('./FOUND_BALANCES.txt', 'a') as f:
                        f.write(f"HIT! Type: {matched_type} | Address: {matched_addr} | WIF: {wif_str} | Page Context: {page_num}\n")
                    
                    print(f"\n\n\033[91m[!!!] CRITICAL HIT! LOCAL DATABASE WALLET MATCH FOUND!\033[0m")
                    print(f"[!] Address [{matched_type}]: {matched_addr}")
                    print(f"[!] Private Key (WIF): {wif_str} | Page: {page_num}\n\n")
                
                trigger_termux_alerts("Alert! Active Bitcoin wallet found locally!")

            time.sleep(DISPLAY_DELAY)
        except Exception:
            continue
                
    return "SUCCESS"

# --- Initialization Core Setup ---
print("="*60)
print("         100% OFFLINE Cryptographic Key Database Engine     ")
print("="*60)

# Pre-load database map arrays
load_database()

start_page = int(input("\n[?] Enter Start Page: ").strip())
end_input = input("[?] Enter End Page (or press Enter for infinite): ").strip()
end_page = int(end_input) if end_input.isdigit() else float('inf')

print(f"\n[+] Processing parameters locked. Starting offline scan pipeline...")
time.sleep(1)

current_chunk_start = start_page
global_start_time = time.time()

# --- Multi-Core Local Generator Loop ---
while current_chunk_start <= end_page:
    batch_size = min(GENERATOR_WORKERS, (end_page - current_chunk_start) + 1)
    if batch_size <= 0:
        break
        
    page_batch = list(range(current_chunk_start, current_chunk_start + int(batch_size)))
    
    with ThreadPoolExecutor(max_workers=len(page_batch)) as page_executor:
        future_to_page = {page_executor.submit(generate_local_page, p, global_start_time): p for p in page_batch}
        for future in as_completed(future_to_page):
            pass 

    current_chunk_start += len(page_batch)

print("\n[+] Scan operations completed up to target index limit safely!")
