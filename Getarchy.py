import gzip
import shutil
import urllib.request
import os
import time

# --- Configuration Paths ---
# Use the official direct link for all active address databases
DATA_URL = "http://addresses.loyce.club/blockchair_bitcoin_addresses_and_balance_LATEST.tsv.gz"
COMPRESSED_TEMP = "latest_dump.tsv.gz"
FINAL_SORTED_FILE = "sorted_funded_addresses.txt"

def download_latest_dump(url: str, output_path: str):
    """Downloads the massive database stream natively with live progress updates."""
    print(f"[*] Connecting to database server: {url}")
    
    # Custom headers to bypass bot protection thresholds
    req = urllib.request.Request(
        url, 
        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    )
    
    start_time = time.time()
    with urllib.request.urlopen(req) as response, open(output_path, 'wb') as out_file:
        meta = response.info()
        file_size = int(meta.get("Content-Length", 0))
        print(f"[*] Downloading {file_size / 1024 / 1024:.2f} MB compressed archive...")
        
        downloaded = 0
        block_size = 1024 * 256  # 256 KB blocks
        
        while True:
            buffer = response.read(block_size)
            if not buffer:
                break
            downloaded += len(buffer)
            out_file.write(buffer)
            
            # Simple terminal status tracking line
            percent = (downloaded / file_size) * 100 if file_size else 0
            print(f"    -> Progress: {percent:.2f}% ({downloaded / 1024 / 1024:.1f} MB)", end='\r')
            
    print(f"\n[+] Download complete in {time.time() - start_time:.1f} seconds.")

def stream_and_sort_addresses(compressed_source: str, output_target: str):
    """
    Streams raw data out of the gzip bundle, isolates addresses from balances, 
    and sorts the dataset completely using a streaming layout.
    """
    print("[*] Extracting addresses and initializing alphabetization sort structure...")
    address_pool = []
    processed_count = 0
    
    # Open the gzip payload directly on-the-fly without unzipping to disk
    with gzip.open(compressed_source, 'rt', encoding='utf-8') as f:
        # Skip the header row (address \t balance)
        next(f, None)
        
        for line in f:
            # Split out tab-separated string token elements
            parts = line.strip().split('\t')
            if parts:
                addr = parts[0]
                # Filter out standard script artifacts or burn addresses if desired
                if addr and not addr.startswith('m-'):
                    address_pool.append(addr)
                    processed_count += 1
            
            if processed_count % 10000000 == 0 and processed_count > 0:
                print(f"    Parsed {processed_count:,} records out of raw archive...")

    print(f"[+] Extraction complete. Extracted {len(address_pool):,} active addresses.")
    print("[*] Sorting entries alphabetically (This takes roughly 15-40 seconds in RAM)...")
    address_pool.sort()
    
    print(f"[*] Saving verified data to permanent path: {output_target}")
    with open(output_target, "w", encoding='utf-8') as out_f:
        for addr in address_pool:
            out_f.write(f"{addr}\n")
            
    print("[+] Synchronization database successfully populated and organized.")

def cleanup():
    """Removes the massive downloaded archive file to free up storage space."""
    if os.path.exists(COMPRESSED_TEMP):
        os.remove(COMPRESSED_TEMP)
        print("[*] Cleaned up temporary working downloads.")

if __name__ == "__main__":
    try:
        # Step 1: Download the current blockchain state package
        download_latest_dump(DATA_URL, COMPRESSED_TEMP)
        
        # Step 2: Stream it, drop the balance column, sort strings, write to text file
        stream_and_sort_addresses(COMPRESSED_TEMP, FINAL_SORTED_FILE)
        
    except Exception as e:
        print(f"\n[!] Synchronization Execution Failure: {e}")
    finally:
        # Step 3: Delete workspace variables and raw storage overhead files
        cleanup()
