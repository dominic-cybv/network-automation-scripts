import hashlib
import os

def calculate_hash(file_path):
    """Generates a SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    
    try:
        with open(file_path, "rb") as f:
            # Read file in chunks to avoid memory overload on large files
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return None

def check_integrity(files_to_monitor, baseline_hashes):
    print("[*] Starting Integrity Check...")
    
    for file_path in files_to_monitor:
        current_hash = calculate_hash(file_path)
        
        if current_hash is None:
            print(f"[!] ALERT: File {file_path} has been DELETED!")
        elif current_hash != baseline_hashes.get(file_path):
            print(f"[!] ALERT: INTEGRITY VIOLATION! File {file_path} has been MODIFIED.")
            print(f"    |_ Old Hash: {baseline_hashes.get(file_path)}")
            print(f"    |_ New Hash: {current_hash}")
        else:
            print(f"[+] {file_path} is secure (Hash Verified).")

if __name__ == "__main__":
    # Example: Protecting a critical config file
    critical_files = ["config.ini", "passwords.txt"]
    
    # In a real app, these 'baseline' hashes would be stored in a secure database
    # For this demo, we assume these are the known good hashes
    known_good_hashes = {
        "config.ini": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        "passwords.txt": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
    }
    
    check_integrity(critical_files, known_good_hashes)
