import argparse
import hashlib
import os
import sys
import time 
import glob
from datetime import datetime
import json

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"


def generate_keys():
    """Generate RSA key pair."""

    if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
        print("✅ Key pair already exists.")
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print("✅ RSA key pair generated successfully.")
    print(f"🔐 Private Key: {PRIVATE_KEY_FILE}")
    print(f"🔓 Public Key : {PUBLIC_KEY_FILE}")


def load_private_key():
    with open(PRIVATE_KEY_FILE, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )


def load_public_key():
    with open(PUBLIC_KEY_FILE, "rb") as f:
        return serialization.load_pem_public_key(
            f.read()
        )


def calculate_file_hash(file_path):
    """
    Calculate SHA-256 hash of a file.
    Uses chunked reading for large files.
    """

    hasher = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            hasher.update(chunk)

    return hasher.digest()


def save_signature(file_path):
    """Create and save digital signature."""

    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        return

    if not os.path.exists(PRIVATE_KEY_FILE):
        print("❌ Private key not found.")
        print("Run: python secure_monitor.py generate-keys")
        return

    file_hash = calculate_file_hash(file_path)

    private_key = load_private_key()

    signature = private_key.sign(
        file_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    signature_file = file_path + ".sig"

    with open(signature_file, "wb") as f:
        f.write(signature)

    print("✅ Signature created successfully.")
    print(f"📄 Signature file: {signature_file}")


def verify_file(file_path):
    """Verify file integrity and generate JSON alert if modified."""
    signature_file = file_path + ".sig"

    # SIEM report structure
    fim_report = {
        "source": "file_integrity_monitor",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "file_path": file_path,
        "status": "UNKNOWN",
        "message": ""
    }

    if not os.path.exists(file_path) or not os.path.exists(signature_file) or not os.path.exists(PUBLIC_KEY_FILE):
        fim_report["status"] = "ERROR"
        fim_report["message"] = "Missing file, signature, or public key."
        print("❌ Error verification prerequisites missing.")
        return

    current_hash = calculate_file_hash(file_path)

    with open(signature_file, "rb") as f:
        signature = f.read()

    public_key = load_public_key()

    try:
        public_key.verify(
            signature,
            current_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        fim_report["status"] = "SUCCESS"
        fim_report["message"] = "File integrity verified. No modification."
        print("✅ File integrity verified.")

    except Exception:
        fim_report["status"] = "ALERT"
        fim_report["message"] = "WARNING: File modified or signature invalid!"
        print("⚠️ WARNING! File modified or signature invalid.")

    #Save final report for SIEM
    with open("fim_report.json", "w", encoding="utf-8") as f:
        json.dump(fim_report, f, indent=4)

def monitor_directory(dir_path, interval_seconds=10):

    
    # First layer of security: Does this folder really exist?
    if not os.path.exists(dir_path):
        print(f"❌ Error: The directory '{dir_path}' does not exist!")
        sys.exit(1) #program output error code 1
        
    # Second layer of security: Is the given path really a folder or a file?
    if not os.path.isdir(dir_path):
        print(f"❌ Error: '{dir_path}' is a file, not a directory!")
        sys.exit(1)

    print(f"👀 Starting continuous monitoring on: {dir_path} (Interval: {interval_seconds}s)")
    print("Press Ctrl+C to stop.")
    

    """
    Continuously monitors a folder and sends changes to SIEM in JSON format
    """
    print(f"👀 Starting continuous monitoring on: {dir_path} (Interval: {interval_seconds}s)")
    print("Press Ctrl+C to stop.")
    
    while True:
        timestamp_start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        #Find all files in the folder (except .sig signature files and keys)
        
        all_files = [f for f in glob.glob(os.path.join(dir_path, "*")) 
                    if not f.endswith(".sig") and not f.endswith(".pem")]
        
        modified_files = []
        corrupted_files = []
        missing_signatures = []
        
        for file_path in all_files:
            signature_file = file_path + ".sig"
            
            # # Scenario 1: The file does not have a signature
            if not os.path.exists(signature_file):
                missing_signatures.append(file_path)
                continue
                
            current_hash = calculate_file_hash(file_path)
            
            with open(signature_file, "rb") as f:
                signature = f.read()
                
            public_key = load_public_key()
            
            # Scenario 2: Checking file changes with public key
            try:
                public_key.verify(
                    signature,
                    current_hash,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            except Exception:
                # If it is not confirmed, it means the file has been tampered with
                modified_files.append(file_path)

        # Create a periodic report for this time period (Interval)
        if modified_files or missing_signatures:
            fim_report = {
                "source": "file_integrity_monitor",
                "monitor_type": "continuous",
                "scan_window": {
                    "start": timestamp_start,
                    "end": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                },
                "status": "ALERT",
                "details": {
                    "modified_files": modified_files,
                    "new_untracked_files": missing_signatures
                }
            }
            
            # Save report for SIEM
            with open("fim_report.json", "w", encoding="utf-8") as f:
                json.dump(fim_report, f, indent=4)
                
            print(f"⚠️ [{datetime.now().strftime('%H:%M:%S')}] ALERT: Directory modified! JSON report updated.")
        else:
            # Even if everything was safe, you would get a heartbeat report.
            fim_report = {
                "source": "file_integrity_monitor",
                "monitor_type": "continuous",
                "scan_window": {
                    "start": timestamp_start,
                    "end": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                },
                "status": "SUCCESS",
                "details": {
                    "message": "All files intact."
                }
            }
            with open("fim_report.json", "w", encoding="utf-8") as f:
                json.dump(fim_report, f, indent=4)

        #Stop for the specified time period.
        time.sleep(interval_seconds)


def main():
    parser = argparse.ArgumentParser(
        description="Secure File Integrity Monitor using RSA Digital Signatures"
    )

    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser(
        "generate-keys",
        help="Generate RSA key pair"
    )

    save_parser = subparsers.add_parser(
        "save",
        help="Create digital signature for a file"
    )
    save_parser.add_argument("filename")

    check_parser = subparsers.add_parser(
        "check",
        help="Verify file integrity"
    )
    check_parser.add_argument("filename")

    monitor_parser = subparsers.add_parser(
        "monitor",
        help="Continuously monitor a directory"
    )
    monitor_parser.add_argument("dirname", help="Directory path to monitor")
    monitor_parser.add_argument("--interval", type=int, default=10, help="Check interval in seconds")


    args = parser.parse_args()

    if args.command == "generate-keys":
        generate_keys()

    elif args.command == "save":
        save_signature(args.filename)

    elif args.command == "check":
        verify_file(args.filename)

    elif args.command == "monitor":
        monitor_directory(args.dirname, args.interval)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
