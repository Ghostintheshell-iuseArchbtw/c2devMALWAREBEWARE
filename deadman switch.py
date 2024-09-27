############################################################################################################################################
###Deadman's Switch - A Python script to encrypt, compress, and shred files################################################################# 
##and directories at regular intervals using a deadman's switch#############################################################################            
############################################################################################################################################

import os
import logging
import getpass
import subprocess
import os

# Problem 2: "datetime" is not defined
shockandpwn_time = datetime.datetime(2022, 1, 1)  # Replace with the desired shockandPWN time

# Problem 4: "files" is not accessed
for root, dirs, _ in os.walk(directory_path, topdown=False):
    pass


def decrypt_data(file_path, cipher):
    """
    Decrypt data in a file.

    Args:
        file_path (str): Path to the file to be decrypted.
        cipher (Fernet): The Fernet cipher object.
    """
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
        decrypted_data = cipher.decrypt(encrypted_data)
    
    with open(file_path, 'wb') as file:
        file.write(decrypted_data)



def decompress_data(file_path):
    """
    Decompress a file.

    Args:
        file_path (str): Path to the file to be decompressed.
    """
    with open(file_path, 'rb') as file:
        compressed_data = file.read()
    
    decompressed_data = gzip.decompress(compressed_data)
    
    with open(file_path, 'wb') as file:
        file.write(decompressed_data)


def decrypt_files_and_directories(directory_path, cipher):
    """
    Decrypt files and directories.

    Args:
        directory_path (str): Path to the directory to decrypt.
        cipher (Fernet): The Fernet cipher object.
    """
    for root, _, files in os.walk(directory_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            decrypt_data(file_path, cipher)
            shred_file(file_path)


def check_passphrase(passphrase, file_path, key_file_path, cipher):
    """
    Check for a passphrase and perform actions accordingly.

    Args:
        passphrase (str): The passphrase.
        file_path (str): Path to the file to encrypt, compress, and shred.
        key_file_path (str): Path to the encryption key file.
        cipher (Fernet): The Fernet cipher object.
    """
    user_input = getpass.getpass("Enter passphrase: ")
    if user_input == passphrase:
        encrypt_and_shred_self(file_path, cipher)
        shred_file(key_file_path)
        delete_file(key_file_path)
        logging.info("System actions avoided for 48 hours. Thank you Dr. Falken.")


def generate_random_passphrase(passphrase_file):
    """
    Generate a random passphrase and save it to a file.

    Args:
        passphrase_file (str): Path to the passphrase file.
    """
    # Generate a random passphrase
    passphrase = "random_passphrase"

    # Save the passphrase to the file
    with open(passphrase_file, 'w') as file:
        file.write(passphrase)


def main():
    """
    Main function to encrypt, compress, and shred files and directories.
    """
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Encrypt, compress, and shred files and directories.')
    parser.add_argument('file_paths', type=str, nargs='+', help='Paths to the files or directories to encrypt, compress, and shred')
    parser.add_argument('key_file_path', type=str, help='Path to the encryption key file')
    parser.add_argument('--decrypt', action='store_true', help='Decrypt the files or directories instead of encrypting, compressing, and shredding')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--interval', type=int, default=24, help='Interval in hours to check for the passphrase (default: 24)')
    parser.add_argument('--passphrase', type=str, default='200OK', help='Passphrase to trigger the actions (default: 200OK)')
    parser.add_argument('--generate-passphrase', action='store_true', help='Generate a random passphrase and save it to a file')
    parser.add_argument('--passphrase-file', type=str, default='passphrase.txt', help='Path to the passphrase file (default: passphrase.txt)')
    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')

    # Read the encryption key from the file
    try:
        encryption_key = read_key_from_file(args.key_file_path)
    except FileNotFoundError:
        logging.error(f"Encryption key file not found: {args.key_file_path}")
        return

    # Create a Fernet cipher object with the key
    cipher = Fernet(encryption_key)

    if args.generate_passphrase:
        generate_random_passphrase(args.passphrase_file)
        logging.info(f"Passphrase generated and saved to {args.passphrase_file}")
        return

    if args.decrypt:
        for file_path in args.file_paths:
            if os.path.isfile(file_path):
                try:
                    decrypt_data(file_path, cipher)
                    decompress_data(file_path)
                except FileNotFoundError:
                    logging.error(f"File not found: {file_path}")
            elif os.path.isdir(file_path):
                try:
                    decrypt_files_and_directories(file_path, cipher)
                    delete_empty_directories(file_path)
                except FileNotFoundError:
                    logging.error(f"Directory not found: {file_path}")
            else:
                logging.error(f"Invalid file or directory path: {file_path}")
    else:
        for file_path in args.file_paths:
            if os.path.isfile(file_path):
                try:
                    compress_file(file_path)
                    encrypt_and_shred_file(file_path, cipher)
                    shred_file(file_path)
                except FileNotFoundError:
                    logging.error(f"File not found: {file_path}")
            elif os.path.isdir(file_path):
                try:
                    encrypt_compress_and_shred_directory(file_path, cipher)
                    delete_empty_directories(file_path)
                except FileNotFoundError:
                    logging.error(f"Directory not found: {file_path}")
            else:
                logging.error(f"Invalid file or directory path: {file_path}")

    # Check for passphrase at regular intervals
    while True:
        for file_path in args.file_paths:
            try:
                check_passphrase(args.passphrase, file_path, args.key_file_path, cipher)
            except FileNotFoundError:
                logging.error(f"File not found: {file_path}")
        logging.info(f"Waiting for {args.interval} hours...")
        time.sleep(args.interval * 3600)


if __name__ == "__main__":
    main()
