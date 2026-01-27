import rsa_core
import ecb
import cbc

def main():
    print("=== RSA Encryption Console Mode ===\n")
    
    # Mode selection
    print("Select encryption mode:")
    print("1. ECB (Electronic Codebook)")
    print("2. CBC (Cipher Block Chaining)")
    
    mode_choice = input("Enter 1 or 2: ").strip()
    
    if mode_choice not in ['1', '2']:
        print("Invalid choice. Exiting.")
        return
    
    mode = "ECB" if mode_choice == '1' else "CBC"
    print(f"\nSelected mode: {mode}\n")
    
    # Get message from user
    message = input("Enter message to encrypt: ").strip()
    
    if not message:
        print("Message cannot be empty. Exiting.")
        return
    
    # Generate RSA keys
    print("\nGenerating RSA keys...")
    e, d, n = rsa_core.keygen(64)
    block_size = 8
    rsa_core.validate_block_size(block_size, n)
    print("Keys generated successfully!")
    
    # Encrypt
    print(f"\nOriginal message: {message}")
    
    if mode == "ECB":
        encrypted_blocks = ecb.encrypt_text(message, e, n, block_size)
        print(f"\nEncrypted blocks: {encrypted_blocks}")
        
        # Decrypt
        decrypted_message = ecb.decrypt_text(encrypted_blocks, d, n, block_size)
    else:  # CBC
        iv, encrypted_blocks = cbc.encrypt_text(message, e, n, block_size)
        print(f"\nIV: {iv}")
        print(f"Encrypted blocks: {encrypted_blocks}")
        
        # Decrypt
        decrypted_message = cbc.decrypt_text(encrypted_blocks, d, n, iv, block_size)
    
    print(f"\nDecrypted message: {decrypted_message}")
    print("\nDone!")

if __name__ == "__main__":
    main()
