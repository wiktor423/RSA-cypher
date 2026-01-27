import base64
import rsa_core
import ecb


RED = "\033[31m"
RESET = "\033[0m"

def main():
    KEY_BITS = 512
    BLOCK_SIZE = 8
    MESSAGE = "This text is a sample for external RSA verification."

    print("\n=== RSA ECB VERIFICATION ===\n")
    print(f"text = {RED}{MESSAGE}{RESET}\n")

    e, d, n = rsa_core.keygen(KEY_BITS)

    print("Public key:")
    print(f"  n = {RED}{n}{RESET}")
    print(f"  e = {RED}{e}{RESET}")

    print("\nPrivate key:")
    print(f"  d = {RED}{d}{RESET}")

    rsa_core.validate_block_size(BLOCK_SIZE, n)

    plaintext_blocks = rsa_core.string_to_blocks(MESSAGE, BLOCK_SIZE)
    encrypted_blocks = ecb.rsa_ecb_encrypt(plaintext_blocks, e, n)

    print("\nPlaintext blocks (integers):")
    for b in plaintext_blocks:
        print(f"\n {RED}{b}{RESET}")

    print("\nCiphertext blocks (integers):")
    for c in encrypted_blocks:
        print(f"\n {RED}{c}{RESET}")
    print()

    decrypted_blocks = ecb.rsa_ecb_decrypt(encrypted_blocks, d, n)
    recovered_text = rsa_core.blocks_to_string(decrypted_blocks, BLOCK_SIZE)

    print("\nRecovered text:")
    print(f"{RED}{recovered_text}{RESET}")

    print("\nExternal check (dCode):")
    print("https://www.dcode.fr/rsa-cipher?\n")

    print(f"  C = {RED}<one ciphertext block>{RESET}")
    print(f"  E = {RED}{e}{RESET}")
    print(f"  N = {RED}{n}{RESET}")
    print(f"  D = {RED}{d}{RESET}")
    
    print("Leave other fields empty, press CALCULATE/DECRYPT.\n")


if __name__ == "__main__":
    main()
