from Crypto.Util import number
import random
# NOTE
# RSA is not a block cipher and CBC mode is not used in real-world cryptosystems.


# KEYGEN
def random_prime(no_bits: int) -> int:
    """
    Docstring for random_prime
    
    :param no_bits: Bit length of the desired prime.
    :type no_bits: int
    :return: random prime.
    :rtype: int
    """
    assert no_bits >= 2

    return number.getPrime(no_bits)

def is_prime(prime: int) -> bool:
    return True

def keygen(no_bits: int) -> tuple[int, int, int]:
    """
    Docstring for keygen
    
    :param no_bits: Description
    :type no_bits: int
    :return: Description
    :rtype: tuple[int, int, int]
    """
    # get 2 distinct primes
    p = random_prime(no_bits)
    q = random_prime(no_bits)
    while p == q:
        q = random_prime(no_bits)

    # modulus
    n = p * q

    # Eulers totient (for prime numbers)
    phi = (p - 1) * (q - 1)
    
    # public exponent
    e = 65537

    # safety
    if phi % e == 0:
        # NOTE add error handling here, do while?
        raise ValueError("Unlucky primes, keygen failed")
    
    # private exponent
    d = pow(e, -1, phi)

    return e, d, n

# testing of the key generation algorithm
if False:
    e, d, n = keygen(8)
    print(e)
    print(d)
    print(n)



# CONVERTING THE DATA INTO BLOCKS

def validate_block_size(block_size: int, n: int):
    if block_size * 8 >= n.bit_length():
        raise ValueError("Block size too large for RSA modulus")


def generate_iv(block_size: int) -> int:
    min_val = 0
    max_val = 2 ** (block_size * 8) - 1
    return random.randint(min_val, max_val)

def pad_message(message: bytes, block_size: int) -> bytes:
    # PKCS-style padding
    # NOTE can fail if the padding exceeds 255 (one byte)
    padding_len = block_size - (len(message) % block_size)
    return message + bytes([padding_len] *  padding_len) # adds n number n numbers at the end of the message 

def unpad_message(message: bytes) -> bytes:
    padding_len = message[-1]
    return message[:-padding_len]

def convert_msg_to_blocks(message: bytes, block_size: int) -> list[int]:
    blocks = []
    # pad the message
    message = pad_message(message, block_size)

    # split the message into blocks
    for i in range(0, len(message), block_size):
        # iterate over the message
        block = message[i: i+block_size]
        block_int = int.from_bytes(block, byteorder="big")
        blocks.append(block_int)
    
    return blocks

def string_to_blocks(text: str, block_size: int) -> list[int]:

    # pad the message
    # print(f"text is:\n{text}")
    message = text.encode("utf-8")
    # print(f"message encoded in utf-8 is:\n{message}")
    message = pad_message(message, block_size)
    # print(f"padded message (block size = {block_size}) is:\n{message}")

    # convert the message into blocks
    blocks = []
    for i in range(0, len(message), block_size):
        # iterate over the message
        block = message[i: i+block_size]
        block_int = int.from_bytes(block, byteorder="big")
        blocks.append(block_int)
    # print(f"message in block form is:\n{blocks}")
    return blocks

def blocks_to_string(blocks: list[int], block_size: int) -> str:

    message = b""
    for block in blocks:
        chunk = block.to_bytes(block_size, byteorder="big")
        message += chunk

    message = unpad_message(message)
    # print(f"decoded message is:\n {message}")
    return message.decode("utf-8")

# testing of the padding functionality
if False:
    text = "Bicycle Day is an unofficial celebration on April 19th of the psychedelic revolution[1] and the first psychedelic trip on LSD by Albert Hofmann in 1943, in tandem with his bicycle ride home from Sandoz Labs.[2][3] It is commonly celebrated by ingesting psychedelics and riding a bike, sometimes in a parade,[4] and often with psychedelic-themed festivities.[5] The holiday was first named and declared in 1985 by Thomas Roberts, a psychology professor at Northern Illinois University,[6][7] but has likely been celebrated by psychedelic enthusiasts since the beginning of the psychedelic era, and celebrated in popular culture since at least 2004.[8]"

    # text = "Bicycle Day (psychedelic holiday)"
    block_size = 10

    blocks = string_to_blocks(text, block_size)

    decoded_text = blocks_to_string(blocks, block_size)

# ENCRYPTION

# make IV = public key?
# need to add checking, that block_int < n

def rsa_encrypt_block(m: int, e: int, n: int) -> int:
    if m >= n:
        raise ValueError("Block too large for modulus")
    return pow(m, e, n)

def rsa_decrypt_block(c: int, d: int, n: int) -> int:
    return pow(c, d, n)

def xor_int(a: int, b: int) -> int:
    return a ^ b

def rsa_cbc_encrypt(blocks: list[int], e: int, n: int, iv: int, block_size: int) -> list[int]:
    encrypted_blocks = []
    mask = (1 << (block_size * 8)) - 1

    prev = iv & mask

    for block in blocks:
        mixed = block ^ prev
        encrypted_block = rsa_encrypt_block(mixed, e, n)
        encrypted_blocks.append(encrypted_block)
        prev = encrypted_block & mask # important

    return encrypted_blocks

def rsa_cbc_decrypt(encrypted_blocks: list[int], d: int, n: int, iv: int, block_size: int) -> list[int]:
    blocks = []
    mask = (1 << (block_size * 8)) - 1

    prev = iv & mask

    for encrypted_block in encrypted_blocks:
        mixed = rsa_decrypt_block(encrypted_block, d, n)
        mixed &= mask # importatn
        block = mixed ^ prev
        blocks.append(block)
        prev = encrypted_block & mask # important

    return blocks


def encrypt_text(text: str, e: int, n: int, block_size: int):
    validate_block_size(block_size, n)
    blocks = string_to_blocks(text, block_size)
    iv = generate_iv(block_size)

    encrypted_blocks = rsa_cbc_encrypt(blocks, e, n, iv, block_size)  # FIX
    return iv, encrypted_blocks


def decrypt_text(encrypted_blocks, d, n, iv, block_size):
    blocks = rsa_cbc_decrypt(encrypted_blocks, d, n, iv, block_size)
    return blocks_to_string(blocks, block_size)

# testing for the complete CBC encryption
if True:
    text = "Bicycle Day is an unofficial celebration on April 19th of the psychedelic revolution[1] and the first psychedelic trip on LSD by Albert Hofmann in 1943, in tandem with his bicycle ride home from Sandoz Labs.[2][3] It is commonly celebrated by ingesting psychedelics and riding a bike, sometimes in a parade,[4] and often with psychedelic-themed festivities.[5] The holiday was first named and declared in 1985 by Thomas Roberts, a psychology professor at Northern Illinois University,[6][7] but has likely been celebrated by psychedelic enthusiasts since the beginning of the psychedelic era, and celebrated in popular culture since at least 2004.[8]"

    public_key, private_key, modulus = keygen(64)
    block_size = 8
    validate_block_size(block_size, modulus) # important! 

    initialisation_vector, encrypted_content = encrypt_text(text, public_key, modulus, block_size)
    print(f"initialisation_vector:\n{initialisation_vector}")
    print(f"encrypted text:\n{encrypted_content}")

    decrypted_text = decrypt_text(encrypted_content, private_key, modulus, initialisation_vector, block_size)
    print(f"the text is decrypted back to:\n{decrypted_text}")