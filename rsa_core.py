from Crypto.Util import number
import random

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

def validate_block_size(block_size: int, n: int):
    if block_size * 8 >= n.bit_length():
        raise ValueError("Block size too large for RSA modulus")

def pad_message(message: bytes, block_size: int) -> bytes:
    # PKCS-style padding
    # NOTE can fail if the padding exceeds 255 (one byte)
    padding_len = block_size - (len(message) % block_size)
    return message + bytes([padding_len] *  padding_len) # adds n number n numbers at the end of the message 


def unpad_message(message: bytes) -> bytes:
    padding_len = message[-1]
    return message[:-padding_len]

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


def rsa_encrypt_block(m: int, e: int, n: int) -> int:
    if m >= n:
        raise ValueError("Block too large for modulus")
    return pow(m, e, n)

def rsa_decrypt_block(c: int, d: int, n: int) -> int:
    return pow(c, d, n)