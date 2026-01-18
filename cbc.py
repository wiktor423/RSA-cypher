"""
- make the encryption work on binary/hexadecimal representation of the data,
such that any data type can be segmented and subbmitted to the algorithm
- prioritize using numpy, wherever possible
- make sure to use prime, large numbers for key generation
- "ciphering blocks"
- what is the initialisation vector? it is public
- XOR
"""

# KEYGEN
from Crypto.Util import number

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

print(keygen(10))
print(keygen(10))