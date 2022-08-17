from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long

e = 3

def get_rsa_private_key():
    return RSA.generate(3072, e=e)

def encrypt(pt, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(bytes(pt, encoding="UTF-8"))
    return ciphertext.hex()


def decrypt(ct, private_key):
    ciphertext = bytes.fromhex(ct)
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)


key = get_rsa_private_key()
ciphertext = encrypt(open('flag.txt', 'r').read(), key.publickey())
print(f"Flag: {ciphertext}")
decrypted_plaintext = decrypt(ciphertext, key)
print(f"Decrypted Flag: {str(decrypted_plaintext, encoding='UTF-8')}")


# Taken from https://riptutorial.com/python/example/8751/computing-large-integer-roots
def nth_root(x, n):
    # Start with some reasonable bounds around the nth root.
    upper_bound = 1
    while upper_bound ** n <= x:
        upper_bound *= 2
    lower_bound = upper_bound // 2
    # Keep searching for a better result as long as the bounds make sense.
    while lower_bound < upper_bound:
        mid = (lower_bound + upper_bound) // 2
        mid_nth = mid ** n
        if lower_bound < mid and mid_nth < x:
            lower_bound = mid
        elif upper_bound > mid and mid_nth > x:
            upper_bound = mid
        else:
            # Found perfect nth root.
            return mid
    return mid + 1

print("Now attempting the attack used before by taking the 3rd root of the "
      "ciphertext...")
ct = bytes.fromhex(ciphertext)
print(long_to_bytes(nth_root(bytes_to_long(ct), e)))
print("With a secure key length and use of OAEP padding, the attack fails.")