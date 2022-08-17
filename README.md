# Hack The Box (HTB) - Log Modulus Attack Walkthrough

This is a walkthrough and explanation of the [Lost Modulus](
https://app.hackthebox.com/challenges/lost-modulus) challenge on Hack The Box.

## Overview

We are provided 2 files in this challenge; [output.txt](output.txt):

```bash
$> cat output.txt
Flag: 148d328b543aa2ede5d5970c5236af3c13ca9c520a2f53fbeceae9530a35c0b6cedff1fd86c44154c05d75d418e13dea251f77
```

NOTE: The flag has been changed for this walkthrough so as not to publish the
actual flag. To get the real flag download the challenge files from
[Hack the Box](hackthebox.com).

and [challenge.py](challenge.py):

```python
#!/usr/bin/python3
from Crypto.Util.number import getPrime, long_to_bytes, inverse
flag = open('flag.txt', 'r').read().strip().encode()

class RSA:
    def __init__(self):
        self.p = getPrime(512)
        self.q = getPrime(512)
        self.e = 3
        self.n = self.p * self.q
        self.d = inverse(self.e, (self.p-1)*(self.q-1))
    def encrypt(self, data: bytes) -> bytes:
        pt = int(data.hex(), 16)
        ct = pow(pt, self.e, self.n)
        return long_to_bytes(ct)
    def decrypt(self, data: bytes) -> bytes:
        ct = int(data.hex(), 16)
        pt = pow(ct, self.d, self.n)
        return long_to_bytes(pt)

def main():
    crypto = RSA()
    print ('Flag:', crypto.encrypt(flag).hex())

if __name__ == '__main__':
    main()
```

In this example code the public and private components aren't saved and the only
output is an encrypted message. There's also a small bit-size to the key which
may be exploited in a factorization attack but CTF challenges RARELY result to
large keyspace brute force attacks.

## Vulnerability

If one looks at the parameters one can see that e is a small value; 3. This
isn't inherently unsafe but we can assume the key size itself except we are
also not padding the message we are encrypting. This means by taking the e-th
root of the ciphertext may reveal the plaintext. This vulnerability is tracked
under the Common Weakness Enumeration
[CWE-780](https://cwe.mitre.org/data/definitions/780.html).

## Exploit

This seems like an easy win, however taking the n-th root of an integer
function is not straightforward. One could try:

```python
from Crypto.Util.number import getPrime, long_to_bytes, inverse
print(long_to_bytes(int(bytes_to_long(ct)**(1/3))))

b'not_tg\xc4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

But due to the rounding and truncation that happens in the above operation you
don't get the decrypted flag. Instead of doing float/int conversions, let's
instead get a function designed to do nth root operations on large integers. I
found the below implementation on
[RIPTutorial](
https://riptutorial.com/python/example/8751/computing-large-integer-roots).

```python
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
```

Using the above function we can then take the e-th root of the ciphertext and
we get the plaintext flag:

```python
ct = bytes.fromhex("148d328b543aa2ede5d5970c5236af3c13ca9c520a2f53fbeceae9530a35c0b6cedff1fd86c44154c05d75d418e13dea251f77")
e = 3 # From line 9 of challenge.py
print(long_to_bytes(nth_root(bytes_to_long(ct), e)))

b'not_the_real_flag'
```

Full solution is available in the [solution.py](solution.py) file included in
this walkthrough. Be sure to run `pip install -r requirements.txt` to install
the pycryptodome version used in this solution example.

## Fixing the Vulnerability

There are several things wrong with this implementation:

- Using non-standard implementations [CWE-327](
  https://cwe.mitre.org/data/definitions/327.html)
  - NEVER ROLL YOUR OWN RSA UNLESS YOU KNOW WHAT YOU'RE DOING
- Small key size [CWE-326](https://cwe.mitre.org/data/definitions/326.html)
  - Per the National Security Agency (NSA) and its [Commercial National Security
    Algorithm (CNSA) Suite](
    https://apps.nsa.gov/iaarchive/prograams/iad-initiatives/cnsa-suite.cfm),
    the minimum key-length that is recommended is 3072 bits.
- Not padding the message before encrypting

A correct implementation using the [PKCS1_OAEP](
https://pycryptodome.readthedocs.io/en/latest/src/cipher/oaep.html) module
in the [PyCryptodome suite](
https://pycryptodome.readthedocs.io/en/latest/index.html) has been provided
as secure implementation counter-example to the insecure RSA implementation
demonstrated by the challenge in the [challenge_secure.py](challenge_secure.py)
file provided in this write-up.
