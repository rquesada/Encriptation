# Cryptography
Secret-key encryption, one-way hash, public-key cryptography, digital signature, PKI, TLS, cryptocurrency and blockchain

## Secret-key encryption
### DES
Data Encryption Standard and outdated symmetric-key algorithm, it is not recommended for use due to its short key length.
#### Generarate a DES key:
The following command generates a DES key using the password "mysecretpassword" and saves it to file "des-key.txt".

`openssl des3 -out des-key.txt -pass pass:mysecretpassword -rand /dev/urandom 8`

#### Encrypt a message:
This command encrypts the content of "plaintext.txt" using DES key from "des-key.txt" and saves the encrypted data to "ciphertext.des"

```
echo "Hello, DES!" > plaintext.txt
openssl des3 -in plaintext.txt -out ciphertext.des -pass file:des-key.txt -e
```
#### Decrypt the message:
This command decrypts the content of ciphertext.des using the same DES key and saves the decrypted data to decrypted.txt.

```
openssl des3 -in ciphertext.des -out decrypted.txt -pass file:des-key.txt -d
```

#### Verify the result:
This command prints the decrypted content to the terminal. It should be the same as the original message: "Hello, DES!"

```
cat decrypted.txt
```

### AES
Advanced Encryption Standard is a widely used symmetric-key encriptation algorithm. Example:

#### Generate an AES key and Initialization Vector (IV):
This command generates a random AES key and IV based on the provided password ("mysecretpassword"). Note that the -P flag is used to print the generated key and IV.

```
openssl enc -aes-256-cbc -k mysecretpassword -P -md sha256 -nosalt
```

#### Encrypt a message:
Replace your-iv-here with the IV generated in step 1. This command encrypts the content of plaintext.txt using AES-256 in CBC mode and saves the encrypted data to ciphertext.aes.

```
echo "Hello, AES!" > plaintext.txt
openssl enc -aes-256-cbc -in plaintext.txt -out ciphertext.aes -k mysecretpassword -iv your-iv-here -nosalt
```

#### Decrypt the message:
Again, replace your-iv-here with the IV generated in step 1. This command decrypts the content of ciphertext.aes using the same AES key and IV and saves the decrypted data to decrypted.txt.

```
openssl enc -aes-256-cbc -in ciphertext.aes -out decrypted.txt -k mysecretpassword -iv your-iv-here -d -nosalt
```

#### Verify the results:
Prints the decrypted content to the terminal. It should be the same as the original message: "Hello, AES!"

```
cat decrypted.txt
```

### Authenticated Encryption Mode: GCM
Authenticated Encryption with Associated Data (AEAD) is a mode of operation for symmetric-key encryption algorithms that simultaneously provides confidentiality, integrity, and authenticity assurances for the encrypted data. Galois/Counter Mode (GCM) is one such AEAD mode that is widely used, especially in the context of AES.
Example:

#### Generate an AES-GCM key and Initialization Vector (IV):
This generates a 256-bit key and a 96-bit IV for AES-GCM and saves them to aes-gcm-key.txt and aes-gcm-iv.txt, respectively.
```
openssl rand -hex 32 > aes-gcm-key.txt
openssl rand -hex 12 > aes-gcm-iv.txt
```

#### Encrypt a message:
This command encrypts the content of plaintext.txt using AES-256 in GCM mode and saves the encrypted data to ciphertext.gcm. The -iv option specifies the IV, and the key is provided through the -pass option.
```
echo "Hello, AES-GCM!" > plaintext.txt
openssl enc -aes-256-gcm -in plaintext.txt -out ciphertext.gcm -pass file:aes-gcm-key.txt -iv $(cat aes-gcm-iv.txt) -nosalt
```

#### Decrypt the message:
This command decrypts the content of ciphertext.gcm using the same AES-GCM key and IV and saves the decrypted data to decrypted.txt.
```
openssl enc -aes-256-gcm -in ciphertext.gcm -out decrypted.txt -pass file:aes-gcm-key.txt -iv $(cat aes-gcm-iv.txt) -d -nosalt
```

#### Verify the results:
This command prints the decrypted content to the terminal. It should be the same as the original message: "Hello, AES-GCM!"
```
cat decrypted.txt
```

## One-way hash
A one-way hash function is a mathematical function that takes an input (or "message") and produces a fixed-size string of characters, which is typically a hash value or hash code. The key characteristic of a one-way hash function is that it should be computationally infeasible to reverse the process, meaning it should be difficult to derive the original input from the hash value.

Commonly used one-way hash functions include MD5 (Message Digest Algorithm 5), SHA-1 (Secure Hash Algorithm 1), SHA-256, SHA-3, and others. However, MD5 and SHA-1 are considered insecure for cryptographic purposes due to vulnerabilities, and it's recommended to use stronger hash functions like SHA-256 or SHA-3 in modern applications.

### MD5
Remember that MD5 is considered insecure for cryptographic purposes due to vulnerabilities, and it's not recommended for security-sensitive applications. For cryptographic use cases, consider using stronger hash functions such as SHA-256 or SHA-3. MD5 is still commonly used for non-security-critical purposes like checksums, but for security, it's essential to choose stronger alternatives.

#### Calculate MD5 Hash with OpenSSL:
This command hashes the string "Hello, MD5!" using the MD5 algorithm. The -n flag is used to suppress the trailing newline character in the input string.

`echo -n "Hello, MD5!" | openssl md5`

The output will be the MD5 hash value, represented as a 32-character hexadecimal string. For example:
`7d0b7808072d458f333d02f1a56f3752`


### SHA
Secure Hash Algorithm, refers to a family of cryptographic hash functions designed by the National Security Agency (NSA) and published by the National Institute of Standards and Technology (NIST) in the United States. The SHA family includes several hash functions, each denoted by its bit-length, such as SHA-1, SHA-256, SHA-384, SHA-512, and more.
Hash Function:

A hash function takes an input (or message) of arbitrary size and produces a fixed-size string of characters, which is the hash value or digest. The key properties of a cryptographic hash function include collision resistance, preimage resistance, and second preimage resistance.

#### SHA-1 (160 bits):
SHA-1 was once widely used for various security applications, including digital signatures and certificates. However, vulnerabilities were discovered over time, and it is now considered insecure for cryptographic purposes.

#### SHA-256 (256 bits), SHA-384 (384 bits), SHA-512 (512 bits):
These are part of the SHA-2 family, which is currently considered secure for most cryptographic applications. SHA-256 is widely used and provides a 256-bit hash value, while SHA-384 and SHA-512 offer longer hash lengths.

#### SHA-3:
SHA-3 is the latest member of the SHA family, designed to provide an alternative to SHA-2. It was selected through a public competition and uses a different internal structure based on the Keccak sponge construction.

#### Common Uses:

Data Integrity: Hash functions are used to ensure the integrity of data. If the hash values of two sets of data match, it is highly likely that the data is the same.
Digital Signatures: Hash functions are a crucial component of digital signatures, where a private key signs the hash value of a message to prove its origin and integrity.
Password Storage: Hash functions are used to securely store passwords by hashing them and storing the hash values. Salting is often used for added security.

#### Example
##### Calculate SHA-256 Hash with OpenSSL:
`echo -n "Hello, SHA-256!" | openssl sha256`
This command hashes the string "Hello, SHA-256!" using the SHA-256 algorithm. The -n flag is used to suppress the trailing newline character in the input string.

The output will be the SHA-256 hash value, represented as a 64-character hexadecimal string. For example:
`80a8e652c7c56a7b9928ff2e89f90b156890c7908e6d00830bfeea4006e705a2`

## Public-key cryptography

## Digital signature

## PKI

## TLS

## Cryptocurrency

## Blockchain
