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


## Public-key cryptography

## Digital signature

## PKI

## TLS

## Cryptocurrency

## Blockchain
