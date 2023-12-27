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
Public-key cryptography, also known as asymmetric cryptography, is a cryptographic system that uses pairs of keys: public keys and private keys.

#### How public-key cryptography works:
##### Key Pair Generation:
Users generate a pair of mathematically related keys: a public key and a private key. These keys are typically very large prime numbers

##### Public Key Distribution: 
The public key is shared openly and can be distributed widely. It is used to encrypt messages or data.

##### Private Key Protection
The private key is kept secret and should only be known to the owner. It is used for decrypting messages or data that were encrypted with the corresponding public key.

##### Encryption: 
If User A wants to send a secure message to User B, User A will use User B's public key to encrypt the message. Once encrypted, only User B, who possesses the corresponding private key, can decrypt and access the original message.

##### Decryption: 
User B uses their private key to decrypt the message that was encrypted with their public key. Since the private key is kept secret, only User B can decrypt the message.

##### Digital Signatures:
Public-key cryptography is also used for digital signatures. If User A wants to sign a message to prove its authenticity, they can use their private key to create a digital signature. Anyone with User A's public key can verify that the signature is valid, ensuring the message has not been tampered with and is indeed from User A

#### RSA:
The RSA algorithm is a widely used public-key cryptosystem that enables secure data transmission and digital signatures. It was introduced in 1977 by Ron Rivest, Adi Shamir, and Leonard Adleman—hence the name RSA. The algorithm is based on the mathematical properties of large prime numbers.
The security of RSA is based on the difficulty of factoring the product of two large prime numbers into its prime factors.
RSA is widely used for secure communication, digital signatures, and key exchange in various applications such as SSL/TLS for secure web browsing, PGP for email encryption, and more.

##### Example:
Below is a basic example demonstrating how to generate RSA key pairs, encrypt and decrypt a message using OpenSSL

###### Step 1: Generate RSA Key Pair
This will create two files: private_key.pem (containing the private key) and public_key.pem (containing the public key).
```
# Generate a private key
openssl genpkey -algorithm RSA -out private_key.pem

# Derive the corresponding public key from the private key
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

###### Step 2: Encrypt a Message
This will create a binary file (encrypted_message.bin) containing the encrypted message.
```
# Message to be encrypted
echo "Hello, RSA!" > message.txt

# Encrypt the message using the recipient's public key
openssl rsautl -encrypt -pubin -inkey public_key.pem -in message.txt -out encrypted_message.bin
```

###### Step 3: Decrypt the Message
This will decrypt the message and store it in decrypted_message.txt.
```
# Decrypt the message using the recipient's private key
openssl rsautl -decrypt -inkey private_key.pem -in encrypted_message.bin -out decrypted_message.txt
```

## Public Key Infraestructure
Public Key Infrastructure (PKI) is a comprehensive system that manages the creation, distribution, storage, and revocation of digital keys and certificates. It provides a framework for secure communication and authentication over a network, typically the internet. PKI relies on the use of asymmetric cryptography, where users have a pair of public and private keys.

### Here are key components and concepts associated with Public Key Infrastructure:
#### Certificate Authority (CA)
The Certificate Authority is a trusted entity responsible for issuing digital certificates. These certificates bind public keys to individuals, devices, or services. The CA verifies the identity of the entity requesting a certificate before issuance.

#### Digital Certificates
A digital certificate is a cryptographic key pair, consisting of a public key and its associated private key. The certificate is digitally signed by the CA, providing a means for others to verify the authenticity of the public key.

#### Registration Authority (RA)
The Registration Authority is responsible for authenticating users before a digital certificate is issued by the CA. In some systems, the roles of the CA and RA are performed by the same entity.

#### Public and Private Keys
CRLs are lists maintained by the CA that contain information about revoked certificates. Clients can check these lists to ensure that a certificate has not been compromised or revoked.

#### Certificate Revocation Lists (CRLs)
PKI can operate under different trust models, including hierarchical, mesh, and hybrid models. In a hierarchical model, a root CA issues certificates to subordinate CAs, creating a chain of trust. In a mesh model, peers trust each other's public keys directly.

#### Public Key Infrastructure Trust Models
PKI is extensively used in SSL/TLS protocols for securing communication over the web. Web browsers use digital certificates to authenticate the identity of websites and establish secure connections.

#### Secure Sockets Layer/Transport Layer Security (SSL/TLS)
PKI is extensively used in SSL/TLS protocols for securing communication over the web. Web browsers use digital certificates to authenticate the identity of websites and establish secure connections.

#### Key Management
Proper key management is crucial in PKI. This includes secure generation, storage, and disposal of keys. Hardware Security Modules (HSMs) are often used to enhance key security.

PKI plays a fundamental role in securing various online activities, including e-commerce transactions, email communication (S/MIME), and virtual private networks (VPNs). It establishes a framework for trustworthy and secure communication by leveraging the principles of asymmetric cryptography and the binding of public keys to verified identities through digital certificates.

## Transport Layer Security
Transport Layer Security (TLS) is a cryptographic protocol designed to secure communication over a computer network. It is the successor to the earlier Secure Sockets Layer (SSL) protocol and is commonly used to secure data transmission over the internet. TLS ensures the privacy and integrity of data exchanged between clients and servers by encrypting the communication.
Here are key aspects of TLS:

### Encryption and Security
TLS provides a secure channel by encrypting the data exchanged between the client and server. This encryption ensures that even if the communication is intercepted, the data remains confidential. It uses symmetric key cryptography for data encryption and asymmetric key cryptography for key exchange and authentication.

### Handshake Protocol
The TLS handshake protocol is used to establish a secure connection between the client and server. During the handshake, the parties negotiate the cryptographic algorithms, exchange cryptographic keys, and authenticate each other's identities. The handshake protocol helps ensure the integrity and security of the subsequent data transmission.

### Versions
There are different versions of TLS, including TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3, and more. It's important for both clients and servers to support modern and secure versions to ensure the highest level of security.

### Cryptographic Algorithms
TLS supports various cryptographic algorithms for key exchange, encryption, and authentication. The choice of algorithms is negotiated during the handshake. Common algorithms include RSA, Diffie-Hellman key exchange, and Elliptic Curve Cryptography (ECC).

### Certificates
TLS relies on digital certificates issued by Certificate Authorities (CAs) to authenticate the identity of the server. These certificates are used during the handshake process to establish trust between the client and server.

### Perfect Forward Secrecy (PFS)
TLS supports Perfect Forward Secrecy, which ensures that even if a long-term key is compromised, past communications remain secure. This is achieved by generating unique session keys for each session, making it more challenging for an attacker to decrypt past communications.

### Application Layer Protocols
TLS is often used to secure application layer protocols, such as HTTPS (HTTP over TLS), SMTP (Secure SMTP), and IMAPS (Secure IMAP), among others. It can be integrated with various applications to provide a secure communication layer.

### TLS 1.3 Improvements
TLS 1.3 is the latest version, offering improved security and performance. It reduces the number of round trips required for the handshake, supports modern cryptographic algorithms, and enhances security features.

## Blockchain
Blockchain is the underlying technology that powers Bitcoin and many other cryptocurrencies. It is a distributed and decentralized ledger that records transactions across a network of computers in a secure and transparent manner.

Key characteristics of blockchain:

### Decentralization
Blockchain operates on a decentralized network of nodes, and no single entity has control over the entire network. This decentralization enhances security, reduces the risk of fraud, and eliminates the need for intermediaries.

### Consensus Mechanism
Consensus mechanisms are protocols that ensure all nodes in the network agree on the validity of transactions. Bitcoin uses Proof of Work (PoW), where miners compete to solve mathematical problems to add new blocks. Other consensus mechanisms include Proof of Stake (PoS) and Delegated Proof of Stake (DPoS).

### Immutability
Once a block is added to the blockchain, it is extremely difficult to alter or remove. The immutability of the blockchain ensures the integrity of the recorded transactions.

### Smart Contracts
Smart contracts are self-executing contracts with the terms of the agreement directly written into code. They automatically execute and enforce the terms when predefined conditions are met. Ethereum is a blockchain platform that is well-known for its support of smart contracts.

### Transparency
All transactions on the blockchain are visible to participants in the network. This transparency helps prevent fraud and provides a verifiable record of transactions.

### Use Cases Beyond Cryptocurrencies
While blockchain technology originated with cryptocurrencies, its applications extend beyond finance. Industries such as supply chain management, healthcare, voting systems, and more are exploring the use of blockchain for its transparency, security, and efficiency.

Bitcoin and blockchain are intertwined, with Bitcoin being the first and most well-known application of blockchain technology. The success of Bitcoin has sparked interest in the broader potential of blockchain, leading to its exploration and adoption in various industries.
 
## Bitcoin
Bitcoin is a decentralized digital currency that operates on a peer-to-peer network. It was introduced in 2009 by an unknown person or group of people using the pseudonym Satoshi Nakamoto. Bitcoin is often referred to as a cryptocurrency because it relies on cryptographic techniques to secure transactions, control the creation of new units, and verify the transfer of assets.
Key features of Bitcoin

### Decentralization
Bitcoin operates on a decentralized network of computers, known as nodes, which collectively maintain a public ledger called the blockchain. This eliminates the need for a central authority, such as a government or financial institution, to control the currency.

### Blockchain
The blockchain is a distributed and immutable ledger that records all Bitcoin transactions. It consists of blocks, each containing a list of transactions. Once a block is added to the blockchain, it cannot be altered retroactively, ensuring transparency and security.

### Mining
Bitcoin mining is the process by which new bitcoins are created and transactions are added to the blockchain. Miners use powerful computers to solve complex mathematical problems, and the first one to solve the problem gets the right to add a new block to the blockchain and is rewarded with newly created bitcoins.

### Limited Supply
Bitcoin has a capped supply of 21 million coins. This scarcity is built into the protocol to mimic the scarcity of precious metals like gold. The controlled supply is intended to prevent inflation over time.

### Anonymity and Pseudonymity
While transactions on the Bitcoin network are transparent and recorded on the blockchain, users are identified by cryptographic addresses rather than personal information. This provides a degree of pseudonymity, although it's not completely anonymous.
