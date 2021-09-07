# Password-Based_Encryption

A small implementation of a password-based encryption using the Java Cryptography Extension (JCE) where you add salt, iterate and hashed repeatedly. This exercise follows the NIST recommendation of using Password-based Key Deviation Function 2 (PBKDF2).

Note: Secret key generated is printed as a base64 for marking purpose of this exercise.

# How to run program

You first need a plain text file `plaintext.txt` which contains text you wish to be encrypted and your chosen password.

Then, run command in terminal below to encrypt file with your chosen password

```
% cd ../yourfiledirectory/FileEncryptor.java
% java FileEncryptor enc "my password" plaintext.txt ciphertext.enc
```
This encrypts `plaintext.txt` into `ciphertext.enc`. This encryption file derives a secret key generated from chosen password.

```
% java FileEncryptor dec "my password" ciphertext.enc plaintext.txt
```

This will decrypt `ciphertext.enc` as `plaintext.txt` from the secret key.
