# CryptApp

This script is able to encrypt/decrypt files with asynchronous/synchronous (RSA/AES) encryption algorithm.

# Usage
```
usage: main.py [-h] [-f FILE] [-p PASSWORD] [-e [ENCRYPT]] [-d [DECRYPT]] [--aes [AES]] [--rsa [RSA]]

encrypt and decrypt

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  set path to the file for encrypt/decrypt
  -p PASSWORD, --password PASSWORD set password for AES algorithm
  -e [ENCRYPT], --encrypt [ENCRYPT] set this param to encrypt file
  -d [DECRYPT], --decrypt [DECRYPT] set this param to decrypt file
  --aes [AES]           encrypt/decrypt by AES
  --rsa [RSA]           encrypt/decrypt by RSA
  ```