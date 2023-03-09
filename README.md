# 🔑 Simple File Encryptor

Encrypts/Decrypts files/directories based on user provided password with AES256
(Aes256GcmSiv, encryption key is derived from password + 96bit random salt with SHA3)

## 🔧 Usage

To find out usage run with the flag `-h`.
Execution will guide through necessary steps if run without parameters/flags.

A precompiled executable for 64Bit-Windows clients is located in `release/simple-encryptor.exe`

## ⚠️ Warning

Files that already exist in the decryption location will be overwritten.

I.e. Suppose file `./plaintext/file.txt` is 
encrypted to `./ciphertext/encrypted`, subsequent decryption of this file to the target-directory `./plaintext/`will 
overwrite the file `./plaintext/file.txt` files without warning!

This issue can be prevented simply by decrypting to any directory other than the plaintext files are located.
