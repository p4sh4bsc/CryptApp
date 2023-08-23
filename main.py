import pyAesCrypt
import argparse
import rsa
import os


##############################################################################################
arg = argparse.ArgumentParser(description='encrypt and decrypt')

arg.add_argument('-f', '--file', type=str, help='set path to the file for encrypt/decrypt')
arg.add_argument('-p', '--password', type=str, help='set password for AES algorithm')
arg.add_argument('-e', '--encrypt', type=bool, const=True, default=False, nargs='?', help='set this param to encrypt file')
arg.add_argument('-d', '--decrypt', type=bool, const=True, default=False, nargs='?', help='set this param to decrypt file')
arg.add_argument('--aes', type=bool, const=True, default=False, nargs='?', help='encrypt/decrypt by AES')
arg.add_argument('--rsa', type=bool, const=True, default=False, nargs='?', help='encrypt/decrypt by RSA')

param = arg.parse_args()
##############################################################################################



def encrypt_aes(file_for_encrypt, password):
    pyAesCrypt.encryptFile(file_for_encrypt, file_for_encrypt+".aes", password)
    print(f"[+] {file_for_encrypt} encrypted by AES")

def decrypt_aes(file_for_decrypt, password):
    pyAesCrypt.decryptFile(file_for_decrypt, file_for_decrypt[:-4], password)
    print(f'[+] {file_for_decrypt} decrypted by AES')

def encrypt_rsa(file_for_encrypt):
    (pubkey, privkey) = rsa.newkeys(1024)

    with open('keys/pub_key.pem', 'wb') as p:
        p.write(pubkey.save_pkcs1('PEM'))
    with open('keys/priv_key.pem', 'wb') as p:
        p.write(privkey.save_pkcs1('PEM'))
    with open(file_for_encrypt, 'rb') as enc_file:
        data_enc = enc_file.read()

    if os.path.isfile('keys/pub_key.pem'):
        public_rsa = rsa.encrypt(data_enc, pubkey)

        with open(f'{file_for_encrypt}.bin', 'wb') as file_out:
            file_out.write(public_rsa)
        print(f"[+] {file_for_encrypt} encrypted by RSA")
    else:
        print("[+] Can't find pub_key")

def decrypt_rsa(file_for_decrypt):
    with open('keys/pub_key.pem', 'rb') as p:
        pubkey = rsa.PublicKey.load_pkcs1(p.read())
    with open('keys/priv_key.pem', 'rb') as p:
        privkey = rsa.PrivateKey.load_pkcs1(p.read())
    with open(file_for_decrypt, 'rb') as enc_file:
        data_enc = enc_file.read()

    if os.path.isfile('keys/priv_key.pem'):
        decrypted_data = rsa.decrypt(data_enc, privkey)

        with open(file_for_decrypt[:-4], 'wb') as file_out:
            file_out.write(decrypted_data)
        print(f'[+] {file_for_decrypt} decrypted by RSA')
    else:
        print("[+] Can't find priv_key")
    
    


if __name__ == "__main__":
    if os.path.isfile(param.file):
        try:
            if param.decrypt == None and  param.encrypt == None:
                print("[+] Please, set -d or -e param")
                print("enc_dec.py -h")
                
            elif param.password == None and param.aes:
                print('[+] Please, set -p param')
                print("enc_dec.py -h")
            
            elif param.encrypt and param.aes:
                encrypt_aes(param.file, param.password)
                
            elif param.decrypt and param.aes:
                decrypt_aes(param.file, param.password)
            
            elif param.encrypt and param.rsa:
                encrypt_rsa(param.file)

            elif param.decrypt and param.rsa:
                decrypt_rsa(param.file)

            else:
                print("Error")
                print("enc_dec.py -h")
        except Exception as ex:
            print(ex)
            print("enc_dec.py -h")
    else:
        print(f"[+] Can't find {param.file}")

        
