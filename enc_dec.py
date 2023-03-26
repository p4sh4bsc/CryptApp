import pyAesCrypt
import argparse


arg = argparse.ArgumentParser(description='encrypt and decrypt')

arg.add_argument('-e', '--encrypt', type=str, help='Указать путь до фала для шифровки')
arg.add_argument('-d', '--decrypt', type=str, help='Указать путь до фала для дешифровки')
arg.add_argument('-p', '--password', type=str, help='Указать пароль для шифровки/дешифровки')

param = arg.parse_args()




def encrypt(file_for_encrypt, output_file, password):
    pyAesCrypt.encryptFile(file_for_encrypt, output_file+".aes", password)

def decrypt(file_for_decrypt, output_file, password):
    pyAesCrypt.decryptFile(file_for_decrypt, output_file, password)
    
    

if __name__ == "__main__":

    if param.decrypt == None and  param.encrypt == None and param.password == None:
        print("Вы не указали, что нужно сделать с файлом")
        print("enc_dec.py -h")
    
        
    elif param.decrypt == None and  param.encrypt == None:
        print("Вы не указали, что нужно сделать с файлом")
        print("enc_dec.py -h")
        
    elif param.password == None:
        print('Пароль не указан')
    
    elif param.decrypt == None:
        encrypt(param.encrypt, param.encrypt, param.password)
        print("encrypt done")
        
    elif param.encrypt == None:
        decrypt(param.decrypt, param.decrypt[0:-4], param.password)
        print("decrypt done")
        
    else:
        print("debug")
    
