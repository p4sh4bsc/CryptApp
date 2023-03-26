import pyAesCrypt
import argparse
from PyPDF2 import *


##############################################################################################
arg = argparse.ArgumentParser(description='encrypt and decrypt')

arg.add_argument('-f', '--file', type=str, help='Указать путь до фала для шифровки/дешифровки')
arg.add_argument('-p', '--password', type=str, help='Указать пароль для шифровки/дешифровки')
arg.add_argument('-e', '--encrypt', type=bool, const=True, default=False, nargs='?', help='Шифровать файл')
arg.add_argument('-d', '--decrypt', type=bool, const=True, default=False, nargs='?', help='Дешифровать файл')
arg.add_argument('--pdf', type=bool, const=True, default=False, nargs='?', help='Шифрованка pdf файла')
arg.add_argument('--aes', type=bool, const=True, default=False, nargs='?', help='Шифровка методом Aes (укажите -e или -d)')


param = arg.parse_args()
##############################################################################################




def encrypt_pdf(file_for_encrypt, output_file, password):
    pdf = PdfReader(file_for_encrypt)

    output_pdf = PdfWriter()
    for page in range(len(pdf.pages)):
        output_pdf.add_page(pdf.pages[page])
        
    output_pdf.encrypt(password)
    
    with open('protected_' + output_file, 'wb') as file:
        output_pdf.write(file)

def encrypt(file_for_encrypt, output_file, password):
    pyAesCrypt.encryptFile(file_for_encrypt, output_file+".aes", password)

def decrypt(file_for_decrypt, output_file, password):
    pyAesCrypt.decryptFile(file_for_decrypt, output_file, password)
    


if __name__ == "__main__":

    try:
        if param.decrypt == None and  param.encrypt == None:
            print("Вы не указали, что нужно сделать с файлом")
            print("enc_dec.py -h")
            
        elif param.password == None:
            print('Пароль не указан')
            print("enc_dec.py -h")
        
        elif param.encrypt == True and param.aes == True:
            encrypt(param.file, param.file, param.password)
            print("encrypt done")
            
        elif param.decrypt == True and param.aes == True:
            decrypt(param.file, param.file[0:-4], param.password)
            print("decrypt done")
            
        elif param.pdf == True:
            encrypt_pdf(param.file, param.file, param.password)
            print("encrypt pdf done")

        else:
            print("Error")
            print("enc_dec.py -h")
    except Exception as ex:
        print(ex)
        print("enc_dec.py -h")
            

    
