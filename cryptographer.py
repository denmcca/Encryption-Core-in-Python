# -*- coding: utf-8 -*-
"""
Created on Tue Oct 17 13:47:20 2017

@author: Dennis
"""
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as apadding

path_output = './output/'
path_keys = '/keys/'
image_file_name = 'image.jpeg'
encrypted_file_name = 'encrypted'
decrypted_file_name = 'decrypted'
rsa_encrypted_file_name = 'rsa_encrypted'
rsa_decrypted_file_name = 'rsa_decrypted'
private_key_file_name = 'private_key'
public_key_file_name = 'public_key'
key_ext = '.pem'
key_size = 32
iv_size = 16
padding_size = 128

key = os.urandom(key_size)

#----------------------Key Generation------------------------
def genKeys(filepath_to_pem_file):
    with open(filepath_to_pem_file, 'rb') as pem:
        private_key = serialization.load_pem_private_key(
                pem.read(),
                password = None,
                backend = default_backend())
        
    pem = private_key.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.PKCS8,
        encryption_algorithm = serialization.NoEncryption()
    )
    
    with open(private_key_file_name + key_ext, 'w') as f:
        f.write(pem.decode())
        
    public_key = private_key.public_key()
    
    pem = public_key.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    )
        
    with open(public_key_file_name + key_ext, 'w') as f:
        f.write(pem.decode())
        
    return
#-----------------------Key Generation----------------------
    
def GetPrivateKey(private_key_filepath):
    with open(private_key_filepath, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password = None,
            backend = default_backend()
        )
    return private_key

def GetPublicKey(public_key_filepath):
    with open(public_key_filepath, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend = default_backend()
        )
    return public_key

#-----------------------------Mycrypt-----------------------
def Myencrypt(message, key) : #constrain: bytes message   
    #confirming key length is at least 32 bytes
    if len(key) < key_size:
        print("Error: Key is {} bytes. 32-byte (256-bits) or greater key required.".format(len(key)))
        return None, None;
    
    #confirming message is a bytes object    
    if not isinstance(message, bytes): #message must be bytes
        message = bytes(message, 'utf-8')

    #setting initialization vector
    iv = os.urandom(iv_size)

    #setting Cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend()) #why use equal sign?
    encryptor = cipher.encryptor() #encryptor mode turned on  
    
    #setting padding object and setting as padder
    padder = padding.PKCS7(padding_size).padder()
    
    #encrypting blocks and padded block
    return encryptor.update(padder.update(message) + padder.finalize()), iv

def Mydecrypt(c_message, key, iv):   
    #confirming key length is at least 32 bytes
    if len(key) < key_size:
        print("Error: Key is {} bytes. 32-byte (256-bit) key required.".format(len(key)))
        return None, None
    
#    print("test0: {}".format(c_message))
    
    #confirming that c_message is a bytes object
    if not isinstance(c_message, bytes):
        c_message = bytes(c_message, 'utf-8')
    
#    print("test1: {}".format(c_message))
    
    
    #setting Cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    #configuring cipher to decrypt
    decryptor = cipher.decryptor()

    #configuring padder
    padder = padding.PKCS7(padding_size).unpadder()
    
    deciphered_text = decryptor.update(c_message)
    unpadded_text = padder.update(deciphered_text)
#    print('unpadded_text: {}'.format(unpadded_text))
    end_text = padder.finalize()
#    print('unpadded_text + padder.finalize(): {}'.format(unpadded_text), end_text)
    
    #padder.update is decrypted message, padder.finalize removes padding from padded block
    return unpadded_text + end_text
#-----------------------------/Mycrypt-----------------------
#-----------------------------Myfile-----------------------   
def MyfileEncrypt(decrypted_filepath):
    #generating 32 byte key
    key = os.urandom(key_size) #must be inside this function

    #splitting filepath into filename and ext
    filename, ext = os.path.splitext(decrypted_filepath)

    #opening file to encrypt
    with open(decrypted_filepath, 'rb') as f:
        data = f.read()        
        ciphertext, iv = Myencrypt(data, key)
    
    with open(path_output + encrypted_file_name + ext, 'wb') as f:
        f.write(ciphertext)
    
#    4.	Return:
#        a.	cipher C
#        b.	IV
#        c.	key
#        d.	extension of the file (as a string).
    return ciphertext, iv, key, ext

def MyfileDecrypt(ciphertext, iv, key, ext): #key is wrapped 
    #splitting file name and extension
#    filename, ext = os.path.splitext(encrypted_file_path)
    
    #opening file using filepath to get iv and encrypted message
#    with open( + ext, 'rb') as f:
#        iv = f.read(iv_size)
#        data = f.read()
    
    #sending encrypted data and iv to be decrypted
    decrypted_message = Mydecrypt(ciphertext, key, iv) #where does key come from?   
    path_to_decrypted_file = path_output + decrypted_file_name + ext
    
    with open(path_to_decrypted_file, 'wb') as f:
        f.write(decrypted_message)
            
    return path_to_decrypted_file
#-----------------------------Myfile-----------------------
#-----------------------------MyRSA-----------------------
def MyRSAEncrypt(filepath, RSA_Publickey_filepath):
    #sending plaintext data to be encrypted
    C, IV, key, ext = MyfileEncrypt(filepath)
        
    publickey = GetPublicKey(RSA_Publickey_filepath) #using self public key to test decryption only 
    
    RSACipher = publickey.encrypt( #encrypting key
            key, 
            apadding.OAEP(
                    mgf = apadding.MGF1(algorithm = hashes.SHA512()),
                    algorithm = hashes.SHA512(),
                    label = None))
    
    return RSACipher, C, IV, ext #RSACipher is the 

def MyRSADecrypt(RSACipher, C, IV, ext, RSA_Privatekey_filepath):    
    privatekey = GetPrivateKey(RSA_Privatekey_filepath)
    
    key = privatekey.decrypt(
            RSACipher, 
            apadding.OAEP(
                    mgf = apadding.MGF1(algorithm = hashes.SHA512()),
                    algorithm = hashes.SHA512(),
                    label = None))
        
    message = Mydecrypt(C, key, IV)
    
    path = path_output + rsa_decrypted_file_name + ext;
    
    with open(path_output + rsa_decrypted_file_name + ext, 'wb') as f:
        f.write(message)
        
    return path
#    return None
        
    
#-----------------------------/MyRSA-----------------------


#-----------------------------Begin Testing----------------------------

#genKeys('PGP_OURFIRSTSERVER.pem')

#-----------------------------String test-----------------------------
print('\n\nBEGIN MYENCRYPT AND MYDECRYPT STRING TEST')
string_key = os.urandom(key_size)
string_to_enc = "This is the test string to test out the encryption and decryption process."
print('string to encrypt: ' + string_to_enc)
string_enc, string_iv = Myencrypt(string_to_enc, string_key)
#print('string encrypted: {}\niv: {}'.format(string_enc, string_iv))
print('string decrypted {}'.format(Mydecrypt(string_enc, string_key, string_iv)))  
print('END MYENCRYPT AND MYDECRYPT STRING TEST')  
#-----------------------------/String test----------------------------


#-----------------------------Plaintext message-----------------------
print('\n\nBEGIN MYENCRYPT AND MYDECRYPT PLAINTEXT FILE TEST')
file_key = os.urandom(key_size)
with open('test.txt', 'rb') as f:
    print('Plaintext to encrypt then decrypt: {}'.format(f.read()))    
    file_enc, iv = Myencrypt(f.read(), file_key)
print('file contents encrypted: {}\niv: {}'.format(file_enc, iv))
print('file contents decrypted: {}'.format(Mydecrypt(file_enc, file_key, iv)))
print('END MYENCRYPT AND MYEDECRYPT PLAINTEXT FILE TEST')
#-----------------------------/Plaintext message-----------------------

#-----------------------------Image test-----------------------
print('\n\nBEGIN MYENCRYPT AND MYDECRYPT IMAGE FILE TEST')
image_key = os.urandom(key_size)
with open(image_file_name, 'rb') as f:
    file_enc, iv = Myencrypt(f.read(), image_key)
with open(path_output + encrypted_file_name + '.' + image_file_name, 'wb') as f:
    f.write(file_enc)
with open(path_output + decrypted_file_name + '.' + image_file_name, 'wb') as f:
    f.write(Mydecrypt(file_enc, image_key, iv))
print('END MYENCRYPT AND MYEDECRYPT IMAGE FILE TEST')
#-----------------------------/Image test-----------------------


#-----------------------------Test Myfile-----------------------
print('\n\nBEGIN MYFILEENCRYPT AND MYFILEEDECRYPT PLAINTEXT FILE TEST')
ct, iv, myfile_key, ext = MyfileEncrypt('test.txt')
print("file contents encrypted: {}".format(ct))
path_to_decrypted_file = MyfileDecrypt(ct, iv, myfile_key, ext)
with open(path_to_decrypted_file, 'r') as f:
    print('file contents decrypted: {}'.format(f.read()))
print('END MYFILEENCRYPT AND MYFILEEDECRYPT PLAINTEXT FILE TEST')
#-----------------------------/Test Myfile-----------------------


#-----------------------------Test MyRsa-----------------------
print('\n\nBEGIN MYRSA TEST')
RSACipher, C, iv, ext = MyRSAEncrypt('test.txt', public_key_file_name + key_ext)
print('ciphertext received: {}'.format(C))
filepath = MyRSADecrypt(RSACipher, C, iv, ext, private_key_file_name + key_ext)
with open(filepath, 'r') as f:
    print('decipered text: {}'.format(f.read()))
print('END MYRSA TEST')
#-----------------------------/Test MyRsa-----------------------

#-----------------------------Test MyRsa Image-----------------------
print('\n\nBEGIN MYRSA TEST')
RSACipher, C, iv, ext = MyRSAEncrypt('image.jpeg', public_key_file_name + key_ext)
print('ciphertext received: {}'.format(C))
filepath = MyRSADecrypt(RSACipher, C, iv, ext, private_key_file_name + key_ext)
print('END MYRSA TEST')
#-----------------------------/Test MyRsa Image-----------------------
