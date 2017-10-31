# -*- coding: utf-8 -*-
"""
Created on Tue Oct 17 13:47:20 2017

@author: Dennis
"""
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes


key = os.urandom(32)



def Myencrypt(message, key) : #constrain: bytes message
    from cryptography.hazmat.primitives import padding

    print("*****entered Myencrypt*****")
    if len(key) < 32:
        print("Error: Key is {} bytes. 32-byte (256-bits) key required.".format(len(key)))
        return None, None;

    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor() #encryptor mode turned on  
    
    #padding message to guarantee 16 bytes    
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message)
    padded_message = padded_message + padder.finalize()
    
    cipher_out = encryptor.update(padded_message)
    print("-----exiting Myencrypt-----")
    return cipher_out, iv #return bytes for C

def Mydecrypt(c_message, key, iv):
    from cryptography.hazmat.primitives import padding

    print("*****entered Mydecrypt*****")
    
    if len(key) < 32:
        print("Error: Key is {} bytes. 32-byte (256-bit) key required.".format(len(key)))
        return None, None
      
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    padded_message = decryptor.update(c_message)
    padder = padding.PKCS7(128).unpadder()
    unencrypted_message = padder.update(padded_message)
    unencrypted_message = unencrypted_message + padder.finalize()
    
    print("-----exiting Mydecrypt-----")
    return unencrypted_message, iv




    
def MyfileEncrypt(filepath):
    print("**********entered MyfileEncrypt**********")
#    1. Generate a 32Byte key. 
#    2. Open and read the file as a string. 
    filename, ext = os.path.splitext(filepath)
#    print(os.path.abspath(filepath))
#    print(filename)
#    print(ext)
    f = open(filepath, 'r')
    data = f.read()
        
#    3.	Call the above method to encrypt file using the key generated. 
    
    encrypted_block, iv = Myencrypt(data.encode(), key)
        
    ciphertext = encrypted_block
    f.close()
    
    
    
    f = open('encrypted.txt', 'w+b')
    f.write(iv + ciphertext)
    f.close()
    
    
    print("----------exiting MyfileEncrypt----------")
#    4.	Return:
#        a.	cipher C
#        b.	IV
#        c.	key
#        d.	extension of the file (as a string).
    return ciphertext, iv, key, ext

def MyfileDecrypt(filepath):
    print("**********entered MyfileDecrypt**********")
    filename, ext = os.path.splitext(filepath)
    f = open(filepath, 'r+b')
    iv = f.read(16)
    data = f.read()
    f.close()
    
    
    decrypted_message, iv_out = Mydecrypt(data, key, iv)   
       
    f = open("decrypted.txt", 'w')
    f.write(decrypted_message.decode())
    f.close()
            
    print("----------exiting MyfileDecrypt---------")
    return decrypted_message, iv_out, key, ext





def MyRSAEncrypt(self, filepath, RSA_Publickey_filepath):
    from cryptography.hazmat.primitives.asymmetric import padding

    C, IV, key, ext = MyfileEncrypt(filepath)
    
    pem = open(RSA_Publickey_filepath, 'rb')
    privatekey = serialization.load_pem_private_key(
            pem.read(),
            password = None,
            backend = default_backend())
    pem.close()
    
    publickey = privatekey.public_key()
    RSACipher = publickey.encrypt(
            key, 
            padding.OAEP(
                    mgf = padding.MGF1(algorithm = hashes.SHA512()),
                    algorithm = hashes.SHA512(),
                    label = None))
    
    return RSACipher, C, IV, ext #RSACipher is the 

def MyRSADecrypt(self, RSACipher, C, IV, ext, RSA_Privatekey_filepath):
    from cryptography.hazmat.primitives.asymmetric import padding

    pem = open(RSA_Privatekey_filepath, 'rb')
    privatekey = serialization.load_pem_private_key(
            pem.read(),
            password = None,
            backend = default_backend())
    pem.close()
    
    deciphered_message = privatekey.decrypt(
            C, 
            padding.OAEP(
                    mgf = padding.MGF1(algorithm = hashes.SHA512()),
                    algorithm = hashes.SHA512(),
                    label = None))
    print(deciphered_message)
    
    return filepath, RSA_Privatekey_filepath



#def MyfileEncrypt(filepath):
#    print("**********entered MyfileEncrypt**********")
##    1. Generate a 32Byte key. 
##    2. Open and read the file as a string. 
#    filename, ext = os.path.splitext(filepath)
##    print(os.path.abspath(filepath))
##    print(filename)
##    print(ext)
#    f = open(filepath, 'r')
#    data = f.read()
#        
##    3.	Call the above method to encrypt file using the key generated. 
#    
#    encrypted_block, iv = myencrypt.Myencrypt(data.encode(), key)
#        
#    ciphertext = encrypted_block
#    f.close()
#    
#    
#    
#    f = open('encrypted.txt', 'w+b')
#    f.write(iv + ciphertext)
#    f.close()
#    
#    
#    print("----------exiting MyfileEncrypt----------")
##    4.	Return:
##        a.	cipher C
##        b.	IV
##        c.	key
##        d.	extension of the file (as a string).
#    return ciphertext, iv, key, ext
#
#def MyfileDecrypt(filepath):
#    print("**********entered MyfileDecrypt**********")
#    filename, ext = os.path.splitext(filepath)
#    f = open(filepath, 'r+b')
#    iv = f.read(16)
#    data = f.read()
#    f.close()
#    
#    decrypted_message, iv_out = myencrypt.Mydecrypt(data, key, iv)   
#       
#    f = open("decrypted.txt", 'w')
#    f.write(decrypted_message.decode())
#    f.close()
#            
#    print("----------exiting MyfileDecrypt---------")
#    return decrypted_message, iv_out, key, ext


#
#


ct, iv, key, ext = MyfileEncrypt('test.txt')
#
print("ct: {}, iv: {}, key: {}, ext: {}".format(ct, iv, key,ext))
#
#print("******************DECRYPTING FROM FILE***********************")
#
dt, div, key, extd = MyfileDecrypt('encrypted.txt')
#
print("dt: {}, div: {}, key: {}, extd: {}".format(dt,div,key,extd))



RSACipher, C, iv, ext = MyRSAEncrypt('test.txt', 'PGP_OURFIRSTSERVER.pem')
print(RSACipher, C, iv, ext)
#filepath, RSAfilepath = MyRSADecrypt(RSACipher, C, iv, ext, 'PGP_OURFIRSTSERVER.pem')
#print(filepath, RSAfilepath)
