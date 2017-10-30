# -*- coding: utf-8 -*-
"""
Created on Tue Oct 17 13:47:20 2017

@author: Dennis
"""
import os 
#import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa

key = os.urandom(32)


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

def Myencrypt(message, key) : #constrain: bytes message
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

def Mydecrypt(c_message, key, iv):
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





ct, iv, key, ext = MyfileEncrypt('test.txt')

print("ct: {}, iv: {}, key: {}, ext: {}".format(ct, iv, key,ext))

print("******************DECRYPTING FROM FILE***********************")

dt, div, key, extd = MyfileDecrypt('encrypted.txt')

print("dt: {}, div: {}, key: {}, extd: {}".format(dt,div,key,extd))
