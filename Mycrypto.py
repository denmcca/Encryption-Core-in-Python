# -*- coding: utf-8 -*-
"""
Created on Tue Oct 17 13:47:20 2017

@author: Dennis
"""
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

#path_to_output = './output/'
#image_file_name = 'image.jpeg'
#encrypted_file_name = 'encrypted'
#decrypted_file_name = 'decrypted'
#rsa_encrypted_file_name = 'rsa_encrypted'
#rsa_decrypted_file_name = 'rsa_decrypted'
key_size = 32
iv_size = 16
padding_size = 128

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
      
    #confirming that c_message is a bytes object
    if not isinstance(c_message, bytes):
        c_message = bytes(c_message, 'utf-8')   
    
    #setting Cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
    #configuring cipher to decrypt
    decryptor = cipher.decryptor()

    #configuring padder
    padder = padding.PKCS7(padding_size).unpadder()
    
    deciphered_text = decryptor.update(c_message)
    unpadded_text = padder.update(deciphered_text)
    end_text = padder.finalize()
    
    #padder.update is decrypted message, padder.finalize removes padding from padded block
    return unpadded_text + end_text

##-----------------------------Begin Testing----------------------------
#
#if not os.path.exists(path_keys):
#    genKeys(path_keys + 'PGP_OURFIRSTSERVER.pem')
#
##-----------------------------String test-----------------------------
#print('\n\nBEGIN MYENCRYPT AND MYDECRYPT STRING TEST')
#string_key = os.urandom(key_size)
#string_to_enc = "This is the test string to test out the encryption and decryption process."
#print('string to encrypt: ' + string_to_enc)
#string_enc, string_iv = Myencrypt(string_to_enc, string_key)
#print('string decrypted {}'.format(Mydecrypt(string_enc, string_key, string_iv)))  
#print('END MYENCRYPT AND MYDECRYPT STRING TEST')  
##-----------------------------/String test----------------------------