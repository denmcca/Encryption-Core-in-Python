# -*- coding: utf-8 -*-
"""
Created on Tue Oct 17 13:47:20 2017

@author: Dennis
"""
import os 
#import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
#from cryptography.hazmat.primitives.asymmetric import rsa

def Myencrypt(message, key) :
    if len(key) < 32:
        print("Error: Key is {} bytes. 32-byte (256-bits) key required.".format(len(key)))
        return None, None;
    
    backend = default_backend()
    IV = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
    encryptor = cipher.encryptor()
    buf = bytearray(31)
    len_encrypted = encryptor.update_into(message, buf)
    C = bytes(buf[:len_encrypted]) + encryptor.finalize()
    return C, IV


def Mydecrypt(C, key, IV):
    if len(key) < 32:
        print("Error: Key is {} bytes. 32-byte (256-bit) key required.".format(len(key)))
        return None, None
    
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
    decryptor = cipher.decryptor()
    buf = bytearray(31)
    len_decrypted = decryptor.update_into(C, buf)
    message = bytes(buf[:len_decrypted]) + decryptor.finalize()
    return message
    

def MyfileEncrypt(path):
#    1. Generate a 32Byte key. 
    k32B = os.urandom(32)
#    2. Open and read the file as a string. 
    filename, ext = os.path.splitext(path)
    print(ext)
    C = ""
    with open(path, 'r+b') as f:
        while 1: 
            byte_s = f.read(16)
            if not byte_s:
                f.close()
                break
            byte = byte_s
            print('{} byte chunk: {}'.format(len(byte), byte))
            eb = Myencrypt(byte_s, k32B)
            C += str(eb[0])
            print('ciphertext from file: {}'.format(C))
            
    f = open("encrypted.txt", 'w+')
    f.write(C)
    f.close()
    
    IV = eb[1]
    return C, IV, k32B, ext


def MyfileDecrypt(filepath):
    return    
    pass


pt0 = b"junkjunkjunkjunk"

#key = codecs.encode(os.urandom(32), 'hex').decode()
key = os.urandom(32)

#print("key:")
#print(str(key))
#print(sys.getsizeof(key))
#print(len(key))

print("Plaintext: {}".format(pt0))

ct, iv = Myencrypt(pt0, key)
print("Ciphertext: {}".format(ct))

pt1 = Mydecrypt(ct, key, iv)

print("Plaintext (deciphered): {}".format(pt1))

ct, iv, key, ext = MyfileEncrypt('test.txt')

print("File's ciphertext: {}".format(ct))

#ciphermsg = "ciphertext: " + str(ct, "utf-8")
