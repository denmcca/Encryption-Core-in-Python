# -*- coding: utf-8 -*-
"""
Created on Tue Oct 17 13:47:20 2017

@author: Dennis
"""
import os 
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
#from cryptography.hazmat.primitives.asymmetric import rsa

def Myencrypt(m, key) :
    print("Myencrypt1")
    if len(key) < 32:
        print("Error: Key must be at least 32 bytes (256-bits)")
        return [None, None];
    print("Myencrypt2")
    
    backend = default_backend()
    print("Myencrypt3")
    iv = os.urandom(16)
    print("Myencrypt4")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    print("Myencrypt5")
    encryptor = cipher.encryptor()
    print("Myencrypt6")
    buf = bytearray(31)
    print("Myencrypt7")
    len_encrypted = encryptor.update_into(m, buf)
    print("Myencrypt8")
    ct = bytes(buf[:len_encrypted]) + encryptor.finalize()
    print("Myencrypt9")
    decryptor = cipher.decryptor()
    print("Myencrypt10")
    len_decrypted = decryptor.update_into(ct, buf)
    print("Myencrypt11")
    return [bytes(buf[:len_decrypted]) + decryptor.finalize(), iv];

def Mydecrypt(ct, key, iv):
    print("start mydecrypt")
    if len(key) < 32:
        print("Error: Key must be 32 bytes (256-bits)")
        return [None, None]
    
    print("mydecrypt1")
    backend = default_backend()
    print("mydecrypt2")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    print("mydecrypt3")
    decryptor = cipher.decryptor()
    print("mydecrypt4")
    buf = bytearray(31)
    print("mydecrypt5")
    len_decrypted = decryptor.update_into(ct, buf)
    print("mydecrypt6")
    return [bytes(buf[:len_decrypted]) + decryptor.finalize()]
    

def MyfileEncrypt(path):
    k32B = os.urandom(32)
    with open("C:\\Users\\phala\\Documents\\OneDrive\\CSULB\\Fall 2017\\CECS 378\\Encrypt.decrypt\\cryptography\\test.txt", 'rb') as f:
        while 1: 
            byte_s = f.read(8)
            if not byte_s:
                break
            byte = byte_s[0]
            print(byte)
    
    m8B = b'adf3'
    
    [C, IV] = Myencrypt(m8B, k32B)
    return [C, IV, k32B, None]


msg = b"junkjunkjunkjunk"

#key = codecs.encode(os.urandom(32), 'hex').decode()
key = os.urandom(32)

print("key:")
print(str(key))
print(sys.getsizeof(key))
print(len(key))

[ct, iv] = Myencrypt(msg, key)

print("Decrypted message:")
print(Mydecrypt(ct, key, iv))

#[C, IV, key] = MyfileEncrypt('C:/Users/phala/Documents/OneDrive/CSULB/Fall 2017/CECS 378/Encrypt.decrypt/test.txt')

#ciphermsg = "ciphertext: " + str(ct, "utf-8")
#ivmsg = "initialization vector: " + iv

#print(ciphermsg)

#print(ivmsg)

#
#import OS
#from cryptography.fernet import Fernet
#
#key = Fernet.generate_key()
#f = Fernet(key)
#token = f.encrypt(b"A really secret message. Not for prying eyes.")
#token
#
#f.decrypt(token)