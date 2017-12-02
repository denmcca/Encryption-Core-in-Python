# -*- coding: utf-8 -*-
"""
Created on Thu Nov 30 14:59:38 2017

@author: phala
"""
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

path_public_key_file_name = './keys/public_key.pem'
path_private_key_file_name = './keys/private_key.pem'
path_to_keys = './keys/'

def findKeys():
    if not os.path.exists(path_public_key_file_name) or not os.path.exists(path_private_key_file_name):
        private_key = rsa.generate_private_key(
                65537,
                2048,
                default_backend())
        private_key_contents = private_key.private_bytes(
                encoding = serialization.Encoding.PEM,
                format = serialization.PrivateFormat.PKCS8,
                encryption_algorithm = serialization.NoEncryption())
        if "keys" not in os.listdir():
            os.mkdir(path_to_keys)
        with open(path_private_key_file_name, 'wb') as f:
            f.write(private_key_contents)
            
        public_key = private_key.public_key()
        public_key_contents = public_key.public_bytes(
                encoding = serialization.Encoding.PEM,
                format = serialization.PublicFormat.SubjectPublicKeyInfo)
        with open(path_public_key_file_name, 'wb') as f:
            f.write(public_key_contents)
            
    return path_public_key_file_name, path_private_key_file_name

def GetPrivateKey():
    privKey = findKeys()[1] #returns full path for private key
    with open(privKey, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(            
            key_file.read(),
            password = None,
            backend = default_backend()
        )
    return private_key

def GetPublicKey():
    pubKey = findKeys()[0] #returns full path for public key
    with open(pubKey, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend = default_backend()
        )
    return public_key

#unnecessary for program
def genNewKeys():
    if os.path.exists(path_private_key_file_name):
        os.remove(path_private_key_file_name)
        print(path_private_key_file_name + ' removed')
    if os.path.exists(path_public_key_file_name):
        os.remove(path_public_key_file_name)
        print(path_public_key_file_name + ' removed')
    
    private_key = rsa.generate_private_key(65537,2048,default_backend())    
    pem = private_key.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.PKCS8,
        encryption_algorithm = serialization.NoEncryption()
    )
    
    #validate keys directory in which keys are placed        
    if 'keys' not in os.listdir():
        os.mkdir('keys')
        print('keys directory created')
    
    with open(path_private_key_file_name, 'w') as f:
        f.write(pem.decode())
        
    public_key = private_key.public_key()
    
    pem = public_key.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open(path_public_key_file_name, 'w') as f:
        f.write(pem.decode())
        
    return path_public_key_file_name, path_private_key_file_name

#genNewKeys()