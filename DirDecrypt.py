# -*- coding: utf-8 -*-
"""
Created on Wed Nov 29 14:08:46 2017

@author: phala
""" 
import os, re
import FileEncryptMAC
import JSONManager
import KeyManager

json_ext = '.json'
json_file_pattern = '.*'+json_ext

def decryptDir():
    if not os.path.exists(KeyManager.path_private_key_file_name):
        print('Key not found! Exiting...')
        return
    dir_list = os.listdir()
    for file_path in dir_list: #drops parent directories
        if re.search(json_file_pattern, file_path, 0) is not None:
            RSACipher, C, IV, tag, ext, file_name = JSONManager.parseJSON(file_path)
            check_path = FileEncryptMAC.MyRSADecrypt(RSACipher, C, IV, tag, file_path, ext, KeyManager.path_private_key_file_name)
            os.remove(file_name + json_ext)

            print('decrypted json to file: ' + check_path)      
            


#starting point for directory decryption
decryptDir()