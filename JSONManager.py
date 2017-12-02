# -*- coding: utf-8 -*-
"""
Created on Thu Nov 30 15:08:55 2017

@author: phala
"""
import json
import os


def createJSON(RSACipher, C, IV, tag, ext, file_path):
    file_name = os.path.splitext(file_path)[0]
    
    #creating set for JSON
    j = {}
    
    #converting bytes to strings
    #inserting mapped string values for JSON
    j['RSACipher']=RSACipher.decode('latin-1')
#    print(RSACipher)
    j['C']=C.decode('latin-1')   
    j['IV']=IV.decode('latin-1')   
    j['tag']=tag.decode('latin-1')    
    j['ext']=ext    
    
    print('createJSON\'s file_path = ' + file_path)
    
    with open(file_name + '.json', 'w') as jfile:
        json.dump(j, jfile)
        print(file_name+'.json' + ' file created')
        
def parseJSON(file_path):
    file_name = os.path.splitext(file_path)[0]
    
    print('parseJSON\'s file_name = ' + file_name)
    
    with open(file_path, 'r') as f:
        jcontents = json.load(f)
        RSACipher = bytes(jcontents['RSACipher'], 'latin-1') #string into bytes
        C = bytes(jcontents['C'], 'latin-1')
        IV = bytes(jcontents['IV'], 'latin-1')
        tag = bytes(jcontents['tag'], 'latin-1')
        ext = jcontents['ext']
        
    return RSACipher, C, IV, tag, ext, file_name
