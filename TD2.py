# -*- coding: utf-8 -*-
"""
Created on Wed Mar 13 16:39:06 2019

@author: lobes
"""
import cryptography 
from codecs import encode, decode 
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from os import urandom

key= urandom(16)
#print(key)

cipher = Cipher(algorithms.AES(key), mode=modes.ECB(), backend=default_backend())
encryptor = cipher.encryptor()
encryptor.update(b'hellohellohello')

message =b'Qu est ce aui est jaune et qui attend'
def pcks7(message, l):
    pad = l - len(message)%l
    return message + bytes([pad]*pad)

## Not secure because it's deterministic
    
def encrypt(key, message):
    cipher = Cipher(algorithms.AES(key), mode=modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(pcks7(message,16))+ encryptor.finalize()

#print (encrypt(key,message))


key =b'YELLOW SUBMARINE'
def oracle(message):
    suffix=decode('7468657265206973206d6f726520746f206c696665207468616e20626f6f6b732c20627574206e6f74206d756368206d6f7265','hex')
    return encrypt(key, message+suffix)

#print(oracle(b'a'))
#print(oracle(b'a'*32))
#print(oracle(b'a'*32)[:16])
#oracle(b'a'*32)[:16]


for x in range (256):
    
    test = oracle(b'a'*15 + bytes([x]))[:16]
    if test == oracle(b'a'*15)[:16]:
        ret=test
        rang=x
        
d={oracle(b'a'*15 + bytes([x]))[:16]:bytes([x]) for x in range(256)}
d[oracle(b'a'*15)[:16]]
print(d[oracle(b'a'*15)[:16]])
    
#print(ret)
#print(chr(rang))

#This loop doesn't work :(
for y in range (15,0,-1):
    for x in range (256):
        test = oracle(b'a'*y + bytes([x])  )[:16]
        if test == oracle(b'a'*y)[:16]:
           ret=test
           rang=x
           #print(chr(rang))

#Enzo's function
def oracle2():
    chaine=b""
    for i in range(16):
        x = 0
        for j in range(256):
            if oracle(b'a' * (15 - i) + chaine + bytes([x]))[:16] != oracle(b'a' * (15 - i))[:16]:
                x=j
        chaine = chaine + bytes([x])
    return chaine
print(oracle2())




    
    
     
    
    


