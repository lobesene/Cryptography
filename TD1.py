# -*- coding: utf-8 -*-

import cryptography
from codecs import encode, decode
from cryptography.hazmat.primitives import padding

secret = b'message secret'
a = encode(secret, 'hex')
#print(a)
# print(decode(a,'hex'))

padder = padding.ANSIX923(128).padder()
padded_data = padder.update(b"11111111111111112222222222")
# print(padded_data)
# print(padder.finalize())

'''def pkcs7(data,block_size):
    padding_size=(block_size-len(data))%block_size
    if padding_size==0:
       padding_size= block_size
    padding =(chr(padding_size)*padding_size).encode
    return data+ bytearray()
print (pkcs7('message secret',16))
'''

def read():
    f = open("C:\\Users\\Narutowin\\Downloads\\cipher.hex")
    return f



# Enzo's function
def encode(bytestring, k=16):
    """
    Pad an input bytestring according to PKCS#7

    """
    l = len(bytestring)
    val = k - (l % k)
    return bytestring + bytearray([val] * val)


#####################################################################

def ENC(input_bytes, char_value):
    output_bytes = b''
    for i in input_bytes:
        output_bytes = output_bytes + bytes(([i ^ char_value]))
    return output_bytes


def old():
    b = b'this is the cypher text'
    print(ENC(b, 50))
    print(ENC(ENC(b, 50), 50))

    cypher = 'a8cad21a2f38222b3a396a233e6a2e252f3924a8cad33e6a3f242e2f38393e2b242e6a0f242d2623392266a8cad36a3e22253f2d223e6a0b2623292f716aa8cad2036a2e2b382f392b336a233ea8cad3396a2b6a0c382f2429226a27253f392f666a2925272f6a253c2f386a3d233e226a1d232626232b276a3e222f6a0925243b3f2f38253864a8cad36a620c2538666a3d233e226a2b26266a222f386a2124253d262f2e2d2f6a252c6a2223393e253833666a0b2623292f6a222b2e6a24256a3c2f38336a29262f2b386a24253e2325246a22253d6a2625242d6a2b2d256a2b24333e2223242d6a222b2e6a222b3a3a2f242f2e64636a19256a39222f6a282f2d2b246a2b2d2b2324706aa8cad2053f6a2f393e6a272b6a29222b3e3e2f75a8cad36a3d222329226a3d2b396a3e222f6a2c2338393e6a392f243e2f24292f6a23246a222f386a0c382f2429226a262f393925246728252521646a1e222f6a07253f392f6a2d2b3c2f6a2b6a393f2e2e2f246a262f2b3a6a253f3e6a252c6a3e222f6a3d2b3e2f38666a2b242e6a392f2f272f2e6a3e256a3b3f233c2f386a2b26266a253c2f386a3d233e226a2c38232d223e646aa8cad20522666a036a282f2d6a33253f386a3a2b382e25246ba8cad36a2938232f2e6a0b2623292f6a222b393e232633666a2b2c382b232e6a3e222b3e6a39222f6a222b2e6a223f383e6a3e222f6a3a2525386a2b2423272b26a8cad3396a2c2f2f2623242d39646aa8cad2036a3b3f233e2f6a2c25382d253e6a33253f6a2e232e24a8cad33e6a2623212f6a292b3e3964a8cad3'
    cyphertext = decode(cypher, 'hex')
    A = []
    F = []

    for i in range(0, 256):
        ENC(cyphertext, i)
        A.append(ENC(cyphertext, i))
        F.append(A[i].count(b'e') + A[i].count(b't') + A[i].count(b'a'))

    print(max(F))

    index = 0
    for i in range(0, len(F)):
        if F[i] == 118:
            index = i
    print(i)
    print(ENC(cyphertext, 255))



import sys
def score(text):
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.'\n"
    p = 0
    for s in text:
        if s in charset or s == ' ' or s == '\'':
            p+=1
    return p

# function that performs XOR operation on two strings
def xor(s1, s2):
    res = ""
    for i in range(0, len(s1)):
        res += chr(ord(s1[i]) ^ ord(s2[i%len(s2)]))

    return res

def decode_cypher(cypher):
    #cypher = 'a8cad21a2f38222b3a396a233e6a2e252f3924a8cad33e6a3f242e2f38393e2b242e6a0f242d2623392266a8cad36a3e22253f2d223e6a0b2623292f716aa8cad2036a2e2b382f392b336a233ea8cad3396a2b6a0c382f2429226a27253f392f666a2925272f6a253c2f386a3d233e226a1d232626232b276a3e222f6a0925243b3f2f38253864a8cad36a620c2538666a3d233e226a2b26266a222f386a2124253d262f2e2d2f6a252c6a2223393e253833666a0b2623292f6a222b2e6a24256a3c2f38336a29262f2b386a24253e2325246a22253d6a2625242d6a2b2d256a2b24333e2223242d6a222b2e6a222b3a3a2f242f2e64636a19256a39222f6a282f2d2b246a2b2d2b2324706aa8cad2053f6a2f393e6a272b6a29222b3e3e2f75a8cad36a3d222329226a3d2b396a3e222f6a2c2338393e6a392f243e2f24292f6a23246a222f386a0c382f2429226a262f393925246728252521646a1e222f6a07253f392f6a2d2b3c2f6a2b6a393f2e2e2f246a262f2b3a6a253f3e6a252c6a3e222f6a3d2b3e2f38666a2b242e6a392f2f272f2e6a3e256a3b3f233c2f386a2b26266a253c2f386a3d233e226a2c38232d223e646aa8cad20522666a036a282f2d6a33253f386a3a2b382e25246ba8cad36a2938232f2e6a0b2623292f6a222b393e232633666a2b2c382b232e6a3e222b3e6a39222f6a222b2e6a223f383e6a3e222f6a3a2525386a2b2423272b26a8cad3396a2c2f2f2623242d39646aa8cad2036a3b3f233e2f6a2c25382d253e6a33253f6a2e232e24a8cad33e6a2623212f6a292b3e3964a8cad3'
    best = ""
    b = 0
    cypher_hex = ""
    #cypher_bin = b''

    #print(type(cypher_hex))
    # bruteforcing all possible values
    for i in range(1, 256):
        c = xor(cypher.decode('hex'), chr(i))
        if score(c) > b:
            b = score(c)
            best = c

    print("Plaintext: {}".format(best))

import binascii
if __name__ == "__main__":
    file = read()
    cypher_hex = ""
    for line in file:
        #Supprime le retour à la ligne
        cypher_hex += line.rstrip()

    nums = binascii.unhexlify(cypher_hex)
    strings = (''.join(chr(num ^ key) for num in nums) for key in range(256))
    max(strings, key=lambda s: s.count(' '))
    #cypher = 'a8cad21a2f38222b3a396a233e6a2e252f3924a8cad33e6a3f242e2f38393e2b242e6a0f242d2623392266a8cad36a3e22253f2d223e6a0b2623292f716aa8cad2036a2e2b382f392b336a233ea8cad3396a2b6a0c382f2429226a27253f392f666a2925272f6a253c2f386a3d233e226a1d232626232b276a3e222f6a0925243b3f2f38253864a8cad36a620c2538666a3d233e226a2b26266a222f386a2124253d262f2e2d2f6a252c6a2223393e253833666a0b2623292f6a222b2e6a24256a3c2f38336a29262f2b386a24253e2325246a22253d6a2625242d6a2b2d256a2b24333e2223242d6a222b2e6a222b3a3a2f242f2e64636a19256a39222f6a282f2d2b246a2b2d2b2324706aa8cad2053f6a2f393e6a272b6a29222b3e3e2f75a8cad36a3d222329226a3d2b396a3e222f6a2c2338393e6a392f243e2f24292f6a23246a222f386a0c382f2429226a262f393925246728252521646a1e222f6a07253f392f6a2d2b3c2f6a2b6a393f2e2e2f246a262f2b3a6a253f3e6a252c6a3e222f6a3d2b3e2f38666a2b242e6a392f2f272f2e6a3e256a3b3f233c2f386a2b26266a253c2f386a3d233e226a2c38232d223e646aa8cad20522666a036a282f2d6a33253f386a3a2b382e25246ba8cad36a2938232f2e6a0b2623292f6a222b393e232633666a2b2c382b232e6a3e222b3e6a39222f6a222b2e6a223f383e6a3e222f6a3a2525386a2b2423272b26a8cad3396a2c2f2f2623242d39646aa8cad2036a3b3f233e2f6a2c25382d253e6a33253f6a2e232e24a8cad33e6a2623212f6a292b3e3964a8cad3'
    #decode_cypher(cypher)

























