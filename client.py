import socket
import sys
import binascii
import json
import random
import hashlib
from math import log2
CHARLIMIT = 256

def compress(bytearr):
    inChars = tuple(bytearr)
    outChars = (inChars[0], )
    keyToArray = {tuple(): (0, ), (inChars[0], ): (1, )}
    basePointer = 1
    limitPointer = 1
    keyCounter = [2]
    while limitPointer < len(inChars):
        if limitPointer % 1000 == 0:
            print("Compressing... "+str(int((limitPointer/len(inChars)*100)))+"%", end="\r")
        if not inChars[basePointer:limitPointer + 1] in keyToArray:
            prepend = keyToArray[inChars[basePointer:limitPointer]]
            if sum(keyCounter) == 1:
                prepend += tuple([0 for i in range(len(keyCounter) - len(prepend) - 1)])
            else:
                prepend += tuple([0 for i in range(len(keyCounter) - len(prepend))])
            outChars += prepend + (inChars[limitPointer], )
            keyToArray[inChars[basePointer:limitPointer + 1]] = tuple(keyCounter)
            #print(keyCounter)
            for i in range(len(keyCounter)):
                keyCounter[i] += 1
                if keyCounter[i] != CHARLIMIT:
                    break
                else:
                    keyCounter[i] = 0
                    if i == len(keyCounter) - 1:
                        keyCounter.append(1)
            basePointer = limitPointer + 1
        limitPointer += 1
    if inChars[basePointer:
               limitPointer] in keyToArray and basePointer != limitPointer:
        prepend = tuple(keyToArray[inChars[basePointer:limitPointer]])
        outChars += prepend + tuple([0 for i in range(len(keyCounter) - len(prepend))])
    return bytes(outChars)

removed = ""     # | parameters used
replaced = False # | for orthogonal (decoding)
def codeOrthogonal(x):
    global removed
    global replcaed

    if (len(x) % 2 != 0):
        removed = x[0]
        x = x[1:]

    if (x[0] == '1'):
        replaced = True
        x = '0' + x[1:]

    first = x[:len(x)//2]
    second = x[len(x)//2:]

    firstCount1 = first.count('1') % 2
    secondCount1 = second.count('1') % 2
    xor = bin(int(first, 2) ^ int(second, 2))[2:]

    if (len(xor) < len(first)):
        xor = "0" * (len(first)-len(xor)) + xor

    coded = str(first)+str(firstCount1)+str(second)+str(secondCount1)+str(xor)
    return coded

errors = 0
def flip(message, probability):
    global errors
    flipped = ""
    for bit in message:
        if (random.random() < probability):
            errors += 1
            if bit == "0":
                flipped += "1"
            else:
                flipped += "0"
        else:
            flipped += bit

    return flipped

def main():
    host = '127.0.0.1'  # localhost
    port = 5000

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print('Connected to {}:{}'.format(host, port))

    f = open("file.txt", "rb")
    data = f.read()
    f.close()
    compressed = compress(data)
    hex = binascii.hexlify(compressed).decode()
    binary = bin(int(hex, 16))[2:]
    coded = codeOrthogonal(binary)

    p=float(input("Give a percentage for errors : "))
    coded = flip(coded, p / 100)

    e = -((coded.count('0')/len(coded))*log2(coded.count('0')/len(coded)) + (coded.count('1')/len(coded))*log2(coded.count('1')/len(coded)))

    sha256_hash = hashlib.sha256()
    sha256_hash.update(coded.encode("utf-8"))
    h = sha256_hash.hexdigest()

    json_data = {
        "encoded_message": coded,
        "compression_algorithm": "lz78",
        "encoding": "orthogonal",
        "parameters": [replaced, removed],
        "errors": errors,
        "SHA256": h,
        "entropy": e
    }

    json_string = json.dumps(json_data)
    json_bytes = json_string.encode('utf-8')

    client_socket.sendall(json_bytes)

    print ("Sent : ")
    print ("encoded_message :", json_data["encoded_message"])
    print ("compression_algorithm :", json_data["compression_algorithm"])
    print ("encoding :", json_data["encoding"])
    print ("parameters :", json_data["parameters"])
    print ("errors :", json_data["errors"])
    print ("SHA256 :", json_data["SHA256"])
    print ("entropy :", json_data["entropy"])
    print ()

    response = client_socket.recv(102400).decode("utf-8")
    response = json.loads(response)

    print ("Received : ")
    print ("decoded_message :", response["decoded_message"])
    print ("compression_algorithm :", response["compression_algorithm"])
    print ("encoding :", response["encoding"])
    print ("parameters :", response["parameters"])
    print ("errors_fixed :", response["errors_fixed"])
    print ("SHA256 :", response["SHA256"])
    print ("entropy :", response["entropy"])
    print ()

    try:
        print ("Server managed to fix", response["errors_fixed"] / json_data["errors"] * 100,"% of the errors")
    except:
        print ("No errors we're found")
        
    print ("entropy before :", e)
    print ("entropy after :", response["entropy"])
    print ()
    print ("hash before :", h)
    print ("hash after :", response["SHA256"])
    print ()

    x = str(input("press to quit"))

    client_socket.close()

if __name__ == '__main__':
    main()
