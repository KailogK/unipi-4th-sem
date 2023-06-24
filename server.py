import socket
import sys
import binascii
import json
import random
import hashlib
from math import log2
CHARLIMIT = 256

def checkRow(message, counts):
    return ((message.count('1') % 2) == counts)

errors = 0
def decodeOrthogonal(coded, replaced, removed):
    global errors

    counter = 0 # counter for total bits fixed

    piece = (len(coded) - 2) // 3
    first = coded[ : piece]
    firstCount1 = coded[piece]
    second = coded[piece+1 : piece*2+1]
    secondCount1 =coded[piece*2+1]
    third = coded[piece*2+2 : ]

    for i in range(len(first)):
        if not ((int(first[i]) + int(second[i])) % 2 == int(third[i])):
            if not (checkRow(first, firstCount1)):
                counter += 1
                if (first[i] == "0"):
                    first[:i] + "1" + first[i:]
                else:
                    first[:i] + "0" + first[i:]
            elif not (checkRow(second, secondCount1)):
                counter += 1
                if (second[i] == "0"):
                    second[:i] + "1" + second[i:]
                else:
                    second[:i] + "0" + second[i:]

    errors = counter

    decoded = coded[:(len(coded)-2)//3]+coded[((len(coded)-2)//3)+1:(((len(coded)-2)//3)*2)+1]
    #if (replaced):
        #decoded = "1" + decoded[1:]

    #if (len(removed)>0):
        #decoded = removed + decoded

    return decoded

def main():
    host = '127.0.0.1'  # localhost
    port = 5000

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print('Server listening on {}:{}'.format(host, port))

    while True:
        client_socket, addr = server_socket.accept()
        print('Connected by', addr)

        while True:
            json_bytes = client_socket.recv(102400).decode("utf-8")
            json_data = json.loads(json_bytes)
            print ("Received : ")
            print ("encoded_message :", json_data["encoded_message"])
            print ("compression_algorithm :", json_data["compression_algorithm"])
            print ("encoding :", json_data["encoding"])
            print ("parameters :", json_data["parameters"])
            print ("errors :", json_data["errors"])
            print ("SHA256 :", json_data["SHA256"])
            print ("entropy :", json_data["entropy"])
            print ()
            bin_data = decodeOrthogonal(json_data["encoded_message"], json_data["parameters"][0], json_data["parameters"][1])

            e = -((bin_data.count('0')/len(bin_data))*log2(bin_data.count('0')/len(bin_data)) + (bin_data.count('1')/len(bin_data))*log2(bin_data.count('1')/len(bin_data)))

            sha256_hash = hashlib.sha256()
            sha256_hash.update(bin_data.encode("utf-8"))
            h = sha256_hash.hexdigest()

            json_data = {
                "decoded_message": bin_data,
                "compression_algorithm": "lz78",
                "encoding": "orthogonal",
                "parameters": "x",
                "errors_fixed": errors,
                "SHA256": h,
                "entropy": e
            }

            json_string = json.dumps(json_data)
            json_bytes = json_string.encode('utf-8')

            print ("Sent : ")
            print ("decoded_message :", bin_data)
            print ("compression_algorithm :", "lz78")
            print ("encoding :", "orthogonal")
            print ("parameters :", "x")
            print ("errors_fixed :", errors)
            print ("SHA256 :", h)
            print ("entropy :", e)
            print ()

            client_socket.send(json_bytes)

            x = str(input("press to quit"))

        client_socket.close()

if __name__ == '__main__':
    main()
