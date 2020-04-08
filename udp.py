import socket
from json import loads

import tools
from crypto import AESCrypto, SHA512


def udpserver(ecc, port=6666):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    while True:
        data = s.recvfrom(1024)
        ip = data[1]
        data = loads(data[0].decode())
        if (data["type"] == "dhkey"):
            key = SHA512(ecc.GetShareKey(data["data"].encode()), 32)
            aeser = AESCrypto(key)
            s.sendto(tools.json_public_key(ecc.GetPublicKey()), (ip[0], 6666))
            print("Accpet from " + str(ip[0]) + ":" + str(ip[1]))
        elif (data["type"] == "message"):
            if aeser:
                print(aeser.cbc_decrypt(data["data"]))
        # s.sendto(data[0], (data[1][0], 6666))


class udpclient():
    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def udpsend(self, data, ip, port):
        self.s.sendto(data, (ip, port))
