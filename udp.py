import socket
from pickle import loads

import tools
from crypto import AESCrypto, SHA512


def udpserver(ecc, que, message, port=6666, fport=5353):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    print(port)
    while True:
        data = s.recvfrom(1024)
        ip = data[1]
        data = loads(data[0])
        if data["type"] == "dhkey" and "aeser" not in locals().keys():
            print(data["data"].encode())
            key = SHA512(ecc.GetShareKey(data["data"].encode()), 32)
            aeser = AESCrypto(key)
            print(data["port"])
            s.sendto(tools.json_public_key(ecc.GetPublicKey(), port), (ip[0], data["port"]))
            que.put(key)
            print("Accept from " + str(ip[0]) + ":" + str(ip[1]))
        elif data["type"] == "message":
            if "aeser" in locals().keys():
                message.put(aeser.cbc_decrypt(data["data"]).decode())
                print(aeser.cbc_decrypt(data["data"]))
        # s.sendto(data[0], (data[1][0], 6666))


class udpclient():
    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def udpsend(self, data, ip, port):
        self.s.sendto(data, (ip, port))
