import queue
import threading

import crypto
import tools
import udp

q = queue.Queue()
message = queue.Queue()
ecc1 = crypto.ECC()
udps = threading.Thread(target=udp.udpserver, args=(ecc1, q, message, 5353, 6666))
udps.setDaemon(True)
udps.start()
client = udp.udpclient()
client.udpsend(tools.json_public_key(ecc1.GetPublicKey(), 5353), "127.0.0.1", 6666)
while True:
    if not q.empty():
        aeser = crypto.AESCrypto(q.get())
        client.udpsend(tools.json_send_message(aeser.cbc_encrypt("Hello")), "127.0.0.1", 6666)
        break
udps.join()
