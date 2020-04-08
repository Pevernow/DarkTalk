import threading

import crypto
import tools
import udp

ecc1 = crypto.ECC()
udps = threading.Thread(target=udp.udpserver, args=(ecc1, 6666))
udps.setDaemon(True)
udps.start()
ecc2 = crypto.ECC()
client = udp.udpclient()
client.udpsend(tools.json_public_key(ecc2.GetPublicKey()), "127.0.0.1", 6666)
a = crypto.AESCrypto
client.udpsend(tools.json_public_key(ecc2.GetPublicKey()), "127.0.0.1", 6666)
udps.join()
