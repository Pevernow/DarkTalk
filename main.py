import queue
import threading

import crypto
import httpmgr
import udp

q = queue.Queue()
message = queue.Queue()
ecc1 = crypto.ECC()
udps = threading.Thread(target=udp.udpserver, args=(ecc1, q, message, 6666))
mgr = threading.Thread(target=httpmgr.startmgr, args=(message, 8000))
udps.setDaemon(True)
mgr.setDaemon(True)
udps.start()
mgr.start()
udps.join()
mgr.join()
