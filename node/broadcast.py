import socket
import random
import time
import json

OUR_ID = random.randrange(0, 2**160)

BROADCAST_TIME = 1

peers = {}
last_local_broadcast = 0

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setblocking(False)
sock.bind(("", 0))




while True:
    try:
        data, addr = sock.recvfrom(1024)
    except socket.error:
        continue

    if data.startswith("GETPEERS"):
        peers[str(addr)] = data[len("GETPEERS "):]

        sock.sendto("PEERINFO " + json.dumps(peers), addr)

    print(data, addr, peers)