

class KBucket(object):
    def __init__(self, k, dht):
        self.k = k
        self.dht = dht

    def add_node(self, ip, port, node_id):
        