import random
import weakref
import threading

import binascii
import bitstring


nodes = {}
nodes_lock = threading.Lock()


def random_id():
    """Generates a random node id."""

    return random.randint(1, 2 ** 160 - 1)



def id_tobinary(node_id):
    """Returns the given node_id in binary format."""

    return bitstring.pack("uint:160", node_id).bytes



def id_frombinary(bin):
    bin = bitstring.BitStream(bytes=bin)
    return bin.read("uint:160")



class Node(object):
    def __init__(self, node_id, address):
        """An object representing a node in a kademlia bucket."""

        self.node_id = node_id
        self.address = address
        self.staleness = 0


    def __xor__(self, other):
        return self.node_id ^ other.node_id


    def __str__(self):
        node_id = bitstring.pack("uint:160", self.node_id).bytes
        node_id = binascii.hexlify(node_id)

        # insert a `-` every 8 characters
        return "Node({}, {})".format("-".join(node_id[i:i+8] for i in range(0, len(node_id), 8)), address)



def get_node(node_id, address=None):
    node = nodes.get(node_id, lambda: None)()

    if not node:
        with nodes_lock:
            node = Node(node_id, address)
            nodes[node_id] = weakref.ref(node)

    return node


