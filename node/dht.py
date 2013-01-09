from __future__ import print_function

import socket
import threading
import time
import itertools

import node


# protocol constants
KADEMLIA_K = 20
KADEMLIA_ALPHA = 3
KADEMLIA_PING_TIMEOUT = 10
KADEMLIA_PING_FREQUENCY = 1

# binary protcol constants
KADEMLIA_PING_PACKET = 0
KADEMLIA_PONG_PACKET = 1
KADEMLIA_FIND_NODE_PACKET = 2
KADEMLIA_RETURN_NODE_PACKET = 3
KADEMLIA_MAGIC = b"KADE"


class DHT(object):
    def __init__(self, bootstrap_addresses):
        """A distributed hash table implementing the Kademlia system.

        The first argument should be a list of (ip, port) tuples that are nodes in the DHT to bootstrap with."""

        # generate 160 bit (20 byte) random ID
        self.node_id = node.random_id()

        # the k-buckets
        self.buckets = [[] for _ in range(160)]
        self.buckets_lock = threading.Lock()

        # the nodes we're pinging to see if they're alive
        self.current_pings = {}
        self.current_pings_lock = threading.Lock()

        # set up socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.socket.setblocking(False)
        self.socket.bind(("", 0))

        # set up node thread
        self.node_thread = threading.Thread(target=self.node_main)
        self.node_thread.daemon = True

        # start node thread
        self.node_thread.start()

        # bootstrap ourselves into the network
        self.bootstrap_addresses = [(bootstrap_addresses, 0)]
        self.bootstrapping = True

        # TODO: remove this
        print(self.socket.getsockname())
        try:
            while True:
                pass
        except KeyboardException:
            pass


    def get_closest_nodes(self, target_node, blacklist):
        # a naive implementation of getting the *amount* closest nodes to a target node
        # concatenate all buckets and for each nodeid in this list take the absolute difference
        # sort this list and then keep adding nodes from this list to a result list until amount
        # is reached or no nodes are left

        possible_nodes = sorted(itertools.chain.from_iterable(self.buckets), key=lambda node: node ^ target_node_id))
        result = []

        for possible_node in possible_nodes:
            if len(result) >= amount:
                return result

            if not possible_node in blacklist:
                result.append(possible_node)

        return result


    def get_value(self, key, callback):
        pass


    def find_nodes(self, node, timeout, callback=None):
        pass


    def ping(self, address, timeout, callback=None):
        rpc_id = node.random_id()

        with self.current_pings_lock:
            self.current_pings[rpc_id] = [0, time.time() + timeout, address, callback]


    def pong(self, address, rpc_id):
        self.socket.sendto(chr(KADEMLIA_PONG_PACKET) + node.tobinary(self.node_id) + node.tobinary(rpc_id), address)


    def node_seen(self, address, node_id):
        # we don't keep track of ourselves
        if node_id == self.node_id:
            return

        # TODO: remove this
        print("Node seen: ", address, node_id)

        time_seen = time.time()

        # we're updating the buckets, lock
        with self.buckets_lock:
            distance = node.distance(self.node_id, node_id)
            bucket = self.buckets[distance.bit_length() - 1]

            # is this node already in the bucket?
            try:
                # yep. move to tail
                index = [tup[1] for tup in bucket].index(node_id)
                bucket.pop(index)
                bucket.append((address, node_id, time_seen))
                return
            except ValueError:
                pass

            # do we have space for this unknown node?
            if len(bucket) < KADEMLIA_K:
                # yep. insert at the tail and we're done
                bucket.append((address, node_id, time_seen))
                return

            # just to be sure, sort the bucket on time_seen, then get the least seen node
            bucket.sort(key=lambda node: node[2])
            least_seen_node = bucket[0]

        # right now we are no longer changing the buckets, so we should unlock
        
        # we ping the least seen node to see if it's still alive
        # create a callback
        def ping_callback(success, reply_address=None, reply_node_id=None):
            # we're updating the buckets, lock
            with self.buckets_lock:
                # due to the dynamic nature of the k-buckets we'll first attempt to simply
                # add our new node, because space might have become available
                # additionally we sort the bucket on time seen afterwards, because things might
                # have changed
                if len(bucket) < KADEMLIA_K:
                    bucket.append((address, node_id, time_seen))
                    bucket.sort(key=lambda node: node[2])
                    return

                if success:
                    # hmm, the least seen node is still active
                    # which means this node should be moved down to the tail
                    # and the node pending for addition should be discarded

                    # ironically, we don't have to do anything. the pinged node is already
                    # moved to the tail because node_seen() was called on it, and discarding
                    # the node pending for addition is done by doing nothing.

                    return

                # add our node and remove the least seen node
                bucket.append((address, node_id, time_seen))
                bucket.sort(key=lambda node: node[2])
                bucket.pop(0)

        self.ping(least_seen_node[0], KADEMLIA_PING_TIMEOUT, ping_callback)


    def handle_packet(self):
        try:
            data, address = self.socket.recvfrom(1024)
        except socket.error:
            return

        if len(data) < 1:
            return

        packet_type = ord(data[0])
        data = data[1:]

        if packet_type == KADEMLIA_PING_PACKET:
            if len(data) < 40:
                return

            node_id = node.frombinary(data[0:20])
            rpc_id = node.frombinary(data[20:40])

            self.node_seen(address, node_id)
            self.pong(address, rpc_id)

            return

        elif packet_type == KADEMLIA_PONG_PACKET:
            if len(data) < 40:
                return

            node_id = node.frombinary(data[0:20])
            rpc_id = node.frombinary(data[20:40])

            self.node_seen(address, node_id)

            with self.current_pings_lock:
                if rpc_id in self.current_pings:
                    if self.current_pings[rpc_id][3] is not None:
                        self.current_pings[rpc_id][3](True, address, node_id)

                    del self.current_pings[rpc_id]


    def node_main(self):
        while True:
            # handle bootstrapping
            if self.bootstrapping:
                
            # handle pings
            with self.current_pings_lock:
                now = time.time()
                pings_timed_out = []

                for rpc_id, ping in self.current_pings.items():
                    # is the ping timed out?
                    if now > ping[1]:
                        pings_timed_out.append(rpc_id)

                        if ping[3] is not None:
                            ping[3](False)

                    # or do we need to reping?
                    elif now > ping[0]:
                        self.socket.sendto(chr(KADEMLIA_PING_PACKET) + node.tobinary(self.node_id) + node.tobinary(rpc_id), ping[2])
                        ping[0] = now + KADEMLIA_PING_FREQUENCY


                for rpc_id in pings_timed_out:
                    del self.current_pings[rpc_id]

            # handle a packet
            self.handle_packet()



if __name__ == "__main__":
    dht = DHT([('127.0.0.1', 57573)])
