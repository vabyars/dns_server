from random import randint
from threading import Lock, Thread
from scapy.layers.dns import *
import socket
from cache import Cache, set_padding
import datetime


class CacheDNS:
    HOST = "127.0.0.1"
    PORT = 53

    def __init__(self):
        self._lock = Lock()
        self.types = {2: "NS", 1: "A", 12: "PTR", 28: "AAAA"}
        self.host = self.HOST
        self.port = self.PORT
        self._cache = Cache()

    def start(self):
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind((self.host, self.port))
        while True:
            data, addr = udp.recvfrom(65535)
            try:
                req = DNS(_pkt=data).qd
                response = b''
                from_cache = False

                if self._cache.contains(req.qname, req.qtype):
                    response, from_cache = self._cache.get(req.qname, req.qtype, data[:2]), True

                if response in [b'', None]:
                    response, from_cache = self._request_to_forwarder(req.qname, req.qtype, data), False
                print(f'\n[{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}]', end=" ")
                print(f"-- {addr[0]} {self.types[req.qtype]} {req.qname}", end=" ")
                print('from cache' if from_cache else 'from forwarder')
                udp.sendto(response, addr)
            except:
                udp.sendto(self._make_error_packet(data), addr)

    def _request_to_forwarder(self, qname, qtype, data):
        upd_request = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upd_request.sendto(data, ("8.8.8.8", 53))
        response = upd_request.recv(65535)
        question = self._get_question(data)
        qnames = self._cache.push(qname, qtype, question, response)
        Thread(target=self.cache_inner_fields, args=(qnames,)).start()
        return response

    def cache_inner_fields(self, qnames):
        for qname in qnames:
            if qname in [None, '']:
                continue
            for qtype in self._cache.used_qtypes:
                self._request_to_forwarder(qname, qtype,
                                           self.create_dns_request(qname, qtype))
    @staticmethod
    def _make_error_packet(packet):
        flags = '1' + set_padding(bin(packet[2])[2:])[1:]
        rcode = set_padding(bin(packet[3])[2:])
        return packet[:2] + struct.pack('>H', int(flags + rcode[:4] + '0010', 2)) + packet[4:]

    def create_dns_request(self, name, _type):
        with self._lock:
            name = name.encode()
            id = struct.pack('>H', randint(50000, 65536))
            flags = b'\x01\x20'
            question = b'\x00\x01'
            answer = b'\x00\x00'
            authority = b'\x00\x00'
            addit = b'\x00\x00'
            qname = b''
            for part in name.split(b'.'):
                qname += struct.pack('B', len(part)) + part
            qtype = struct.pack('>H', _type)
            qclass = b'\x00\x01'
            return id + flags + question + answer + authority + addit + qname + qtype + qclass

    @staticmethod
    def _get_question(packet):
        spacket = packet[12:]
        return spacket[:spacket.find(b'\x00') + 5]


if __name__ == '__main__':
    server = CacheDNS()
    server.start()