import itertools
import time
import socket
from typing import Iterator

import netprotocols

class Decoder:
    def __init__(self, interface: str):
        self.interface = interface
        self.data = None
        self.protocol_queue = ["Ethernet"]
        self.packet_num: int = 0
        self.frame_length: int = 0
        self.epoch_time: float = 0

    def _bind_interface(self, sock: socket.socket):
        if self.interface is not None:
            sock.bind((self.interface, 0))

    def _attach_protocols(self, frame: bytes):
        start = end = 0
        for proto in self.protocol_queue:
            try:
                proto_class = getattr(netprotocols, proto)
            except AttributeError:
                continue
            end: int = start + proto_class.header_len
            protocol = proto_class.decode(frame[start:end])
            setattr(self, proto.lower(), protocol)
            if protocol.encapsulated_proto in (None, "undefined"):
                break
            self.protocol_queue.append(protocol.encapsulated_proto)
            start = end
        self.data = frame[end:]

    def execute(self) -> Iterator:
     with socket.socket(socket.PF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        self._bind_interface(sock)
        for self.packet_num in itertools.count(1):
            try:
                frame, _ = sock.recvfrom(9000)  # Adjust the buffer size if needed
            except OSError as e:
                print(f"Error receiving packet: {e}")
                continue

            if not frame:
                print("[!] Received an empty frame. Aborting packet capture...")
                break

            self.frame_length = len(frame)
            self.epoch_time = time.time_ns() / (10 ** 9)
            self._attach_protocols(frame)
            yield self
            del self.protocol_queue[1:]





class PacketSniffer:
    def __init__(self):
        self._observers = list()

    def register(self, observer) -> None:
        self._observers.append(observer)

    def _notify_all(self, *args, **kwargs) -> None:
        [observer.update(*args, **kwargs) for observer in self._observers]

    def listen(self, interface: str) -> Iterator:
        for frame in Decoder(interface).execute():
            self._notify_all(frame)
            yield frame
