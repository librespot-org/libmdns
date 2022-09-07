from zeroconf import ServiceBrowser, Zeroconf, ZeroconfServiceTypes
from time import sleep


TYPE = "_http._tcp.local."
NAME = "libmdns Web Server"


class MyListener:
    def __init__(self):
        self.found = []

    def has_found(self, name):
        return name in self.found

    def add_service(self, zeroconf, type, name):
        self.found.append(name.replace("." + TYPE, ""))

    def update_service(self, zeroconf, type, name):
        pass


zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, TYPE, listener)
try:
    t = 0
    while t < 5 and not listener.has_found(NAME):
        sleep(1)
        t += 1
    assert listener.has_found(NAME)
    print('Service query: Success')
finally:
    zeroconf.close()

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_services._dns-sd._udp.local.", listener)
try:
    t = 0
    while t < 5 and not listener.has_found(TYPE):
        sleep(1)
        t += 1
    assert listener.has_found(TYPE)
    print('Service type enumeration: Success')
finally:
    zeroconf.close()
