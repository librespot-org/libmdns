from zeroconf import ServiceBrowser, Zeroconf
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


zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, TYPE, listener)
try:
    t = 0
    while t < 5 and not listener.has_found(NAME):
        sleep(1)
        t += 1
    assert listener.has_found(NAME)
    print('Success')
finally:
    zeroconf.close()
