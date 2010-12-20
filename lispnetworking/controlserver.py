from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor

from lispnetworking import packet

import pprint

class LispControlServer(DatagramProtocol):
    def datagramReceived(self, data, (host, port)):
        # p = packet()
        # p.fromstruct(data)
        #p = data
        data = file("packetdump").read()
        # file('packetdump','w').write(data)
        parsed = packet.structure.parse(data)
        print "received from %s:%d\n%r" % (host, port, data)
        pprint.pprint(parsed.__dict__)
        # self.transport.write(data, (host, port))

if __name__ == '__main__':
    reactor.listenUDP(4342, LispControlServer())
    reactor.run()
    
    