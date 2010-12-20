#!/opt/local/bin/python2.5

# from twisted.internet.protocol import DatagramProtocol
# from twisted.internet import reactor

from construct import *
from lispnetworking import packet
import sys, pprint
from optparse import OptionParser

def main():
	global source
	global mapresolver
	global eid_address
	
	usage = "usage: %prog [options] -m MAPRESOLVER <EID>"
	parser = OptionParser(usage)
	parser.add_option("-m", "--mapresolver", dest="mapresolver",
    	help="Map-Resolver which will be queried. Mandatory.")
	parser.add_option("-s", "--source", dest="source",
        help="Source IP address, must be in RLOC Space (e.g. not behind NAT)")
	parser.add_option("-b", "--machine-parsable", dest="machinereadable",
        action="store_false", default=False, help="Display in scriptable output")
	parser.add_option("-d", "--debug", dest="debug",
        action="store_false", default=False, help="Display debug output")
 
	(options, args) = parser.parse_args()
	
	if (not options.mapresolver):
		parser.error("Please specify a map-resolver to query")
	if len(args) != 1:
		parser.error("Please specify an EID address")
	eid_address = args[0]
	print eid_address
	
	
	data = Container(destination = eid_address)
	
	p = Container()
	p.type = 'encapcontrol'
	p.data = Container()

#	Container()
	
#	p.data.ip_header = Container()
#	p.data.ip_header.type = 'IPv4',
	
#	p.data.ip_header.data = Container()
#	p.data.ip_header.data.destination = eid_address,
#	p.data.ip_header.data.identification = '12345',
#	p.data.ip_header.data.protocol = 'UDP',
#	p.data.ip_header.data.source = options.source

	payload = packet.structure.build(p)
	
		
	

# mandator
# mapresolver (name or ip)
# eid prefix
# optional source (v4 or v6 address)
# debug


# cool stuff not in draft-ietf-lisp-lig-02
# lcaf instanceid
# authentication_key

if __name__ == "__main__":
    main()            
