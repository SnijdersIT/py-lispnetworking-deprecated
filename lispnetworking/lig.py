#!/opt/local/bin/python2.5

# from twisted.internet.protocol import DatagramProtocol
# from twisted.internet import reactor

from lispnetworking import packet
import sys
import pprint
from optparse import OptionParser

def main():
	global source
	global mapresolver
	global eid_address
	
	usage = "usage: %prog [options] <EID>"
	parser = OptionParser(usage)
	parser.add_option("-m", "--mapresolver", dest="mapresolver",
    	help="Map-Resolver which will be queried. Mandatory")
	parser.add_option("-s", "--source", dest="source",
        help="Source IP address, must be in RLOC Space (e.g. not behind NAT)")
	parser.add_option("-b", "--machine-parsable",
        action="store_false", dest="machinereadable", default=False,
        help="Display in scriptable output")
        
	(options, args) = parser.parse_args()
	
	if (not options.mapresolver):
		parser.error("Please specify a map-resolver to query")
	if len(args) != 1:
		parser.error("Please specify an EID address")

	

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
