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
		
	p = Container(
	ip_header = Container(
		data = Container(
			checksum = 0, # must be computed later
			destination = eid_address,
			flags = Container(dont_fragment = False, more_fragments = False),
			frame_offset = 0,
			header_length = 20,
			identification = 12345,
			options = '', 
			payload_length = 0, # must be computed later
			protocol = 'UDP', 
			source = '172.16.42.205', 
			tos = Container(high_reliability = False, high_throuput = False, minimize_cost = False, minimize_delay = False, precedence = 0),
			total_length = 0, # must be computed later
			ttl = 255, 
			version = 4
			),
		type = 'IPv4'
	), 
	lisp_control_message = Container(
		authoritive = False, 
		eid_mask_len = 32, 
		eid_prefix = '153.16.0.0', 
		eid_prefix_afi = 'IPv4', 
		itr_rloc_address = ['172.16.42.205'], 
		itr_rloc_afi = 'IPv4', 
		itr_rloc_count = 1, 
		map_record = None, 
		map_reply_record = False, 
		nonce = '\x0f~o\xdcNxq\t', 
		probe = False, 
		record_count = 1, 
		send_map_request = False, 
		source_eid_address = None, 
		source_eid_afi = 'zero', 
		type = 'maprequest'
	), 
	type_inner_header = 'maprequest',
	type_outer_header = 'encapcontrol',
	udp_header = Container(
		checksum = 0, # must be computed later
		destination = 4342, 
		header_length = 8, 
		payload_length = 0, # must be computed later
		source = 55147)
	)

	pprint.pprint(p)
	payload = packet.encapcontrol.build(p)
	pprint.pprint(payload)
		
	

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
