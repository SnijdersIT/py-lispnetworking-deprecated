#!/usr/bin/python2.5

# from twisted.internet.protocol import DatagramProtocol
# from twisted.internet import reactor

import sys, pprint, random, socket, struct
from construct import *
from construct.protocols.layer4 import udp
from optparse import OptionParser
from IPy import IP
from lispnetworking import packet

def random_bytes(size):
	return "".join(chr(random.randrange(0, 256)) for i in xrange(size))
	
def dottedQuadToNum(ip):
    "convert decimal dotted quad string to long integer"
    return struct.unpack('L',socket.inet_aton(ip))[0]
        
def main():
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
	if (not options.source):
		source = socket.gethostbyname(socket.gethostname())
	else: source = options.source
	if (IP(source).iptype() == 'PRIVATE'): 
		print('Source Address is ' + source + '. Are you sure you want to use a non-global source IP address? Proceeding anyway..')
	if (not options.mapresolver):
		parser.error("Please specify a map-resolver to query")
	else: mapresolver = options.mapresolver
	if len(args) != 1:
		parser.error("Please specify an EID address")
	eid_address = args[0]
	
	eid_prefix_afi = 'IPv' + str(IP(eid_address).version())
	if eid_prefix_afi == 'IPv4': eid_mask_len = 32
	if eid_prefix_afi == 'IPv6': eid_mask_len = 128

	rloc_afi = 'IPv' + str(IP(source).version())
	
	maprequest = Container(
		authoritive = False, 
		eid_mask_len = eid_mask_len, 
		eid_prefix = eid_address, 
		eid_prefix_afi = eid_prefix_afi, 
		itr_rloc_address = [source],
		itr_rloc_afi = rloc_afi, 
		itr_rloc_count = 1, 
		map_record = None, 
		map_reply_record = False, 
		nonce = random_bytes(8), 
		probe = False,
		record_count = 1,
		send_map_request = False, 
		source_eid_address = None, 
		source_eid_afi = 'zero', 
		type = 'maprequest'
	)
	packet.step1 = packet.maprequest.build(maprequest)

	udp_header = Container(
		# 'UDP checksum computation is optional for IPv4. If a checksum
		# is not used it should be set to the value zero.'
		# and because i don't understand at all how this should be done
		# i'm just leaving it - job
		checksum = 0x0000, 
		destination = 4342, 
		header_length = 8, 
		payload_length = len(packet.step1), # must be computed later
		source = random.randint(20000, 65000))	
	
	packet.step2 = udp.udp_header.build(udp_header) + packet.step1

	ip_header = Container(
		data = Container(
			checksum = 0x0000, # must be computed later
			destination = eid_address,
			flags = Container(dont_fragment = False, more_fragments = False),
			frame_offset = 0, # no idea what this is
			header_length = 20,
			identification = 12345,
			options = '', 
			payload_length = len(packet.step2), 
			protocol = 'UDP', 
			source = source, 
			tos = Container(
				high_reliability = False,
				high_throuput = False,
				minimize_cost = False,
				minimize_delay = False,
				precedence = 0
				),
			total_length = len(packet.step2) + 20,
			ttl = 255, 
			version = 4
			),
		type = 'IPv4'
	) 
	
	packet.step3 = packet.ipv4.ipv4_header.build(ip_header.data) + packet.step2
	
	outer = Container(
		type_outer_header = 'encapcontrol'
		)
	
	p = packet.outer.build(outer) + packet.step3
	#packet.step3
	
#	p = lisp_control_message
#	p.type = 'encapcontrol'
#	p.data = lisp_control_message
	pprint.pprint(p)
	socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(p, (mapresolver,4342))
	print(udp_header.source)
	UDPSock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
  	listen_addr = ("", udp_header.source)
  	UDPSock.bind(listen_addr)
  	data,addr = UDPSock.recvfrom(1024)
#  	print data.strip(),addr
  	pprint.pprint(packet.structure.parse(data))
  	
#	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#	s.connect((mapresolver, 4342))
#	(data, addr) = s.recvfrom(60)
#	s.close()
#	parsed = packet.structure.parse(data)
#	pprint.pprint(parsed.__dict__)

	# cool stuff not in draft-ietf-lisp-lig-02
	# lcaf instanceid
	# authentication_key


if __name__ == "__main__":
    main()            
