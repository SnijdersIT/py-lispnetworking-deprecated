from construct import *
from construct.protocols.layer3 import ipv4, ipv6
from construct.protocols.layer4 import udp

def IP_ProtocolEnum(subcon):
    return Enum(subcon,
        IPv4 = 4,
        IPv6 = 6
    )    

def AFI_Enum(subcon):
    return Enum(subcon,
    	zero = 0,
    	IPv4 = 1,
        IPv6 = 2,
        LCAF = 16387
    )    

def MessageTypeEnum(subcon):
    return  Enum(subcon,
        reserved = 0,
        maprequest = 1,
        mapreply = 2,
        mapregister = 3,
        encapcontrol = 8
    )

def plus1(x, ctx): return x+1

def min1(x, ctx): return x-1
              
ip_header = Struct('ip_header',
    Peek(EmbeddedBitStruct(
      IP_ProtocolEnum(Nibble('type')),
      Padding(4),
      )
    ),  
    Switch("data", lambda ctx: ctx["type"],
        {
           "IPv4": ipv4.ipv4_header,
           "IPv6": ipv6.ipv6_header
        }
    )  
)

lcaf = Struct('lcaf')

map_record = Struct('map_record',
	EmbeddedBitStruct(
	Bits('record_ttl', 32),
	Bits('locator_count', 8),
	Bits('eid_mask_len', 8),
	Enum(Bits('action', 5),
		no_action = 0,
		native_forward = 1,
		send_map_request = 2,
		drop = 3
	  )
	),
	# A bit
	Flag('authoritative'),
	# few bits are reserved
	Padding(16),
	Bits('map_version_number', 12),
    AFI_Enum(UBInt16('eid_afi')),
    Switch("eid_prefix", lambda ctx: ctx.eid_afi,
    	{
                "IPv4": ipv4.IpAddress('eid_prefix'),
                "IPv6": ipv6.Ipv6Address('eid_prefix'),
                "LCAF": lcaf
        }
    ),
    
    # locator part
    
    UBInt8('priority'),
    UBInt8('weight'),
    UBInt8('multicast_priority'),
    UBInt8('multicast_weight'),
    Padding(13),
    Flag('local_locator'),
    Flag('is_probed'),
    Flag('is_reachable'),
    AFI_Enum(UBInt16('locator_afi')),
    Switch("locator", lambda ctx: ctx["locator_afi"],
    	{
                "IPv4": ipv4.IpAddress('locator'),
                "IPv6": ipv6.Ipv6Address('locator'),
                "LCAF": lcaf
        }
    )

	#  Mapping Protocol Data:  See [CONS] or [ALT] for details.  This field
    #  is optional and present when the UDP length indicates there is
    #  enough space in the packet to include it.
	# - thus we ignore it for now - Job
	
)	

maprequest = Struct('maprequest',
    EmbeddedBitStruct(
    
      # by now we already know it's a maprequest - job      
      MessageTypeEnum(Nibble('type')),

      # A This is an authoritative bit, which is set to 0 for UDP-based Map-Requests
      #      sent by an ITR.
      Flag('authoritive'),          
      
      # M When set, it indicates a Map-Reply Record segment is included in
      #      the Map-Request.
      Flag('map_reply_record'),
      
      # P This is the probe-bit which indicates that a Map-Request SHOULD be
      #     treated as a locator reachability probe. 
      Flag('probe'),
      
      # S 'SMR bit' 
      Flag('send_map_request'),
      
      # a few bits which are reserved, should be set 0 when sending, ignore when receiving
      # thus we treat it as padding :-)
      Padding(11),
      
      # This 5-bit field is the ITR-RLOC Count, which encodes the
      #      additional number of (ITR-RLOC-AFI, ITR-RLOC Address) fields
      # we add 1 because this field starts at 0
	  ExprAdapter(Bits('itr_rloc_count', 5), encoder = min1, decoder = plus1),

      # Record count, "a receiver MUST accept and
      #  process Map-Requests that contain one or more records, but a
      #  sender MUST only send Map-Requests containing one record. "
      Bits('record_count', 8)
   ),
      
   # Nonce, An 8-byte random value created by the sender of the Map-
   #  Request.  This nonce will be returned in the Map-Reply.
   Bytes('nonce', 8),

   # Source-EID-AFI:  Address family of the "Source EID Address" field.    
   AFI_Enum(UBInt16('source_eid_afi')),

   # Source-EID-Address: 
   # determine if this is a maprequest used for map-cache refreshing or rloc probing
   # if 0 then source-eid-address field has length 0
   
   Switch("source_eid_address", lambda ctx: ctx.source_eid_afi,
       {
                "zero": Pass,
                "IPv4": ipv4.IpAddress('source_eid_address'),
                "IPv6": ipv6.Ipv6Address('source_eid_address'),
                "LCAF": lcaf
       }
    ),

   # ITR-RLOC-AFI:
   AFI_Enum(UBInt16('itr_rloc_afi')),

   # ITR-RLOC Addresses:
   # Remember, +1 was added to make parsing easier
   MetaRepeater(lambda ctx: ctx["itr_rloc_count"],
	   Switch("itr_rloc_address", lambda ctx: ctx.itr_rloc_afi,
            {
                "zero": Pass,
                "IPv4": ipv4.IpAddress('itr_rloc_address'),
                "IPv6": ipv6.Ipv6Address('itr_rloc_address'),
                "LCAF": lcaf
            }
       )
   ),
              
    #  8 bits that are reserved for future use 
    Padding(1), 

    # EID mask-len
    UBInt8("eid_mask_len"),
   
    # EID-prefix-AFI:
    AFI_Enum(UBInt16('eid_prefix_afi')),
      
    #  EID-prefix:
	Switch("eid_prefix", lambda ctx: ctx.eid_prefix_afi,
        {
            "IPv4": ipv4.IpAddress('eid_prefix'),
            "IPv6": ipv6.Ipv6Address('eid_prefix'),
            "LCAF": lcaf
         }
    ),
      
	# Map-Reply Record: 
	# this can be used for caching the RLOC's of the Source EID if the M bit is set
	# thus with one map_request both parties know a bit more
    If(lambda ctx: ctx["map_reply_record"],
    	map_record
    )
    
    # Mapping Protocol Data: (optional field)          
	# we don't support CONS so we ignore for the moment
   
)

mapreply = Struct('mapreply',
    EmbeddedBitStruct(
      MessageTypeEnum(Nibble('type_outer_header')),
      Flag('in_response_to_probe'),
      Flag('have_echo_nonce'),
      Padding(18),
      UBInt8('record_count'),
    ),
	#   Nonce:  A 24-bit value set in a Data-Probe packet or a 64-bit value
	#      from the Map-Request is echoed in this Nonce field of the Map-
	#      Reply.
	# i think we are only replying with the 4 random bytes.. and not doing data-probing - job
	Bytes('nonce', 8),
	MetaRepeater(lambda ctx: ctx["record_count"],
		map_record
	)
)

mapregister = Struct('mapregister',
    EmbeddedBitStruct(
    	MessageTypeEnum(Nibble('type_outer_header')),
		Flag('proxy_map_reply'),
		Padding(18),
        UBInt8('record_count'),
	),
	Bytes('nonce', 8),
	UBInt8('key_id'),
	UBInt8('authentication_length'),
	MetaField("authentication_data", lambda ctx: ctx["authentication_length"]),
	map_record
)

encapcontrol = Struct('encapcontrol',
    EmbeddedBitStruct(
      MessageTypeEnum(Nibble('type_outer_header')),
      Padding(32-4),
    ),
    
    # inside the encapsulated control message there is an ip header
    # the destination in this inner header is the EID we're going to 
    # look up.
    ip_header,
    
    # innder UDP header, the destination port should be 4342
    udp.udp_header,

	#  At this time, only Map-Request messages and PIM
    #  Join-Prune messages [MLISP] are allowed to be encapsulated.
    #  but since we not doing anything with MLISP we can only switch
    #  to the maprequest
    Peek(EmbeddedBitStruct(
      	Enum(
        	Nibble('type_inner_header'),
        	maprequest = 1
         ),
        Padding(4),
       )
    ),
    Switch("lisp_control_message", lambda ctx: ctx["type_inner_header"],
            {
                "maprequest": maprequest
            }
        ),
)

structure = Struct('lisppacket',
    Peek(EmbeddedBitStruct(
      	MessageTypeEnum(Nibble('type')),
      	Padding(4),
    	)
    ),
    Switch("data", lambda ctx: ctx["type"],
    	{
    		"maprequest": maprequest,
            "mapreply": mapreply,
            "mapregister": mapregister,
            "encapcontrol": encapcontrol
        }
    )
)
