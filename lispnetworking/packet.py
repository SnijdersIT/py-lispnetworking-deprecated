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
      IP_ProtocolEnum(BitField('type', 4)),
      Padding(4),
      )
    ),  
    Switch("data", lambda ctx: ctx.type,
        {
           "IPv4": ipv4.ipv4_header,
           "IPv6": ipv6.ipv6_header
        }
    )  
)

lcaf = Struct('lcaf')
map_reply_record = Struct('map_reply_record')

maprequest = Struct('maprequest',
    EmbeddedBitStruct(
    
      # by now we already know it's a maprequest - job      
      MessageTypeEnum(BitField('type', 4)),

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
    	map_reply_record
    )
    
    # Mapping Protocol Data: (optional field)          
	# we don't support CONS so we ignore for the moment
   
)

mapreply = Struct('mapreply')
mapregister = Struct('mapregister')

encapcontrol = Struct('encapcontrol',
    EmbeddedBitStruct(
      MessageTypeEnum(BitField('type_outer_header', 4)),
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
        	BitField('type_inner_header', 4),
        	maprequest = 1
         ),
        Padding(4),
       )
    ),
    Switch("lisp_control_message", lambda ctx: ctx.type_inner_header,
            {
                "maprequest": maprequest
            }
        ),
)

structure = Struct('lisppacket',
    Peek(EmbeddedBitStruct(
      	MessageTypeEnum(BitField('type',4)),
      	Padding(4),
    	)
    ),
    Switch("data", lambda ctx: ctx.type,
    	{
    		"maprequest": maprequest,
            "mapreply": mapreply,
            "mapregister": mapregister,
            "encapcontrol": encapcontrol
        }
    )
)
