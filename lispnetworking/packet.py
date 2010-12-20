from construct import *
from construct.protocols.layer3.ipv4 import ipv4_header
from construct.protocols.layer3 import ipv4, ipv6
from construct.protocols.layer4 import udp

def IP_ProtocolEnum(subcon):
    return Enum(subcon,
        IPv4 = 4,
        IPv6 = 6
    )    

def AFI_Enum(subcon):
    return Enum(subcon,
    	map_refresh = 0,
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
                
class IPv4AddressAdapter(Adapter):
    def _encode(self, obj, context):
        return "".join(chr(int(b)) for b in obj.split("."))
    def _decode(self, obj, context):
        return ".".join(str(ord(b)) for b in obj)

def IPv4Address(name):
    return IPv4AddressAdapter(Bytes(name, 4))

def ProtocolEnum(code):
    return Enum(code,
        ICMP = 1,
        TCP = 6,
        UDP = 17,
    )
    
ipv4_header = Struct("ipv4_header",
    EmbeddedBitStruct(
        Const(Nibble("version"), 4),
        ExprAdapter(Nibble("header_length"), 
            decoder = lambda obj, ctx: obj * 4, 
            encoder = lambda obj, ctx: obj / 4
        ),
    ),
    BitStruct("tos",
        Bits("precedence", 3),
        Flag("minimize_delay"),
        Flag("high_throuput"),
        Flag("high_reliability"),
        Flag("minimize_cost"),
        Padding(1),
    ),
    UBInt16("total_length"),
    Value("payload_length", lambda ctx: ctx.total_length - ctx.header_length),
    UBInt16("identification"),
    EmbeddedBitStruct(
        Struct("flags",
            Padding(1),
            Flag("dont_fragment"),
            Flag("more_fragments"),
        ),
        Bits("frame_offset", 13),
    ),
    UBInt8("ttl"),
    ProtocolEnum(UBInt8("protocol")),
    UBInt16("checksum"),
    IPv4Address("source"),
    IPv4Address("destination"),
    Field("options", lambda ctx: ctx.header_length - 20),
)

ip_header = Struct('ip_header',
   Anchor("base"),
    EmbeddedBitStruct(
      IP_ProtocolEnum(BitField('type', 4)),
      Padding(4),
    ),
    Pointer(lambda ctx: ctx.base,
        Switch("data", lambda ctx: ctx.type,
            {
                "IPv4": ipv4_header,
                "IPv6": ipv6.ipv6_header
            }
        )
    ),  
)

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
      Bits('itr_rloc_count', 5),
      
      # Record count, "a receiver MUST accept and
      #  process Map-Requests that contain one or more records, but a
      #  sender MUST only send Map-Requests containing one record. "
      Bits('record_count', 8)
   ),
      
   # Nonce, An 8-byte random value created by the sender of the Map-
   #  Request.  This nonce will be returned in the Map-Reply.
   Bytes('nonce', 8),
      
   # Source-EID-AFI:  Address family of the "Source EID Address" field.    
 #  AFI_Enum(Bytes('source_eid_afi', 2)),
      
   # Source-EID-Address: 
   # determine if this is a maprequest used for map-cache refreshing or rloc probing
   # if 0 then source-eid-address field has length 0
#      If('source_eid_afi' == 0,
#          Bits("source_eid_address", 0)
#      ),
      
      # Source EID address is 32 bit if ipv4
#      If('maprequest.source_eid_afi' == 4,
#          Bits('source_eid_address', 32)
#      ),
          
      # Source EID address is 128 bit if ipv6
#      If('maprequest.source_eid_afi' == 6,      
#          Bits('source_eid_address', 128)
#      ),
      
      # the following fields still need implementation
                
      # ITR-RLOC-AFI:
      
      # ITR-RLOC Address:
      
      # EID mask-len
      
      # EID-prefix-AFI:
      
      #  EID-prefix:
      
      # Map-Reply Record: 
      
      # Mapping Protocol Data: (optional field)          

   
)

mapreply = Struct('mapreply')
mapregister = Struct('mapregister')

encapcontrol = Struct('encapcontrol',
    EmbeddedBitStruct(
      MessageTypeEnum(BitField('type_outer_header', 4)),
      Padding(32-4),
    ),
    
    # hardcoding that it's ipv4 works
     ipv4_header,
    
    # letting the program select which version it is fails
    # ip_header,
     Probe(),
     udp.udp_header,

    Anchor("lisp_control_message"),

    EmbeddedBitStruct(
      Enum(
        BitField('type_inner_header', 4),
        maprequest = 1
      ),
      Padding(4),
    ),

    Pointer(lambda ctx: ctx.lisp_control_message,
        Switch("lisp_control_message", lambda ctx: ctx.type_inner_header,
            {
                "maprequest": maprequest
            }
        )
    ),

    Probe()

)

structure = Struct('lisppacket',
    Anchor("base"),
    EmbeddedBitStruct(
      MessageTypeEnum(BitField('type',4)),
      Padding(4),
    ),
    Pointer(lambda ctx: ctx.base,
        Switch("data", lambda ctx: ctx.type,
            {
                "maprequest": maprequest,
                "mapreply": mapreply,
                "mapregister": mapregister,
                "encapcontrol": encapcontrol
            }
        )
    ),
)
