from construct import *
from construct.protocols.layer3 import ipv4, ipv6

# maybe useful 

def ProtocolEnum(subcon):
    return Enum(subcon,
        IPv4 = 4,
        IPv6 = 6
    )

ippacket = Struct('ippacket',
   Anchor("base"),
    EmbeddedBitStruct(
      Enum(
        BitField('type', 4),
        v4 = 4,
        v6 = 6
      ),
      Padding(4),
    ),
    Pointer(lambda ctx: ctx.base,
        Switch("data", lambda ctx: ctx.type,
            {
                "v4": ipv4.ipv4_header,
                "v6": ipv6.ipv6_header
            }
        )
    ),  
)
encapcontrol = Struct('encapcontrol',
    EmbeddedBitStruct(
      Enum(
        BitField('type', 4),
        reserved = 0,
        maprequest = 1,
        mapreply = 2,
        mapregister = 3,
        encapcontrol = 8
      ),
      Padding(32-4),
    ),
    ippacket
)
maprequest = Struct('maprequest',
    EmbeddedBitStruct(
      
      # A This is an authoritative bit, which is set to 0 for UDP-based Map-Requests
      #      sent by an ITR.
      Flag('a'),          
      
      # M When set, it indicates a Map-Reply Record segment is included in
      #      the Map-Request.
      Flag('m'),
      
      # P This is the probe-bit which indicates that a Map-Request SHOULD be
      #     treated as a locator reachability probe. 
      Flag('p'),
      
      # S 'SMR bit' 
      Flag('smr'),
      
      # a few bits which are reserved, should be set 0 when sending, ignore when receiving
      # thus we treat it as padding :-)
      Padding(11),
      
      # This 5-bit field is the ITR-RLOC Count, which encodes the
      #      additional number of (ITR-RLOC-AFI, ITR-RLOC Address) fields
      Bits('irc', 5),
      
      # Record count, "a receiver MUST accept and
      #  process Map-Requests that contain one or more records, but a
      #  sender MUST only send Map-Requests containing one record. "
      Bits('recordcount', 8),
      
      # Nonce, An 8-byte random value created by the sender of the Map-
      #  Request.  This nonce will be returned in the Map-Reply.
      Bytes('nonce', 8),
      
      # Source-EID-AFI:  Address family of the "Source EID Address" field.    
      ProtocolEnum(BitField('source_eid_afi', 16)),
      
      # Source-EID-Address: 
      # determine if this is a maprequest used for map-cache refreshing or rloc probing
      # if 0 then source-eid-address field has length 0
      If(lamda ctx: ctx["source_eid_afi"] = 0,
          Padding(0)
      )
      
      # Source EID address is 32 bit if ipv4
      If(lamda ctx: ctx["source_eid_address"] = 4,
          Bits('source_eid_address', 32)
      ),
          
      # Source EID address is 128 bit if ipv6
      If(lamda ctx: ctx["source_eid_address"] = 6,      
          Bits('source_eid_address', 128)
      )
      
      # vanaf hier had ik vandaag geen zin meer - job
          
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

structure = Struct('lisppacket',
    Anchor("base"),
    EmbeddedBitStruct(
      Enum(
        BitField('type', 4),
        reserved = 0,
        maprequest = 1,
        mapreply = 2,
        mapregister = 3,
        encapcontrol = 8
      ),
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
