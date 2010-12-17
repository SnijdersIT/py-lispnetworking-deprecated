from construct import *
from construct.protocols.layer3 import ipv4, ipv6

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
maprequest = Struct('maprequest')
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
