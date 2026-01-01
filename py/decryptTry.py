from scapy.all import Raw
from scapy.layers.zigbee import *
from scapy.layers.dot15d4 import *
from killerbee import kbdecrypt

from zigbee_decrypt_inline import decode

raw = bytes.fromhex(
    "61 88 06 63 69 88 ea 00 00 08 00 88 ea 00 00 1d 04"
    "21 01 30 1e 58 02 00 63 6c 69 63 6c 69 63 6c 1b 86"
    "dd 18 54 34 a8 9b 16 09 7c 75 77 a5 56 16 19 9d 9c"
    "9b cf 28 29 f5 37 18 02 ee 4a 6b 1f 43 24 12 4a 50 75 dc"
)

pkt = Dot15d4(raw)
kbdecrypt(pkt, key=bytes([90,105,103,66,101,101,65,108,108,105,97,110,99,101,48,57]))
