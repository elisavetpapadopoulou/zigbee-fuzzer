import os
import sys

current = os.path.dirname(os.path.realpath(__file__))
parent = os.path.dirname(current)
sys.path.append(parent)

from scapy.all import Raw
from scapy.layers.zigbee import *
from scapy.layers.dot15d4 import *
from ZigbeeEncryption import decrypt_all


raw = bytes.fromhex(
    "4188cdf016ffff00000912fcff000001acfe3e053a004b120028b20e0000fe3e053a004b120000e6c48e5f37a6"
)

class DecryptTry():
    def __init__(self, serial_port=0, target_mac=0x0000, ):
        self.config = {
            "pan_id": 0xFFFF,
            "coord_addr": 0xFFFF,
            #TODO: Save the coordinator's IEEE address dynamically
            "coord_ieee": 0x6c63696c63696c63,
            "short_address": 0xFFFE,
            "ieee_address": 0x79bc000000010001,
            "tc_global_key": bytes([90,105,103,66,101,101,65,108,108,105,97,110,99,101,48,57]),
            "tc_link_key": b"",
            "network_key": {}
        }


if __name__ == "__main__":
    decrypt_try = DecryptTry()
    pkt = Dot15d4(raw)
    decoded_pkt = decrypt_all(decrypt_try, pkt)
    decoded_pkt.show2()

