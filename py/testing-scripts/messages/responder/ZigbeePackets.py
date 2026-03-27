from scapy.layers.dot15d4 import *
from scapy.layers.zigbee import *
from scapy.packet import Raw

PACKET_TEMPLATES = {
    'MAC_BEACON':                       lambda sul: Dot15d4(fcf_frametype = 0)
                                                    / Dot15d4Beacon(),
    'MAC_ASSOCIATION_RESPONSE':         lambda sul: Dot15d4(fcf_frametype = 1)
                                                    / Dot15d4Data()
                                                    / Dot15d4Cmd(cmd_id = 2)
                                                    / Dot15d4CmdAssocResp(),
    'MAC_DISSOCIATION_NOTIFICATION':    lambda sul: Dot15d4(fcf_frametype = 1)
                                                    / Dot15d4Data()
                                                    / Dot15d4Cmd(cmd_id = 3) /
                                                    Dot15d4CmdDisassociation(),
    'PAN_ID_CONFLICT_NOTIFY':           lambda sul: Dot15d4(fcf_frametype = 3) 
                                                    / Dot15d4Cmd(cmd_id = 5),
    'MAC_ORPHAN_NOTIFY':                lambda sul: Dot15d4(fcf_frametype = 3) 
                                                    / Dot15d4Cmd(cmd_id = 6),
    'MAC_ACK':                          lambda sul: Dot15d4(fcf_frametype = 2),

    'APS_TRANSPORT_NWK_KEY':            lambda sul: Dot15d4(fcf_frametype = 1) 
                                                    / Dot15d4Data() / ZigbeeNWK(frametype = 1) 
                                                    / ZigbeeSecurityHeader() 
                                                    / ZigbeeAppCommandPayload(cmd_identifier = 5),
    'APS_ACK':                          lambda sul: Dot15d4(fcf_frametype = 1) 
                                                    / Dot15d4Data() 
                                                    / ZigbeeNWK(frametype = 0) 
                                                    / ZigbeeAppDataPayload(frametype = 2),
    'ZDO_DEVICE_ANNOUNCE':              lambda sul: Dot15d4(
                                                        fcf_frametype = 1,
                                                        fcf_security=0,
                                                        fcf_ackreq=0,
                                                        fcf_panidcompress=1,
                                                        fcf_destaddrmode=2,
                                                        fcf_srcaddrmode=2,
                                                        seqnum=self.mac_seq & 0xFF
                                                    )/ Dot15d4Data(
                                                        dest_panid=self.pan_id,
                                                        dest_addr=0xFFFF,
                                                        src_addr=self.short_address
                                                    )/ ZigbeeNWK(
                                                        frametype = 0,
                                                        destination=0xFFFD,
                                                        source=self.short_address,
                                                        radius=30,
                                                        seqnum=self.nwk_seq & 0xFF
                                                    )/ ZigbeeAppDataPayload(
                                                        frame_control=0x00,
                                                        aps_frametype=0,
                                                        delivery_mode=0,
                                                        counter=self.aps_seq & 0xFF,
                                                        profile=0x0000,
                                                        cluster=0x0013,
                                                        src_endpoint=0,
                                                        dst_endpoint=0
                                                    )/ Raw(self.short_address.to_bytes(2,"little") + self.ieee_address.to_bytes(8, "little") + bytes([cap & 0xFF])),
    'APS_TRANSPORT_KEY':                lambda sul: Dot15d4(fcf_frametype = 1) 
                                                    / Dot15d4Data() 
                                                    / ZigbeeNWK(frametype = 1) 
                                                    / ZigbeeSecurityHeader() 
                                                    / ZigbeeAppCommandPayload(cmd_identifier = 5),
    'APS_VERIFY_KEY':                   lambda sul: Dot15d4(fcf_frametype = 1) 
                                                    / Dot15d4Data() 
                                                    / ZigbeeNWK(frametype = 1) 
                                                    / ZigbeeSecurityHeader() 
                                                    / ZigbeeAppCommandPayload(cmd_identifier = 15),
    'APS_CONFIRM_KEY':                  lambda sul: Dot15d4(fcf_frametype = 1) 
                                                    / Dot15d4Data() 
                                                    / ZigbeeNWK(frametype = 1) 
                                                    / ZigbeeSecurityHeader() 
                                                    / ZigbeeAppCommandPayload(cmd_identifier = 16),

