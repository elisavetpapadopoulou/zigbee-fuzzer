from scapy import config
from scapy.layers.dot15d4 import *
from scapy.layers.zigbee import *
from scapy.packet import Raw

from ZigbeeEncryption import zigbee_hmac

PACKET_TEMPLATES = {
    'MAC_BEACON':                       lambda self: Dot15d4FCS(fcf_frametype = 0)
                                                    / Dot15d4Beacon(),

    'MAC_ASSOCIATION_REQUEST':          lambda self: Dot15d4FCS(
                                                        fcf_frametype=3,
                                                        fcf_security=0,
                                                        fcf_ackreq=1,
                                                        fcf_panidcompress=1,
                                                        fcf_destaddrmode=2,
                                                        fcf_srcaddrmode=3,
                                                        seqnum=self.sequence_numbers["mac_seq"] & 0xFF
                                                    )/Dot15d4Cmd(
                                                        cmd_id=0x01,
                                                        dest_panid=self.config["pan_id"],
                                                        dest_addr=self.config["coord_addr"],
                                                        src_addr=self.config["ieee_address"]
                                                    )/Dot15d4CmdAssocReq(
                                                        device_type=0,
                                                        security_capability=1,
                                                        allocate_address=1
                                                    ),
    'MAC_ASSOCIATION_RESPONSE':         lambda self: Dot15d4FCS(fcf_frametype = 1)
                                                    / Dot15d4Data()
                                                    / Dot15d4Cmd(cmd_id = 2)
                                                    / Dot15d4CmdAssocResp(),
    'MAC_DISASSOCIATION_NOTIFY':    lambda self: Dot15d4FCS(
                                                        fcf_frametype=3,
                                                        fcf_security=0,
                                                        fcf_ackreq=1,
                                                        fcf_panidcompress=1,
                                                        fcf_destaddrmode=2,
                                                        fcf_srcaddrmode=3,
                                                        seqnum=self.sequence_numbers["mac_seq"] & 0xFF
                                                    )/Dot15d4Cmd(
                                                        dest_panid=self.config["pan_id"],
                                                        dest_addr=self.config["coord_addr"],
                                                        src_addr=self.config["ieee_address"],
                                                        cmd_id=0x03
                                                    )/Dot15d4CmdDisassociation(),

    'MAC_DATA_REQUEST':                 lambda self: Dot15d4FCS(
                                                        fcf_frametype=3,
                                                        fcf_security=0,
                                                        fcf_ackreq=1,
                                                        fcf_panidcompress=1,
                                                        fcf_destaddrmode=2,
                                                        fcf_srcaddrmode=3,
                                                        seqnum=self.sequence_numbers["mac_seq"] & 0xFF
                                                    )/ Dot15d4Cmd(
                                                        cmd_id = 0x04,
                                                        dest_panid=self.config["pan_id"],
                                                        dest_addr=self.config["coord_addr"],
                                                        src_addr=self.config["ieee_address"]
                                                    ),
    'MAC_PAN_ID_CONFLICT_NOTIFY':           lambda self: Dot15d4FCS(
                                                        fcf_frametype=3,
                                                        fcf_security=0,
                                                        fcf_ackreq=1,
                                                        fcf_panidcompress=1,
                                                        fcf_destaddrmode=2,
                                                        fcf_srcaddrmode=2,
                                                        seqnum=self.sequence_numbers["mac_seq"] & 0xFF
                                                    )/Dot15d4Cmd(
                                                        dest_panid=self.config["pan_id"],
                                                        dest_addr=self.config["coord_addr"],
                                                        src_addr=self.config["short_address"],
                                                        cmd_id=0x05
                                                    ),

    'MAC_ORPHAN_NOTIFY':                lambda self: Dot15d4FCS(
                                                        fcf_frametype=3,
                                                        fcf_security=0,
                                                        fcf_ackreq=1,
                                                        fcf_panidcompress=1,
                                                        fcf_destaddrmode=2,
                                                        fcf_srcaddrmode=3,
                                                        seqnum=self.sequence_numbers["mac_seq"] & 0xFF
                                                    )/Dot15d4Cmd(
                                                        dest_panid=self.config["pan_id"],
                                                        dest_addr=self.config["coord_addr"],
                                                        src_addr=self.config["ieee_address"],
                                                        cmd_id=0x06
                                                    ),

    'MAC_BEACON_REQUEST':               lambda self: Dot15d4FCS(
                                                        fcf_panidcompress=1,
                                                        fcf_ackreq=0,
                                                        fcf_security=0,
                                                        fcf_frametype=3,
                                                        fcf_srcaddrmode=3,
                                                        fcf_framever=0,
                                                        fcf_destaddrmode=2,
                                                        seqnum=self.sequence_numbers["mac_seq"]
                                                    )/ Dot15d4Cmd(
                                                        cmd_id = 0x07,
                                                        dest_panid = self.config["pan_id"],
                                                        dest_addr = self.config["coord_addr"],
                                                        src_addr = self.config["ieee_address"]
                                                    ),
    'MAC_COORDINATOR_REALIGN':          lambda self: Dot15d4FCS(fcf_frametype = 1)
                                                    / Dot15d4Data()
                                                    / Dot15d4Cmd(cmd_id = 8)
                                                    / Dot15d4CmdCoordRealign(),
    'MAC_GTS_REQUEST':                  lambda self: Dot15d4FCS(
                                                        fcf_frametype=3,
                                                        fcf_security=0,
                                                        fcf_ackreq=1,
                                                        fcf_panidcompress=1,
                                                        fcf_destaddrmode=2,
                                                        fcf_srcaddrmode=2,
                                                        seqnum=self.sequence_numbers["mac_seq"] & 0xFF
                                                    )/Dot15d4Cmd(
                                                        dest_panid=self.config["pan_id"],
                                                        dest_addr=self.config["coord_addr"],
                                                        src_addr=self.config["short_address"],
                                                        cmd_id=0x09
                                                    )/Dot15d4CmdGTSReq(),

    'MAC_ACK':                          lambda self: Dot15d4FCS(fcf_frametype = 2),

    'APS_TRANSPORT_NWK_KEY':            lambda self: Dot15d4FCS(fcf_frametype = 1)
                                                    / Dot15d4Data() / ZigbeeNWK(frametype = 1)
                                                    / ZigbeeSecurityHeader()
                                                    / ZigbeeAppCommandPayload(cmd_identifier = 5),
    'APS_ACK':                          lambda self: Dot15d4FCS(fcf_frametype = 1)
                                                    / Dot15d4Data()
                                                    / ZigbeeNWK(frametype = 0)
                                                    / ZigbeeAppDataPayload(frame_control = 2),
    'NWK_ROUTE_REPLY':                  lambda self: Dot15d4FCS(
                                                        fcf_frametype = 1,
                                                        fcf_security=0,
                                                        fcf_ackreq=1,
                                                        fcf_panidcompress=1,
                                                        fcf_destaddrmode=2,
                                                        fcf_srcaddrmode=2,
                                                        seqnum=self.sequence_numbers["mac_seq"] & 0xFF
                                                    )/ Dot15d4Data(
                                                        dest_panid=self.config["pan_id"],
                                                        dest_addr=self.config["coord_addr"],
                                                        src_addr=self.config["short_address"]
                                                    )/ ZigbeeNWK(
                                                        frametype = 1,
                                                        destination=self.config["coord_addr"],
                                                        source=self.config["short_address"],
                                                        discover_route=0,
                                                        radius=10,
                                                        seqnum=self.sequence_numbers["nwk_seq"] & 0xFF
                                                    )/ ZigbeeNWKCommandPayload(
                                                        cmd_identifier="route reply",
                                                        # route_request_identifier=rri,
                                                        originator_address=self.config["coord_addr"],
                                                        responder_address=self.config["short_address"],
                                                        path_cost=1
                                                    ),


    'NWK_REJOIN_REQUEST_TC':               lambda self: Dot15d4FCS(
                                                        fcf_frametype=1,
                                                        fcf_security=0,
                                                        fcf_ackreq=1,
                                                        fcf_panidcompress=1,
                                                        fcf_destaddrmode=2,
                                                        fcf_srcaddrmode=3,
                                                        seqnum=self.sequence_numbers["mac_seq"] & 0xFF
                                                    ) / Dot15d4Data(
                                                        dest_panid=self.config["pan_id"],
                                                        dest_addr=self.config["coord_addr"],
                                                        src_addr=self.config["ieee_address"]
                                                    ) / ZigbeeNWK(
                                                        frametype=1,
                                                        flags="extended_src",
                                                        destination=self.config["coord_addr"],
                                                        source=self.config["short_address"],
                                                        radius=1,
                                                        seqnum=self.sequence_numbers["nwk_seq"] & 0xFF,
                                                        ext_src=self.config["ieee_address"],
                                                        #TODO: save coord_ieee address from beacon
                                                        ext_dst=self.config["coord_ieee"]
                                                    ) / ZigbeeNWKCommandPayload(
                                                        cmd_identifier="rejoin request",
                                                        security_capability=0,
                                                        allocate_address=1,
                                                        device_type=0,
                                                        power_source=0,
                                                        receiver_on_when_idle=0,
                                                        alternate_pan_coordinator=0
                                                    ),

    'NWK_REJOIN_REQUEST_SECURE':               lambda self: Dot15d4FCS(
                                                        fcf_frametype=1,
                                                        fcf_security=0,
                                                        fcf_ackreq=1,
                                                        fcf_panidcompress=1,
                                                        fcf_destaddrmode=2,
                                                        fcf_srcaddrmode=3,
                                                        seqnum=self.sequence_numbers["mac_seq"] & 0xFF
                                                    ) / Dot15d4Data(
                                                        dest_panid=self.config["pan_id"],
                                                        dest_addr=self.config["coord_addr"],
                                                        src_addr=self.config["ieee_address"]
                                                    ) / ZigbeeNWK(
                                                        frametype=1,
                                                        flags="extended_src",
                                                        destination=self.config["coord_addr"],
                                                        source=self.config["short_address"],
                                                        radius=1,
                                                        seqnum=self.sequence_numbers["nwk_seq"] & 0xFF,
                                                        ext_src=self.config["ieee_address"],
                                                        #TODO: save coord_ieee address from beacon
                                                        ext_dst=self.config["coord_ieee"]
                                                    ) / ZigbeeNWKCommandPayload(
                                                        cmd_identifier="rejoin request",
                                                        security_capability=1,
                                                        allocate_address=1,
                                                        device_type=0,
                                                        power_source=0,
                                                        receiver_on_when_idle=0,
                                                        alternate_pan_coordinator=0
                                                    ),

    'ZDO_NODE_DESCRIPTOR_REQUEST':      lambda self: Dot15d4FCS(
                                                        fcf_frametype=1,
                                                        fcf_security=0,
                                                        fcf_ackreq=1,
                                                        fcf_panidcompress=1,
                                                        fcf_destaddrmode=2,
                                                        fcf_srcaddrmode=2,
                                                        seqnum=self.sequence_numbers["mac_seq"]
                                                    )/ Dot15d4Data(
                                                        dest_panid=self.config["pan_id"],
                                                        dest_addr=self.config["coord_addr"],
                                                        src_addr=self.config["short_address"]
                                                    )/ ZigbeeNWK(
                                                        frametype=0,
                                                        destination=self.config["coord_addr"],
                                                        source=self.config["short_address"],
                                                        radius=30,
                                                        seqnum=(self.sequence_numbers["nwk_seq"] + 1) & 0xFF
                                                    )/ ZigbeeAppDataPayload(
                                                        frame_control=0,
                                                        aps_frametype=0,
                                                        delivery_mode=0,
                                                        counter=(self.sequence_numbers["aps_seq"] + 1) & 0xFF,
                                                        profile=0x0000,
                                                        cluster=0x0002,
                                                        src_endpoint=0,
                                                        dst_endpoint=0
                                                    )/ Raw(bytes([self.sequence_numbers["zdo_tsn"] & 0xFF]) + self.config["coord_addr"].to_bytes(2, "little")),

    'APS_TRANSPORT_KEY':                  lambda self: Dot15d4FCS(
                                                        fcf_frametype = 1,
                                                        fcf_security=0,
                                                        fcf_ackreq=1,
                                                        fcf_panidcompress=1,
                                                        fcf_destaddrmode=2,
                                                        fcf_srcaddrmode=2,
                                                        seqnum=self.sequence_numbers["mac_seq"] & 0xFF
                                                    )/ Dot15d4Data(
                                                        dest_panid=self.config["pan_id"],
                                                        dest_addr=self.config["coord_addr"],
                                                        src_addr=self.config["short_address"]
                                                    )/ ZigbeeNWK(
                                                        frametype = 0,
        #     print(f"Handler name: {handler_name}")
                                                        destination=self.config["coord_addr"],
                                                        source=self.config["short_address"],
                                                        radius=30,
                                                        seqnum=self.sequence_numbers["nwk_seq"] & 0xFF
                                                    )/ ZigbeeAppDataPayload(
                                                        frame_control=4,
                                                        aps_frametype=1,
                                                        delivery_mode=0,
                                                        counter=self.sequence_numbers["aps_seq"] & 0xFF
                                                    )/ ZigbeeAppCommandPayload(
                                                        cmd_identifier=0x08,
                                                        key_type=0x01
                                                    ),

    'APS_REQUEST_KEY':                lambda self: Dot15d4FCS(
                                                        fcf_frametype = 1,
                                                        fcf_security=0,
                                                        fcf_ackreq=1,
                                                        fcf_panidcompress=1,
                                                        fcf_destaddrmode=2,
                                                        fcf_srcaddrmode=2,
                                                        seqnum=self.sequence_numbers["mac_seq"] & 0xFF
                                                    )/ Dot15d4Data(
                                                        dest_panid=self.config["pan_id"],
                                                        dest_addr=self.config["coord_addr"],
                                                        src_addr=self.config["short_address"]
                                                    )/ ZigbeeNWK(
                                                        frametype = 0,
                                                        destination=self.config["coord_addr"],
                                                        flags=0x12,
                                                        source=self.config["short_address"],
                                                        ext_src=self.config["ieee_address"],
                                                        radius=30,
                                                        seqnum=self.sequence_numbers["nwk_seq"] & 0xFF
                                                    )/ ZigbeeAppDataPayload(
                                                        aps_frametype=1,
                                                        delivery_mode=0,
                                                        frame_control=6,
                                                        counter=self.sequence_numbers["aps_seq"] & 0xFF
                                                    )/ ZigbeeAppCommandPayload(
                                                        cmd_identifier=0x08,
                                                        key_type=0x04
                                                    ),

    'APS_CONFIRM_KEY':                   lambda self: Dot15d4FCS(fcf_frametype = 1)
                                                    / Dot15d4Data()
                                                    / ZigbeeNWK(frametype = 1)
                                                    / ZigbeeSecurityHeader()
                                                    / ZigbeeAppCommandPayload(cmd_identifier = 15),

    'APS_VERIFY_KEY':                  lambda self: Dot15d4FCS(
                                                        fcf_frametype = 1,
                                                        fcf_security=0,
                                                        fcf_ackreq=1,
                                                        fcf_panidcompress=1,
                                                        fcf_destaddrmode=2,
                                                        fcf_srcaddrmode=2,
                                                        seqnum=self.sequence_numbers["mac_seq"] & 0xFF
                                                    )/ Dot15d4Data(
                                                        dest_panid=self.config["pan_id"],
                                                        dest_addr=self.config["coord_addr"],
                                                        src_addr=self.config["short_address"]
                                                    )/ ZigbeeNWK(
                                                        frametype = 0,
                                                        destination=self.config["coord_addr"],
                                                        flags='extended_src',
                                                        source=self.config["short_address"],
                                                        ext_src=self.config["ieee_address"],
                                                        radius=30,
                                                        seqnum=self.sequence_numbers["nwk_seq"] & 0xFF
                                                    )/ ZigbeeAppDataPayload(
                                                        aps_frametype=1,
                                                        delivery_mode=0,
                                                        frame_control=6,
                                                        counter=self.sequence_numbers["aps_seq"] & 0xFF
                                                    )/ ZigbeeAppCommandPayload(
                                                        key_type=0x04,
                                                        address=self.config["ieee_address"],
                                                        cmd_identifier=0x0F,
                                                        key_hash=0
                                                    ),

    'ZDO_DEVICE_ANNOUNCE':              lambda self: Dot15d4FCS(
                                                        fcf_frametype = 1,
                                                        fcf_security=0,
                                                        fcf_ackreq=0,
                                                        fcf_panidcompress=1,
                                                        fcf_destaddrmode=2,
                                                        fcf_srcaddrmode=2,
                                                        seqnum=self.sequence_numbers["mac_seq"] & 0xFF
                                                    )/ Dot15d4Data(
                                                        dest_panid=self.config["pan_id"],
                                                        dest_addr=0xFFFF,
                                                        src_addr=self.config["short_address"]
                                                    )/ ZigbeeNWK(
                                                        frametype = 0,
                                                        destination=0xFFFD,
                                                        source=self.config["short_address"],
                                                        radius=30,
                                                        seqnum=self.sequence_numbers["nwk_seq"] & 0xFF
                                                    )/ ZigbeeAppDataPayload(
                                                        frame_control=0x00,
                                                        aps_frametype=0,
                                                        delivery_mode=2,
                                                        counter=self.sequence_numbers["aps_seq"] & 0xFF,
                                                        profile=0x0000,
                                                        cluster=0x0013,
                                                        src_endpoint=0,
                                                        dst_endpoint=0
                                                    )/ Raw(bytes(self.sequence_numbers["zdo_tsn"] & 0xFF)
                                                            + self.config["short_address"].to_bytes(2,"little")
                                                            + self.config["ieee_address"].to_bytes(8, "little")
                                                            + bytes([0x6C & 0xFF])),

    'ZCL_READ_ATTRIBUTES':              lambda self: Dot15d4FCS(
                                                        fcf_frametype = 0,
                                                        fcf_security=0,
                                                        fcf_ackreq=0,
                                                        fcf_panidcompress=1,
                                                        fcf_destaddrmode=2,
                                                        fcf_srcaddrmode=2,
                                                        seqnum=self.sequence_numbers["mac_seq"] & 0xFF
                                                    )/ Dot15d4Data(
                                                        dest_panid=self.config["pan_id"],
                                                        dest_addr=self.config["coord_addr"],
                                                        src_addr=self.config["short_address"]
                                                    )/ ZigbeeNWK(
                                                        frametype=0,
                                                        proto_version=2,
                                                        source=0x0000,
                                                        destination=self.config["coord_addr"],
                                                        radius=30
                                                    )/ ZigbeeAppDataPayload(
                                                        profile=0x0104,
                                                        cluster=0x0000,
                                                        src_endpoint=0,
                                                        dst_endpoint=0
                                                    ),

    'ZCL_DISCOVER_ATTRIBUTES':          lambda self: Dot15d4FCS(
                                                        fcf_frametype = 0,
                                                        fcf_security=0,
                                                        fcf_ackreq=0,
                                                        fcf_panidcompress=1,
                                                        fcf_destaddrmode=2,
                                                        fcf_srcaddrmode=2,
                                                        seqnum=self.sequence_numbers["mac_seq"] & 0xFF
                                                    )/ Dot15d4Data(
                                                        dest_panid=self.config["pan_id"],
                                                        dest_addr=self.config["coord_addr"],
                                                        src_addr=self.config["short_address"]
                                                    )/ ZigbeeNWK(
                                                        frametype=0,
                                                        proto_version=2,
                                                        source=self.config["short_address"],
                                                        destination=self.config["coord_addr"],
                                                        radius=30
                                                    )/ ZigbeeAppDataPayload(
                                                        profile=0x0104,
                                                        cluster=0x0000,
                                                        src_endpoint=0,
                                                        dst_endpoint=0
                                                    )/ Raw(
                                                        b"\x00"
                                                        b"\x02"
                                                        b"\x0C"
                                                        b"\x00\x00"
                                                        b"\x05"
                                                    )

    # 'ZDO_ACTIVE_ENDPOINT_REQUEST'
}

