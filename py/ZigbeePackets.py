from scapy import config
from scapy.layers.dot15d4 import *
from scapy.layers.zigbee import *
from scapy.packet import Raw

from ZigbeeEncryption import zigbee_hmac

def build_zdo_node_descriptor_payload(self):
    tsn = getattr(self, "last_zdo_tsn", self.sequence_numbers["zdo_tsn"] & 0xFF)

    status = 0x00

    nwk_addr_of_interest = self.config["short_address"]
    byte0 = 0x02
    byte1 = 0x08
    mac_capability = 0x0c

    manufacturer_code = 0x1234
    max_buffer_size = 0x50
    max_incoming_transfer_size = 0x0050
    server_mask = 0x0000
    max_outgoing_transfer_size = 0x0050
    descriptor_capability = 0x00

    node_descriptor = (
        bytes([byte0]) +
        bytes([byte1]) +
        bytes([mac_capability]) +
        manufacturer_code.to_bytes(2, "little") +
        bytes([max_buffer_size]) +
        max_incoming_transfer_size.to_bytes(2, "little") +
        server_mask.to_bytes(2, "little") +
        max_outgoing_transfer_size.to_bytes(2, "little") +
        bytes([descriptor_capability])
    )

    zdo_payload = (
        bytes([tsn]) +
        bytes([status]) +
        nwk_addr_of_interest.to_bytes(2, "little") +
        node_descriptor
    )

    return zdo_payload

def build_zdo_extended_address_payload(self):
    tsn = getattr(self, "last_zdo_tsn", self.sequence_numbers["zdo_tsn"] & 0xFF)

    # Usually the requester is the coordinator, but better if you stored the actual source
    dst_addr = getattr(self, "last_zdo_request_src", self.config["coord_addr"])

    status = 0x00
    ieee_addr = self.config["ieee_address"]
    nwk_addr = self.config["short_address"]

    zdo_payload = (
        bytes([tsn]) +
        bytes([status]) +
        ieee_addr.to_bytes(8, "little") +
        nwk_addr.to_bytes(2, "little")
    )

    return zdo_payload

def build_zdo_active_endpoint_response(self):
    tsn = getattr(self, "last_zdo_tsn", self.sequence_numbers["zdo_tsn"] & 0xFF)
    dst_addr = getattr(self, "last_zdo_request_src", self.config["coord_addr"])

    nwk_addr = self.config["short_address"]

    # Minimal endpoint list: pretend we have endpoint 1
    active_eps = [1]

    zdo_payload = (
        bytes([tsn]) +
        bytes([0x00]) +  # status = success
        nwk_addr.to_bytes(2, "little") +
        bytes([len(active_eps)]) +
        bytes(active_eps)
    )

    return zdo_payload

def build_zdo_simple_descriptor_response(self):
    tsn = getattr(self, "last_zdo_tsn", self.sequence_numbers["zdo_tsn"] & 0xFF)
    dst_addr = getattr(self, "last_zdo_request_src", self.config["coord_addr"])
    nwk_addr = self.config["short_address"]

    endpoint = 0x01
    profile_id = 0x0104
    device_id = 0x0000
    device_version = 0x00

    input_clusters = [0x0000]
    output_clusters = []

    simple_desc = (
        bytes([endpoint]) +
        profile_id.to_bytes(2, "little") +
        device_id.to_bytes(2, "little") +
        bytes([device_version & 0x0F]) +
        bytes([len(input_clusters)]) +
        b"".join(c.to_bytes(2, "little") for c in input_clusters) +
        bytes([len(output_clusters)]) +
        b"".join(c.to_bytes(2, "little") for c in output_clusters)
    )

    zdo_payload = (
        bytes([tsn]) +
        bytes([0x00]) +
        nwk_addr.to_bytes(2, "little") +
        bytes([len(simple_desc)]) +
        simple_desc
    )

    return zdo_payload

def build_zcl_read_attributes_payload(self):
    dst_addr = getattr(self, "last_zcl_request_src", self.config["coord_addr"])
    src_ep = getattr(self, "last_zcl_dst_endpoint", 1)
    dst_ep = getattr(self, "last_zcl_src_endpoint", 1)
    zcl_seq = getattr(self, "last_zcl_seq", 0)

    manufacturer_name = b"TestVendor"
    model_identifier = b"TestNode1"

    # ZCL frame:
    # [frame control][transaction seq][command id]
    # command id 0x01 = Read Attributes Response
    zcl_header = bytes([
        0x18,       # frame type: profile-wide, direction: server->client, disable default response
        zcl_seq,    # must match incoming ZCL seq
        0x01        # Read Attributes Response
    ])

    # Attribute 0x0004: Manufacturer Name
    attr_0004 = (
        (0x0004).to_bytes(2, "little") +
        bytes([0x00]) +          # status = success
        bytes([0x42]) +          # data type = character string
        bytes([len(manufacturer_name)]) +
        manufacturer_name
    )

    # Attribute 0x0005: Model Identifier
    attr_0005 = (
        (0x0005).to_bytes(2, "little") +
        bytes([0x00]) +          # status = success
        bytes([0x42]) +          # data type = character string
        bytes([len(model_identifier)]) +
        model_identifier
    )

    zcl_payload = zcl_header + attr_0004 + attr_0005
    return zcl_payload



PACKET_TEMPLATES = {
    'MAC_BEACON':                       lambda self: Dot15d4(fcf_frametype = 0)
                                                    / Dot15d4Beacon(),

    'MAC_ASSOCIATION_REQUEST':          lambda self: Dot15d4(
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
                                                        alternate_pan_coordinator=0,
                                                        power_source=1,
                                                        receiver_on_when_idle=1,
                                                        device_type=0,
                                                        security_capability=1,
                                                        allocate_address=1
                                                    ),
    'MAC_ASSOCIATION_RESPONSE':         lambda self: Dot15d4(fcf_frametype = 1)
                                                    / Dot15d4Data()
                                                    / Dot15d4Cmd(cmd_id = 2)
                                                    / Dot15d4CmdAssocResp(),
    'MAC_DISASSOCIATION_NOTIFY':    lambda self: Dot15d4(
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

    'MAC_DATA_REQUEST':                 lambda self: Dot15d4(
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
    'MAC_PAN_ID_CONFLICT_NOTIFY':           lambda self: Dot15d4(
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

    'MAC_ORPHAN_NOTIFY':                lambda self: Dot15d4(
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

    'MAC_BEACON_REQUEST':               lambda self: Dot15d4(
                                                        fcf_panidcompress=0,
                                                        fcf_ackreq=1,
                                                        fcf_security=0,
                                                        fcf_frametype=3,
                                                        fcf_srcaddrmode=0,
                                                        fcf_framever=0,
                                                        fcf_destaddrmode=2,
                                                        seqnum=self.sequence_numbers["mac_seq"]
                                                    )/ Dot15d4Cmd(
                                                        cmd_id = 0x07,
                                                        dest_panid = self.config["pan_id"],
                                                        dest_addr = self.config["coord_addr"],
                                                        # src_addr = self.config["ieee_address"]
                                                    ),
    'MAC_COORDINATOR_REALIGN':          lambda self: Dot15d4(fcf_frametype = 1)
                                                    / Dot15d4Data()
                                                    / Dot15d4Cmd(cmd_id = 8)
                                                    / Dot15d4CmdCoordRealign(),
    'MAC_GTS_REQUEST':                  lambda self: Dot15d4(
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

    'MAC_ACK':                          lambda self: Dot15d4(fcf_frametype = 2),

    # ****************************************** APS *****************************************

    'APS_TRANSPORT_NWK_KEY':            lambda self: Dot15d4(fcf_frametype = 1)
                                                    / Dot15d4Data() / ZigbeeNWK(frametype = 1)
                                                    / ZigbeeSecurityHeader()
                                                    / ZigbeeAppCommandPayload(cmd_identifier = 5),
    'APS_ACK':                          lambda self: Dot15d4(
                                                        fcf_frametype=1,
                                                        fcf_ackreq=0,
                                                        fcf_panidcompress=1,
                                                        fcf_destaddrmode=2,
                                                        fcf_srcaddrmode=2,
                                                        seqnum=self.sequence_numbers["mac_seq"] & 0xFF
                                                    )/ Dot15d4Data(
                                                        dest_panid=self.config["pan_id"],
                                                        dest_addr=0x0000,
                                                        src_addr=self.config["short_address"]
                                                    )/ ZigbeeNWK(
                                                        frametype=0,
                                                        destination=0x0000,
                                                        source=self.config["short_address"],
                                                        radius=30,
                                                        seqnum=self.sequence_numbers["nwk_seq"] & 0xFF
                                                    )/ ZigbeeAppDataPayload(
                                                        frame_control=['ack_format'],
                                                        aps_frametype=2,
                                                        delivery_mode=0,
                                                        counter=2 & 0xFF,
                                                    ),


    'APS_TRANSPORT_KEY':                  lambda self: Dot15d4(
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

    'APS_REQUEST_TCLK':                lambda self: Dot15d4(
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
                                                        flags=["extended_src"],
                                                        destination=self.config["coord_addr"],
                                                        source=self.config["short_address"],
                                                        ext_src=self.config["ieee_address"],
                                                        radius=30,
                                                        seqnum=self.sequence_numbers["nwk_seq"] & 0xFF
                                                    )/ ZigbeeAppDataPayload(
                                                        aps_frametype=1,
                                                        delivery_mode=0,
                                                        frame_control=['security', 'ack_req'],
                                                        counter=self.sequence_numbers["aps_seq"] & 0xFF
                                                    )/ ZigbeeAppCommandPayload(
                                                        cmd_identifier=0x08,
                                                        key_type=0x04
                                                    ),

    'APS_REQUEST_NWK_KEY':                lambda self: Dot15d4(
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
                                                        flags=["extended_src"],
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
                                                        key_type=0x01
                                                    ),

    'APS_CONFIRM_KEY':                   lambda self: Dot15d4(fcf_frametype = 1)
                                                    / Dot15d4Data()
                                                    / ZigbeeNWK(frametype = 1)
                                                    / ZigbeeSecurityHeader()
                                                    / ZigbeeAppCommandPayload(cmd_identifier = 15),

    'APS_VERIFY_TCLK':                  lambda self: Dot15d4(
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

    'APS_VERIFY_GLOBAL_KEY':                  lambda self: Dot15d4(
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

    # ******************************************* NWK *****************************************

    'NWK_ROUTE_REPLY':                  lambda self: Dot15d4(
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
                                                        cmd_identifier="rejoin request",
                                                        # route_request_identifier=rri,
                                                        originator_address=self.config["coord_addr"],
                                                        responder_address=self.config["short_address"],
                                                        path_cost=1
                                                    ),


    'NWK_REJOIN_REQUEST_TC':               lambda self: Dot15d4(
                                                        fcf_frametype=1,
                                                        fcf_security=0,
                                                        fcf_ackreq=0,
                                                        fcf_panidcompress=1,
                                                        fcf_destaddrmode=2,
                                                        fcf_srcaddrmode=2,
                                                        seqnum=self.sequence_numbers["mac_seq"] & 0xFF
                                                    ) / Dot15d4Data(
                                                        dest_panid=self.config["pan_id"],
                                                        dest_addr=self.config["coord_addr"],
                                                        src_addr=0xFFFE
                                                    ) / ZigbeeNWK(
                                                        frametype=1,
                                                        flags=["extended_src"],
                                                        destination=0xFFFC,
                                                        source=0xFFFE,
                                                        radius=1,
                                                        seqnum=self.sequence_numbers["nwk_seq"] & 0xFF,
                                                        ext_src=self.config["ieee_address"],
                                                        #TODO: save coord_ieee address from beacon
                                                        # ext_dst=self.config["coord_ieee"]
                                                    ) / ZigbeeNWKCommandPayload(
                                                        cmd_identifier="rejoin request",
                                                        alternate_pan_coordinator=0,
                                                        power_source=1,
                                                        receiver_on_when_idle=1,
                                                        device_type=0,
                                                        security_capability=0,
                                                        allocate_address=1
                                                    ),

    'NWK_REJOIN_REQUEST_SECURE':               lambda self: Dot15d4(
                                                        fcf_frametype=1,
                                                        fcf_security=0,
                                                        fcf_ackreq=1,
                                                        fcf_panidcompress=1,
                                                        fcf_destaddrmode=2,
                                                        fcf_srcaddrmode=2,
                                                        seqnum=self.sequence_numbers["mac_seq"] & 0xFF
                                                    ) / Dot15d4Data(
                                                        dest_panid=self.config["pan_id"],
                                                        dest_addr=self.config["coord_addr"],
                                                        src_addr=self.config["short_address"]
                                                    ) / ZigbeeNWK(
                                                        frametype=1,
                                                        flags=["extended_src", "security"],
                                                        destination=0xFFFC,
                                                        source=self.config["short_address"],
                                                        radius=1,
                                                        seqnum=self.sequence_numbers["nwk_seq"] & 0xFF,
                                                        ext_src=self.config["ieee_address"],
                                                        #TODO: save coord_ieee address from beacon
                                                        # ext_dst=self.config["coord_ieee"]
                                                    ) / ZigbeeNWKCommandPayload(
                                                        cmd_identifier="rejoin request",
                                                        alternate_pan_coordinator=0,
                                                        power_source=1,
                                                        receiver_on_when_idle=1,
                                                        device_type=0,
                                                        security_capability=1,
                                                        allocate_address=1
                                                    ),

    # ************************************ ZDO *****************************************
    'ZDO_NODE_DESCRIPTOR_REQUEST_UNENCRYPTED':  lambda self: Dot15d4(
                                                        fcf_frametype=1,
                                                        fcf_security=0,
                                                        fcf_ackreq=1,
                                                        fcf_panidcompress=1,
                                                        fcf_destaddrmode=2,
                                                        fcf_srcaddrmode=3,
                                                        seqnum=self.sequence_numbers["mac_seq"]
                                                    )/ Dot15d4Data(
                                                        dest_panid=self.config["pan_id"],
                                                        dest_addr=self.config["coord_addr"],
                                                        src_addr=self.config["short_address"]
                                                    )/ ZigbeeNWK(
                                                        frametype=0,
                                                        flags=['extended_src'],
                                                        destination=self.config["coord_addr"],
                                                        source=self.config["short_address"],
                                                        ext_src=self.config["ieee_address"],
                                                        radius=30,
                                                        seqnum=(self.sequence_numbers["nwk_seq"]) & 0xFF
                                                    )/ ZigbeeAppDataPayload(
                                                        frame_control=0,
                                                        aps_frametype=0,
                                                        delivery_mode=0,
                                                        counter=(self.sequence_numbers["aps_seq"]) & 0xFF,
                                                        profile=0x0000,
                                                        cluster=0x0002,
                                                        src_endpoint=0,
                                                        dst_endpoint=0
                                                    )/ Raw(bytes([self.sequence_numbers["zdo_tsn"] & 0xFF]) + self.config["coord_addr"].to_bytes(2, "little")),


    'ZDO_NODE_DESCRIPTOR_RESPONSE':      lambda self: Dot15d4(
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
                                                        seqnum=(self.sequence_numbers["nwk_seq"]) & 0xFF
                                                    )/ ZigbeeAppDataPayload(
                                                        frame_control=0,
                                                        aps_frametype=0,
                                                        delivery_mode=0,
                                                        counter=(self.sequence_numbers["aps_seq"]) & 0xFF,
                                                        profile=0x0000,
                                                        cluster=0x8002,
                                                        src_endpoint=0,
                                                        dst_endpoint=0
                                                    )/ Raw(build_zdo_node_descriptor_payload(self)),

    'ZDO_EXTENDED_ADDRESS_RESPONSE':      lambda self: Dot15d4(
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
                                                        seqnum=(self.sequence_numbers["nwk_seq"]) & 0xFF
                                                    )/ ZigbeeAppDataPayload(
                                                        frame_control=0,
                                                        aps_frametype=0,
                                                        delivery_mode=0,
                                                        counter=(self.sequence_numbers["aps_seq"]) & 0xFF,
                                                        profile=0x0000,
                                                        cluster=0x8001,
                                                        src_endpoint=0,
                                                        dst_endpoint=0
                                                    )/ Raw(build_zdo_extended_address_payload(self)),


    'ZDO_NODE_DESCRIPTOR_REQUEST':      lambda self: Dot15d4(
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
                                                        seqnum=(self.sequence_numbers["nwk_seq"]) & 0xFF
                                                    )/ ZigbeeAppDataPayload(
                                                        frame_control=0,
                                                        aps_frametype=0,
                                                        delivery_mode=0,
                                                        counter=(self.sequence_numbers["aps_seq"]) & 0xFF,
                                                        profile=0x0000,
                                                        cluster=0x0002,
                                                        src_endpoint=0,
                                                        dst_endpoint=0
                                                    )/ Raw(bytes([self.sequence_numbers["zdo_tsn"] & 0xFF]) + self.config["coord_addr"].to_bytes(2, "little")),

    'ZDO_SIMPLE_DESCRIPTOR_RESPONSE':      lambda self: Dot15d4(
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
                                                        seqnum=(self.sequence_numbers["nwk_seq"]) & 0xFF
                                                    )/ ZigbeeAppDataPayload(
                                                        frame_control=0,
                                                        aps_frametype=0,
                                                        delivery_mode=0,
                                                        counter=(self.sequence_numbers["aps_seq"]) & 0xFF,
                                                        profile=0x0000,
                                                        cluster=0x8004,
                                                        src_endpoint=0,
                                                        dst_endpoint=0
                                                    )/ Raw(build_zdo_simple_descriptor_response(self)),

    'ZDO_SIMPLE_DESCRIPTOR_REQUEST':      lambda self: Dot15d4(
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
                                                        seqnum=(self.sequence_numbers["nwk_seq"]) & 0xFF
                                                    )/ ZigbeeAppDataPayload(
                                                        frame_control=0,
                                                        aps_frametype=0,
                                                        delivery_mode=0,
                                                        counter=(self.sequence_numbers["aps_seq"]) & 0xFF,
                                                        profile=0x0000,
                                                        cluster=0x0004,
                                                        src_endpoint=0,
                                                        dst_endpoint=0
                                                    )/ Raw(bytes([self.sequence_numbers["zdo_tsn"] & 0xFF]) + self.config["coord_addr"].to_bytes(2, "little")),


    'ZDO_MGMT_LQI_REQ':                       lambda self: Dot15d4(
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
                                                        seqnum=(self.sequence_numbers["nwk_seq"]) & 0xFF
                                                    )/ ZigbeeAppDataPayload(
                                                        frame_control=0,
                                                        aps_frametype=0,
                                                        delivery_mode=0,
                                                        counter=(self.sequence_numbers["aps_seq"]) & 0xFF,
                                                        profile=0x0000,
                                                        cluster=0x00031,
                                                        src_endpoint=0,
                                                        dst_endpoint=0
                                                    )/ Raw(bytes([self.sequence_numbers["zdo_tsn"] & 0xFF]) + self.config["coord_addr"].to_bytes(2, "little")),

    'ZDO_DEVICE_ANNOUNCE':              lambda self: Dot15d4(
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
                                                    )/ Raw(bytes([self.sequence_numbers["zdo_tsn"] & 0xFF])
                                                            + self.config["short_address"].to_bytes(2,"little")
                                                            + self.config["ieee_address"].to_bytes(8, "little")
                                                            + bytes([0x6C & 0xFF])),

    'ZDO_ACTIVE_ENDPOINT_RESPONSE':             lambda self: Dot15d4(
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
                                                        seqnum=(self.sequence_numbers["nwk_seq"]) & 0xFF
                                                    )/ ZigbeeAppDataPayload(
                                                        frame_control=0,
                                                        aps_frametype=0,
                                                        delivery_mode=0,
                                                        counter=(self.sequence_numbers["aps_seq"]) & 0xFF,
                                                        profile=0x0000,
                                                        cluster=0x8005,
                                                        src_endpoint=0,
                                                        dst_endpoint=0
                                                    )/ Raw(build_zdo_active_endpoint_response(self)),

    # ******************************************* ZCL *****************************************
    'ZCL_READ_ATTRIBUTES':              lambda self: Dot15d4(
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

    'ZCL_READ_ATTRIBUTES_RESPONSE':              lambda self: Dot15d4(
                                                        fcf_frametype=1,
                                                        fcf_security=0,
                                                        fcf_ackreq=1,
                                                        fcf_panidcompress=1,
                                                        fcf_destaddrmode=2,
                                                        fcf_srcaddrmode=2,
                                                        seqnum=self.sequence_numbers["mac_seq"],
                                                    )
                                                    / Dot15d4Data(
                                                        dest_panid=self.config["pan_id"],
                                                        dest_addr=self.config["coord_addr"],
                                                        src_addr=self.config["short_address"],
                                                    )
                                                    / ZigbeeNWK(
                                                        frametype=0,
                                                        destination=self.config["coord_addr"],
                                                        source=self.config["short_address"],
                                                        radius=30,
                                                        seqnum=self.sequence_numbers["nwk_seq"] & 0xFF,
                                                    )
                                                    / ZigbeeAppDataPayload(
                                                        frame_control=0,
                                                        aps_frametype=0,
                                                        delivery_mode=0,
                                                        counter=self.sequence_numbers["aps_seq"] & 0xFF,
                                                        profile=0x0104,      # Home Automation
                                                        cluster=0x0000,      # Basic cluster
                                                        src_endpoint=getattr(self, "last_zcl_dst_endpoint", 1),
                                                        dst_endpoint=getattr(self, "last_zcl_src_endpoint", 1),
                                                    )
                                                    / Raw(build_zcl_read_attributes_payload(self)
                                                ),


    'ZCL_DISCOVER_ATTRIBUTES':          lambda self: Dot15d4(
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
                                                    ),
}

