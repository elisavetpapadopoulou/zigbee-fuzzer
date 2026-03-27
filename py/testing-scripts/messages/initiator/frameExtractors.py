from os import pathconf_names
from scapy.layers.dot15d4 import Dot15d4, Dot15d4Beacon, Dot15d4Cmd, Dot15d4CmdAssocResp
from scapy.layers.zigbee import ZigbeeNWK, ZigbeeAppDataPayload, ZigbeeAppCommandPayload, ZigbeeNWKCommandPayload

"""
Predicates that determine the type of frame our fuzzer received from the SUT.
"""
def _handlers(self, pkt):
    if Dot15d4Beacon in pkt:
        return "MAC_BEACON"

    elif Dot15d4CmdAssocResp in pkt:
        return "MAC_ASSOCIATION_RESPONSE"

    elif ZigbeeAppDataPayload in pkt:
        aps = pkt[ZigbeeAppDataPayload]
        if getattr(aps, "aps_frametype", None) == 2:
            return "APS_ACK"
        elif getattr(aps, "aps_frametype", None) == 0 :
            if aps.profile == 0x0000 and int(aps.cluster) == 0x8002:
                return "ZDO_NODE_DESCRIPTOR_RESPONSE"

    elif ZigbeeAppCommandPayload in pkt:
        aps = pkt[ZigbeeAppCommandPayload]
        aps_cmd = int(getattr(aps, "cmd_identifier", 0))
        if aps_cmd == 0x05:
            return "APS_TRANSPORT_KEY"
        elif aps_cmd == 0x0B:
            return "APS_UPDATE_DEVICE"

    if ZigbeeNWK in pkt and ZigbeeNWKCommandPayload in pkt:
        nwk_cmd = pkt[ZigbeeNWKCommandPayload]
        cmd_id = int(getattr(nwk_cmd, "cmd_identifier", -1))
        is_rreq = (cmd_id == 0x01)
        is_rrep = (cmd_id == 0x02)
        if is_rreq:
            return "NWK_DISCOVER_ROUTE_REQUEST"
        elif is_rrep:
            return "NWK_DISCOVER_ROUTE_REPLY"

"""
Handlers that will extract and symbolize the incoming frames
"""
def _h_mac_beacon(self, pkt):
    pan_id = getattr(pkt, "src_panid", None)
    src_short = getattr(pkt, "src_addr", None)
    association_permit = getattr(pkt, "sf_assocpermit", None)

def _h_mac_association_response(self, pkt):
    assoc_response_pl = pkt[Dot15d4CmdAssocResp]
    status = getattr(pkt, "association_status", None)
    if status == 0x00:
        short_address = getattr(pkt, "short_address", None)

def _h_aps_ack(self, pkt):
    pass

def _h_zdo_node_descriptor_response(self, pkt):
    pass

def _h_aps_transport_key(self, pkt):
    pass

def _h_aps_update_device(self, pkt):
    if ZigbeeAppDataPayload in pkt:
        aps = pkt[ZigbeeAppDataPayload]
        return int(getattr(aps, "cmd_identifier", 0)) == 0x0B

def _h_nwk_route_request(self, pkt):
    if ZigbeeNWK in pkt and ZigbeeNWKCommandPayload in pkt:
        nwk = pkt[ZigbeeNWK]
        cmd = pkt[ZigbeeNWKCommandPayload]
        src = getattr(nwk, "source", None)
        dst = getattr(nwk, "destination", None)
        dest_addr = getattr(cmd, "destination_address", None)
        many_to_one = getattr(cmd, "many_to_one", None)


def _h_nwk_route_reply(self, pkt):
    if ZigbeeNWK in pkt and ZigbeeNWKCommandPayload in pkt:
        cmd = pkt[ZigbeeNWKCommandPayload]
        originator = getattr(cmd, "originator_address", None)
        responder = getattr(cmd, "responder_address", None)

