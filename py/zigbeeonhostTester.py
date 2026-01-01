import threading
from time import sleep
from Cryptodome.Cipher import AES
import struct

from scapy.all import conf, raw
from scapy.packet import Packet
from scapy.layers.dot15d4 import Dot15d4CmdDisassociation, Dot15d4CmdGTSReq, Dot15d4FCS, Dot15d4Data, Dot15d4Ack, Dot15d4CmdAssocReq, Dot15d4Cmd
from scapy.layers.zigbee import ZigbeeAppDataPayload, ZigbeeDeviceProfile, ZigbeeNWK, ZigbeeNWKCommandPayload, ZigbeeSecurityHeader, ZigbeeAppCommandPayload
# from ZbossSimulatorDriver import *
from zigbeeOnHostDriver import zigbeeOnHostDriver
from scapy.packet import Raw

SEC_LEVEL_MASK = 0x07
ENC_MIC32 = 0x05

conf.dot15d4_protocol = "zigbee"

MIC_len = {
        0: 0,
        1: 4,
        2: 8,
        3: 16,
        4: 0,
        5: 4,
        6: 8,
        7: 16
        }
def _sec_owner(pkt):
    sec = pkt.getlayer(ZigbeeSecurityHeader)
    if not sec:
        return None
    return type(sec.underlayer)

def _mk_mac_ll(pkt):
    mac0 = pkt[Dot15d4FCS]
    ll0  = pkt[Dot15d4Data]
    mac = Dot15d4FCS(
        fcf_frametype     = mac0.fcf_frametype,
        fcf_security      = mac0.fcf_security,
        fcf_ackreq        = mac0.fcf_ackreq,
        fcf_panidcompress = mac0.fcf_panidcompress,
        fcf_destaddrmode  = mac0.fcf_destaddrmode,
        fcf_srcaddrmode   = mac0.fcf_srcaddrmode,
        fcf_framever      = mac0.fcf_framever,
        seqnum            = mac0.seqnum & 0xFF,
    )
    ll = Dot15d4Data(
        dest_panid = ll0.dest_panid,
        dest_addr  = ll0.dest_addr,
        src_addr   = ll0.src_addr,
    )
    return mac, ll

def is_nwk_link_status(pkt_plain):
    nwk = pkt_plain.getlayer(ZigbeeNWK)
    if not nwk or nwk.frametype != 1: return False
    cmd = pkt_plain.getlayer(ZigbeeNWKCommandPayload)
    return getattr(cmd, "cmd_identifier", None) == 0x08

def rebuild_plain_nwk(pkt, plaintext: bytes):
        """
        Remove ZigbeeSecurityHeader and attach the decrypted NWK payload (pt).
        Try to parse it as APS (most common), else NWK command, else Raw.
        """
        mac = pkt[Dot15d4FCS].copy()
        mac.remove_payload()
        ll  = pkt[Dot15d4Data].copy()
        ll.remove_payload()

        nwk = pkt[ZigbeeNWK].copy()
        nwk.flags = int(nwk.flags) & ~0x02
        nwk.remove_payload()

        if int(nwk.frametype) == 0:
            decrypted_layer = ZigbeeAppDataPayload(_pkt=plaintext)
        else:
            decrypted_layer = Raw(plaintext)
        return mac / ll / nwk / decrypted_layer

def rebuild_plain_aps(pkt, plaintext: bytes):
    """
    Return a new packet:
      Dot15d4 / NWK / APS(with security bit cleared) / <decrypted layer>
    """
    mac = pkt[Dot15d4FCS].copy()
    mac.remove_payload()
    ll  = pkt[Dot15d4Data].copy()
    ll.remove_payload()
    nwk = pkt[ZigbeeNWK].copy()
    nwk.remove_payload()

    aps_sec = pkt[ZigbeeAppDataPayload]
    aps_hdr = aps_sec.copy()
    aps_hdr.remove_payload()
    fc = aps_hdr.frame_control
    fc.security = 0
    aps_hdr.frame_control = fc

    aps_cmd = ZigbeeAppCommandPayload(_pkt=plaintext)

    new_pkt = mac / ll / nwk / aps_hdr / aps_cmd
    new_pkt.show2()
    return new_pkt

def build_aps_update_device(pan_id, dst_short, src_short, src_ieee,
                            mac_seq, nwk_seq, aps_seq,
                            update_status=0x00):
    return (
        Dot15d4FCS(
            fcf_frametype=1,
            fcf_security=0,
            fcf_ackreq=1,
            fcf_panidcompress=1,
            fcf_destaddrmode=2,
            fcf_srcaddrmode=2,
            seqnum=mac_seq & 0xFF
        )
        / Dot15d4Data(
            dest_panid=pan_id,
            dest_addr=dst_short,
            src_addr=src_short
        )
        / ZigbeeNWK(
            frametype=0,
            proto_version=2,
            destination=dst_short,
            source=src_short,
            flags="extended_src",
            ext_src=src_ieee,
            radius=30,
            seqnum=nwk_seq & 0xFF
        )
        / ZigbeeAppDataPayload(
            aps_frametype=1,
            delivery_mode=0,
            frame_control=6,
            counter=aps_seq & 0xFF
        )
        / ZigbeeAppCommandPayload(
            cmd_identifier=0x06
        )
        / Raw(
            src_ieee.to_bytes(8, "little") +
            src_short.to_bytes(2, "little") +
            bytes([update_status & 0xFF])
        )
    )

def build_nwk_rejoin_request(pan_id, dst_short, src_short, src_ieee, mac_seq, nwk_seq):
    return Dot15d4FCS(
                fcf_frametype=1,
                fcf_security=0,
                fcf_ackreq=1,
                fcf_panidcompress=1,
                fcf_destaddrmode=2,
                fcf_srcaddrmode=2,
                seqnum= mac_seq & 0xFF
            ) / Dot15d4Data(
                dest_panid=pan_id,
                dest_addr=dst_short,
                src_addr=src_short
            ) / ZigbeeNWK(
                frametype=1,
                flags="extended_src",
                destination=dst_short,
                source=src_short,
                radius=1,
                seqnum=nwk_seq & 0xFF,
                ext_src=src_ieee
            ) / ZigbeeNWKCommandPayload(
                cmd_identifier="rejoin request",
                security_capability=0,
                allocate_address=1,
                device_type=0,
                power_source=0,
                receiver_on_when_idle=0,
                alternate_pan_coordinator=0
            )
def build_mac_panid_conflict_notify(pan_id, dst_short, src_short, src_ieee, mac_seq):
    return Dot15d4FCS(
            fcf_frametype=3,
            fcf_security=0,
            fcf_ackreq=1,
            fcf_panidcompress=1,
            fcf_destaddrmode=2,
            fcf_srcaddrmode=2,
            seqnum=mac_seq & 0xFF
        )/Dot15d4Cmd(
            dest_panid=pan_id,
            dest_addr=dst_short,
            src_addr=src_short,
            cmd_id=0x05
        )

def build_mac_disassociation_notification(pan_id, src_ieee, mac_seq, dest_short, reason):
    reason_b = bytes([reason & 0xFF])
    return Dot15d4FCS(
            fcf_frametype=3,
            fcf_security=0,
            fcf_ackreq=1,
            fcf_panidcompress=1,
            fcf_destaddrmode=2,
            fcf_srcaddrmode=3,
            seqnum=mac_seq & 0xFF
        )/Dot15d4Cmd(
            dest_panid=pan_id,
            dest_addr=dest_short,
            src_addr=src_ieee,
            cmd_id=0x03
        )/Dot15d4CmdDisassociation(
            disassociation_reason=reason & 0xFF
        )

def build_mac_orphan_notification(pan_id, src_ieee, mac_seq, dest_short):
    return Dot15d4FCS(
            fcf_frametype=3,
            fcf_security=0,
            fcf_ackreq=1,
            fcf_panidcompress=1,
            fcf_destaddrmode=2,
            fcf_srcaddrmode=3,
            seqnum=mac_seq & 0xFF
        )/Dot15d4Cmd(
            dest_panid=pan_id,
            dest_addr=dest_short,
            src_addr=src_ieee,
            cmd_id=0x06
        )

# def build_mac_coordinator_realign(pan_id, mac_seq, coord_short, src_short, logical_channel):

def build_mac_gts_request(pan_id, coord_short, src_short, mac_seq, gts_len=1, direction=1, allocate=True):
    gts_char = (gts_len & 0x07) \
             | ((direction & 0x01) << 3) \
             | ((0 if allocate else 1) << 4)
    payload = bytes([gts_char & 0x1F])
    return Dot15d4FCS(
            fcf_frametype=3,
            fcf_security=0,
            fcf_ackreq=1,
            fcf_panidcompress=1,
            fcf_destaddrmode=2,
            fcf_srcaddrmode=2,
            seqnum=mac_seq & 0xFF
        )/Dot15d4Cmd(
            dest_panid=pan_id,
            dest_addr=coord_short,
            src_addr=src_short,
            cmd_id=0x09
        )/Dot15d4CmdGTSReq(
            gts_len=gts_len,
            gts_dir=1 if direction else 0,
            charact_type=0 if allocate else 1
        )


def build_verify_aps_key(pan_id, dst_short, src_short, src_ieee, mac_seq, nwk_seq,
                         aps_counter, tc_link_key):
    return Dot15d4FCS(
            fcf_frametype = 1,
            fcf_security=0,
            fcf_ackreq=1,
            fcf_panidcompress=1,
            fcf_destaddrmode=2,
            fcf_srcaddrmode=2,
            seqnum=mac_seq & 0xFF
        )/ Dot15d4Data(
            dest_panid=pan_id,
            dest_addr=dst_short,
            src_addr=src_short
        )/ ZigbeeNWK(
            frametype = 0,
            destination=dst_short,
            flags=0x12,
            source=src_short,
            ext_src=src_ieee,
            radius=30,
            seqnum=nwk_seq & 0xFF
        )/ ZigbeeAppDataPayload(
            aps_frametype=1,
            delivery_mode=0,
            frame_control=6,
            counter=aps_counter & 0xFF
        )/ ZigbeeAppCommandPayload(
            cmd_identifier=0x0F,
        )

def build_aps_request_key(pan_id, dst_short, src_short, src_ieee,
                          mac_seq, nwk_seq, aps_ctr, key_type):
    return Dot15d4FCS(
            fcf_frametype = 1,
            fcf_security=0,
            fcf_ackreq=1,
            fcf_panidcompress=1,
            fcf_destaddrmode=2,
            fcf_srcaddrmode=2,
            seqnum=mac_seq & 0xFF
        )/ Dot15d4Data(
            dest_panid=pan_id,
            dest_addr=dst_short,
            src_addr=src_short
        )/ ZigbeeNWK(
            frametype = 0,
            destination=dst_short,
            flags=0x12,
            source=src_short,
            ext_src=src_ieee,
            radius=30,
            seqnum=nwk_seq & 0xFF
        )/ ZigbeeAppDataPayload(
            aps_frametype=1,
            delivery_mode=0,
            frame_control=6,
            counter=aps_ctr & 0xFF
        )/ ZigbeeAppCommandPayload(
            cmd_identifier=0x08,
            key_type=key_type
        )

def build_zdo_node_descriptor_request(pan_id, src_short, aps_ctr, mac_seq, nwk_seq, zdo_tsn, target_nwk):
    return (
        Dot15d4FCS(
            fcf_frametype=1,
            fcf_security=0,
            fcf_ackreq=1,
            fcf_panidcompress=1,
            fcf_destaddrmode=2,
            fcf_srcaddrmode=2,
            seqnum=mac_seq
        )/ Dot15d4Data(
            dest_panid=pan_id,
            dest_addr=target_nwk,
            src_addr=src_short
        )/ ZigbeeNWK(
            frametype=0,
            destination=target_nwk,
            source=src_short,
            radius=30,
            seqnum=(nwk_seq + 1) & 0xFF
        )/ ZigbeeAppDataPayload(
            frame_control=4,
            aps_frametype=0,
            delivery_mode=0,
            counter=(aps_ctr + 1) & 0xFF,
            profile=0x0000,
            cluster=0x0002,
            src_endpoint=0,
            dst_endpoint=0
        )/ Raw(bytes([zdo_tsn & 0xFF]) + target_nwk.to_bytes(2, "little"))
    )


def build_zdo_device_announce(pan_id, src_short, src_ieee, aps_ctr, mac_seq, nwk_seq, cap=0x6C):
    return Dot15d4FCS(
            fcf_frametype = 1,
            fcf_security=0,
            fcf_ackreq=0,
            fcf_panidcompress=1,
            fcf_destaddrmode=2,
            fcf_srcaddrmode=2,
            seqnum=mac_seq & 0xFF
        )/ Dot15d4Data(
            dest_panid=pan_id,
            dest_addr=0xFFFF,
            src_addr=src_short
        )/ ZigbeeNWK(
            frametype = 0,
            destination=0xFFFD,
            source=src_short,
            radius=30,
            seqnum=nwk_seq & 0xFF
        )/ ZigbeeAppDataPayload(
            frame_control=0x00,
            aps_frametype=0,
            delivery_mode=0,
            counter=aps_ctr & 0xFF,
            profile=0x0000,
            cluster=0x0013,
            src_endpoint=0,
            dst_endpoint=0
        )/ Raw(src_short.to_bytes(2,"little") + src_ieee.to_bytes(8, "little") + bytes([cap & 0xFF]))

def build_nwk_route_reply(pan_id, src_short, dest_short, mac_seq, nwk_seq, rri):
    return Dot15d4FCS(
            fcf_frametype = 1,
            fcf_security=0,
            fcf_ackreq=1,
            fcf_panidcompress=1,
            fcf_destaddrmode=2,
            fcf_srcaddrmode=2,
            seqnum=mac_seq & 0xFF
        )/ Dot15d4Data(
            dest_panid=pan_id,
            dest_addr=dest_short,
            src_addr=src_short
        )/ ZigbeeNWK(
            frametype = 1,
            destination=dest_short,
            source=src_short,
            discover_route=0,
            radius=10,
            seqnum=nwk_seq & 0xFF
        )/ ZigbeeNWKCommandPayload(
            cmd_identifier="route reply",
            route_request_identifier=rri,
            originator_address=dest_short,
            responder_address=src_short,
            path_cost=1
        )

def build_mac_data_request(pan_id, dest_short, src_ieee, mac_seq):
    return Dot15d4FCS(
            fcf_frametype=3,
            fcf_security=0,
            fcf_ackreq=1,
            fcf_panidcompress=1,
            fcf_destaddrmode=2,
            fcf_srcaddrmode=3,
            seqnum=mac_seq & 0xFF
            )/ Dot15d4Cmd(
                cmd_id = 0x04,
                dest_panid=pan_id,
                dest_addr=dest_short,
                src_addr=src_ieee
            )

def build_assoc_request_raw(pan_id, dest_short, src_ieee,
                            mac_seq):
    return Dot15d4FCS(
            fcf_frametype=3,
            fcf_security=0,
            fcf_ackreq=1,
            fcf_panidcompress=1,
            fcf_destaddrmode=2,
            fcf_srcaddrmode=3,
            seqnum=mac_seq & 0xFF
            )/Dot15d4Cmd(
                dest_panid=pan_id,
                dest_addr=dest_short,
                src_addr=src_ieee,
                cmd_id=0x01
            )/Dot15d4CmdAssocReq(
                allocate_address=1,
                security_capability=1,
                device_type=0
            )

def build_beacon_request_noaddr(pan_id, dest_short, src_ieee, mac_seq=1):
    return Dot15d4FCS(
            fcf_panidcompress=1,
            fcf_ackreq=0,
            fcf_pending=0,
            fcf_security=0,
            fcf_frametype=3,
            fcf_srcaddrmode=3,
            fcf_framever=0,
            fcf_destaddrmode=2,
            seqnum=mac_seq
        )/ Dot15d4Cmd(
            dest_panid = pan_id,
            dest_addr = dest_short,
            src_addr = src_ieee,
            cmd_id = 0x07
        )


class AliveNode:
    def __init__(self):
        self.radio = zigbeeOnHostDriver()
        self.mac_seq = 1
        self.nwk_seq = 1
        self.aps_seq = 1
        self.sec_nwk_fc: int = 0x01000000
        self.sec_aps_fc: int = 0x01000000
        self.trying_association = False
        self.associated = False
        self.announcing = False
        self.requesting_aps_key = False
        self.chosen_pan = None
        self.src_short = None
        self.src_ieee = 0x79bc000000010002
        self.dest_short = 0x0000
        self.cap = 0x8E
        self.zdo_tsn = 0
        self.seen_rreq = set()
        self.tc_link_key = bytes([90,105,103,66,101,101,65,108,108,105,97,110,99,101,48,57])
        self.nwk_key = {}
        self.final = False

    def aps_encrypt(self, pkt):
        # Force APS header bits (visible)
        aps = pkt[ZigbeeAppDataPayload]
        aps.aps_frametype = 1
        aps.delivery_mode = 0
        aps.frame_control  = "security"

        # AAD header = APS header without payload
        aps_hdr = aps.copy(); aps_hdr.remove_payload()
        aps_hdr_b = bytes(aps_hdr)

        # Plaintext = APS command payload (detach from underlayers)
        cmd = aps.payload.copy(); cmd.underlayer = None
        PT = raw(cmd)

        # Counter BEFORE use
        self.sec_aps_fc = (self.sec_aps_fc + 1) & 0xFFFFFFFF
        fc_le  = self.sec_aps_fc.to_bytes(4, "little")
        src_le = int(self.src_ieee).to_bytes(8, "little")

        # SecCtrl: wire vs fixed (Zigbee quirk)
        sec_wire  = 0x20                      # extnonce=1, KIM=0, level bits 0
        sec_fixed = (sec_wire & 0xF8) | 0x05  # -> 0x25 (ENC+MIC-32) for CCM

        # Nonce & AAD (Zigator pattern)
        nonce = src_le + fc_le + bytes([sec_fixed])            # 13 bytes
        aad   = aps_hdr_b + bytes([sec_fixed]) + fc_le + src_le

        ccm = AES.new(self.tc_link_key, AES.MODE_CCM, nonce=nonce, mac_len=4)
        ccm.update(aad)
        C = ccm.encrypt(PT)
        U = ccm.digest()

        # On-wire APS aux (extnonce=1 → include src EUI)
        aps_aux_b = bytes([sec_wire]) + fc_le + src_le

        # Exact APS PDU bytes: APS header || APS aux || C || U
        aps_pdu_bytes = aps_hdr_b + aps_aux_b + C + U

        # Build packet for next step with fresh MAC/LL and a clean NWK header
        mac, ll = _mk_mac_ll(pkt)
        nwk = pkt[ZigbeeNWK].copy(); nwk.remove_payload()
        aps_pkt = mac / ll / nwk / Raw(aps_pdu_bytes)
        return aps_pkt, aps_pdu_bytes

    def nwk_encrypt(self, pkt, key_seqnum, nwk_key, my_eui64, aps_pdu_bytes):
      # Fresh MAC/LL and a clean NWK header
        mac, ll = _mk_mac_ll(pkt)

        nwk = pkt[ZigbeeNWK].copy()
        nwk.flags   = "security+extended_src"  # 0x12
        nwk.ext_src = my_eui64
        nwk.remove_payload()
        nwk_hdr_b = bytes(nwk)

        self.sec_nwk_fc = (self.sec_nwk_fc + 1) & 0xFFFFFFFF
        fc_le  = self.sec_nwk_fc.to_bytes(4, "little")
        src_le = int(my_eui64).to_bytes(8, "little")

        # SecCtrl: wire vs fixed (Zigbee quirk)
        sec_wire  = 0x28                      # extnonce=1, KIM=1, level bits 0
        # sec_fixed = (sec_wire & 0xF8) | 0x05  # -> 0x2D (ENC+MIC-32) for CCM
        sec_fixed = 0x2D

        # Nonce & AAD
        nonce = src_le + fc_le + bytes([sec_fixed])
        aad   = nwk_hdr_b + bytes([sec_fixed]) + fc_le + src_le + bytes([key_seqnum & 0xFF])

        ccm = AES.new(nwk_key, AES.MODE_CCM, nonce=nonce, mac_len=4)
        ccm.update(aad)
        C = ccm.encrypt(aps_pdu_bytes)   # ENTIRE APS PDU
        U = ccm.digest()

        # On-wire NWK aux (wire SecCtrl + FC + src + key index)
        # nwk_aux_b = bytes([sec_wire]) + fc_le + src_le + bytes([key_seqnum & 0xFF])
        nwk_aux_b = struct.pack("<B I Q B", sec_wire, self.sec_nwk_fc, int(my_eui64), key_seqnum & 0xFF)


        frame = mac / ll / nwk / Raw(nwk_aux_b + C + U)
        print(f"APS_CMD_REQUEST_KEY: {bytes(frame).hex()}")
        return frame


    def decode(self, pkt):
        sec = pkt.getlayer("ZigbeeSecurityHeader")
        if self.final and not is_nwk_link_status(pkt):
            print("APS_CMD_REQUEST_KEY")
            pkt.show2()

        # Security Control fields
        extended_nonce = int(sec.extended_nonce)
        key_id = int(sec.key_type)
        nwk_security_level = 5

        # Step 1 of Specification
        sender_address = int(sec.source).to_bytes(8, byteorder="little")
        received_frame_counter_int = int(sec.fc)
        if received_frame_counter_int == (1 << 32) - 1:
            raise ValueError("Bad Frame Counter")
        received_frame_counter = received_frame_counter_int.to_bytes(4, byteorder="little")

        # Step 2 of Specification
        # TODO If sequence_number != None match it to the sequence number of any 
        # key in the nwkSecurityMaterialSet attribute in the NIB. If the security
        # material cannot be obtained, security processing shall indicate a failure
        # to the next higher layer with a status of 'frame security failed' and no 
        # further security processing shall be done on this frame. 

        key_seqnum = sec.key_seqnum
        key = ""
        if key_id == 1:
            if self.nwk_key != {}:
                key = self.nwk_key[key_seqnum]
                keylen = len(key)
            else:
                print("NWK key not stored yet")
                return None, key_id
        elif key_id == 2:
            key = self.zigbee_hmac(b"\x00", self.tc_link_key)
        elif key_id == 3:
            key = self.zigbee_hmac(b"\x02", self.tc_link_key)
        else:
            key = self.tc_link_key

        # Step 3 of Specification: is ignored for now 
        # Step 4 of Specification
        M = MIC_len[nwk_security_level & 0x07]

        # N = CCM Nonce is a 13-octet string constructed using the:
        # a) security control (nwk_security_level + key_id + extended_nonce), 
        # b) frame counter (received_frame_counter), 
        # c) and the source address (sender_address) fields. 
        security_control = ((nwk_security_level & 0x07)
                            | ((key_id & 0x03) << 3)
                            | ((extended_nonce & 0x01) << 5))


        nonce = sender_address + received_frame_counter + bytes([security_control])


        secured_payload = bytes(sec.data)
        mic = bytes(secured_payload[-4:])

        C = secured_payload[:-4]
        U = mic
        # print(f"[DECRYPT] extended_nonce: {extended_nonce}")
        # print(f"[DECRYPT] key_id: {key_id}")
        # print(f"[DECRYPT] network_security_level: {nwk_security_level}")
        # print(f"[DECRYPT] sender_address: {sender_address.hex()}")
        # print(f"[DECRYPT] received_frame_counter: {received_frame_counter.hex()}")
        # print(f"[DECRYPT] KEY: {key}")
        # print(f"[DECRYPT] keylength: {keylen}")
        # print(f"[DECRYPT] M: {M}")
        # print(f"[DECRYPT] C: {C.hex()}")
        # print(f"[DECRYPT] security_control: {security_control}")
        # print(f"[DECRYPT] nonce: {nonce.hex()}")
        # print(f"[DECRYPT] secured_payload: {secured_payload.hex()}")
        # print(f"[DECRYPT] mic: {mic.hex()}")

        if len(U) != M:
            raise ValueError(f"MIC length mismatch: expected {M}, got {len(U)}")

        encrypted_layer = str(sec.underlayer)
        if encrypted_layer.startswith("ZigbeeApp"):
            aps = pkt.getlayer("ZigbeeAppDataPayload")
            aps_header = aps.copy()
            aps_header.remove_payload()
            aps_header = bytes(aps_header)[:2]
            aps_frame_control = aps_header[:1]
            aps_counter = aps_header[1:]

            aux = bytes([security_control]) + received_frame_counter + sender_address
            if key_id == 1:
                aux += bytes([sec.key_seqnum])
            aad = aps_header + aux

            # print(f"[DECRYPT] aps_frame_control: {aps_frame_control.hex()}")
            # print(f"[DECRYPT] aps_counter: {aps_counter.hex()}")
            # print(f"[DECRYPT] aad: {aad.hex()}")
            # print(f"[DECRYPT] aux: {aux.hex()}")

        elif encrypted_layer.startswith("ZigbeeNWK"):
            nwk = pkt.getlayer("ZigbeeNWK")
            if nwk is None:
                nwk = pkt.getlayer("Zigbee Network Layer")
            nwk_header = nwk.copy()
            nwk_header.remove_payload()
            nwk_header = bytes(nwk_header)

            aux = bytes([security_control]) + received_frame_counter
            if extended_nonce:
                aux += sender_address

            if key_id == 1:
                aux += bytes([key_seqnum])
            aad = nwk_header + aux

        cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=M)
        cipher.update(bytes(aad))
        plaintext = cipher.decrypt(C)
        cipher.verify(mic)

        print(f"[APS] Decrypted OK (key_id={key_id}, sec_ctrl_wire=0x{security_control:02x})")

        return plaintext, key_id

    def zigbee_mmo_hash(self, message):
        # Initial value for the digest of the message
        digest = bytearray.fromhex("00000000000000000000000000000000")

        # Pad the message
        padding = bytearray([0x80])
        while (len(message) + len(padding) + 2) % 16 != 0:
            padding.append(0x00)
        padding.append((8*len(message)) >> 8)
        padding.append((8*len(message)) & 0xff)
        padded_message = message + padding

        # Sanity check
        if len(padded_message) % 16 != 0:
            raise ValueError(
                    "The length of the padded message "
                    + "({}) is not a multiple of ".format(len(padded_message))
                    + "the block size ({})".format(16),
                    )

        # Compute the digest of the message
        plaintext = bytearray()
        for i in range(len(padded_message)):
            plaintext.append(padded_message[i])
            if len(plaintext) == 16:
                cipher = AES.new(key=digest, mode=AES.MODE_ECB)
                ciphertext = cipher.encrypt(plaintext)
                digest = bytearray(ciphertext)
                for j in range(16):
                    digest[j] ^= plaintext[j]
                plaintext = bytearray()

        return bytes(digest)


    def decode_all(self, pkt):
        for _ in range(2):
            owner = _sec_owner(pkt)
            if owner is None:
                break
            plaintext, key_id = self.decode(pkt)
            if plaintext is None:
                return pkt
            if owner is ZigbeeNWK:
                pkt = rebuild_plain_nwk(pkt, plaintext)
                if is_nwk_link_status(pkt):
                    return None
            elif owner is ZigbeeAppDataPayload:
                pkt = rebuild_plain_aps(pkt, plaintext)
                if key_id == 2:
                    aps_cmd = pkt.getlayer(ZigbeeAppCommandPayload)
                    if aps_cmd and hasattr(aps_cmd, "key_seqnum") and hasattr(aps_cmd, "key"):
                        self.nwk_key = {aps_cmd.key_seqnum: bytes(aps_cmd.key)}
                        self.aps_update_device()
                        sleep(15)
                        self.request_aps_key()
                        self.final = True
                else:
                    break
        return pkt

    def zigbee_hmac(self, message, key):
        # HMAC uses the following inner and outer pads
        inner_pad = 0x36
        outer_pad = 0x5c

        # Hash the key if it is longer than the block size
        if len(key) > 16:
            key = bytearray(self.zigbee_mmo_hash(key))
        else:
            key = bytearray(key)

        # Pad the key with zeros if it is shorter than the block size
        for _ in range(16 - len(key)):
            key.append(0x00)

        # Sanity check
        if len(key) != 16:
            raise ValueError(
                "The length of the key ({}) ".format(len(key))
                + "is not equal to the block size ({})".format(16),
            )

        # Compute the inner and outer keys
        inner_key = bytearray(key)
        outer_key = bytearray(key)
        for i in range(16):
            inner_key[i] ^= inner_pad
            outer_key[i] ^= outer_pad

        return self.zigbee_mmo_hash(outer_key + self.zigbee_mmo_hash(inner_key + message))


    # In your AliveNode, add this test:
    def inject_test_beacon(self):
        # Proper beacon frame matching coordinator's network
        beacon_hex = bytes([
        0x80, 0x06,
        0x71, 0x09,
        0x19,
        0x03, 0x08,  # Frame Control: MAC command, no addr
        0x01,        # Sequence  
        0xFF, 0xFF,  # Dest PAN (broadcast)
        0xFF, 0xFF,  # Dest addr (broadcast)
        0x07         # Beacon Request command
        ])
        self.radio._send(beacon_hex)

    def send_beacon_request(self):
        self.radio.enable_raw()
        sleep(10)
        pkt = build_beacon_request_noaddr(pan_id=0xFFFF, dest_short=0xFFFF, src_ieee=self.src_ieee, mac_seq=self.mac_seq & 0xFF)
        self.mac_seq += 1
        print(f"[TX] Beacon Request (no addressing): {bytes(pkt).hex(" ")}")
        self.radio.inject_air_frame_with_meta(bytes(pkt), True)

    def try_assoc(self):
        frame = build_assoc_request_raw(pan_id=self.chosen_pan, dest_short=self.dest_short, src_ieee=self.src_ieee, mac_seq=self.mac_seq & 0xFF)
        self.mac_seq += 1
        self.radio.inject_air_frame_with_meta(bytes(frame))
        print(f"Sent AssocReq --> PAN=0x{self.chosen_pan:04X}, coord=0x{self.dest_short}")
        print(f"[TX] {bytes(frame).hex()}")

    def pull_assoc(self, pan_id, dest_short):
        frame = build_mac_data_request(pan_id, dest_short, self.src_ieee, self.mac_seq)
        self.mac_seq += 1
        self.radio.inject_air_frame_with_meta(bytes(frame))
        print(f"[TX] MAC DATA REQUEST {bytes(frame).hex()}")

    def request_aps_key(self):
        frame = build_aps_request_key(
            pan_id   = self.chosen_pan,
            dst_short= 0x0000,
            src_short= self.src_short,
            src_ieee = self.src_ieee,
            mac_seq  = self.mac_seq & 0xFF,
            nwk_seq  = self.nwk_seq,
            aps_ctr  = self.aps_seq,
            key_type = 0x04,
        )

        frame, aps_bytes = self.aps_encrypt(frame)

        key_seqnum = max(self.nwk_key.keys())
        nwk_key    = self.nwk_key[key_seqnum]
        frame = self.nwk_encrypt(frame, key_seqnum, nwk_key, self.src_ieee, aps_bytes)
        self.radio.inject_air_frame_with_meta(bytes(frame))
        print("[TX] APS Request Key (APS+NWK secured)")
        frame.show2()
        sleep(2)
        self.pull_assoc(self.chosen_pan, self.dest_short)

    def verify_aps_key(self):
        frame = build_verify_aps_key(
            pan_id   = self.chosen_pan,
            dst_short= 0x0000,
            src_short= self.src_short,
            src_ieee = self.src_ieee,
            mac_seq  = self.mac_seq & 0xFF,
            nwk_seq  = self.nwk_seq,
            aps_counter  = self.aps_seq,
            tc_link_key = self.tc_link_key,
        )

        frame, aps_bytes = self.aps_encrypt(frame)
        key_seqnum = max(self.nwk_key.keys())
        nwk_key    = self.nwk_key[key_seqnum]
        frame = self.nwk_encrypt(frame, key_seqnum, nwk_key, self.src_ieee, aps_bytes)
        self.radio.inject_air_frame_with_meta(bytes(frame))
        print("[TX] APS Verify Key (APS+NWK secured)")
        frame.show2()
        sleep(2)
        self.mac_seq = (self.mac_seq + 1) & 0xFF
        self.nwk_seq = (self.nwk_seq + 1) & 0xFF
        self.pull_assoc(self.chosen_pan, self.dest_short)


    def zdo_device_announce(self):
        frame = build_zdo_device_announce(pan_id=self.chosen_pan, src_short=self.src_short, src_ieee=self.src_ieee, aps_ctr=self.aps_seq, mac_seq=self.mac_seq, nwk_seq=self.nwk_seq, cap=0x6C)
        self.mac_seq = (self.mac_seq + 1) & 0xFF
        self.radio.inject_air_frame_with_meta(bytes(frame))
        print("[TX] ZDO Device Announce")

    def nwk_route_reply(self, destination, route_request_identifier):
        frame = build_nwk_route_reply(
                pan_id=self.chosen_pan,
                src_short=self.src_short,
                dest_short=destination,
                mac_seq=self.mac_seq,
                nwk_seq=self.nwk_seq,
                rri=route_request_identifier
                )
        self.radio.inject_air_frame_with_meta(bytes(frame))
        self.mac_seq = (self.mac_seq + 1) & 0xFF
        self.nwk_seq = (self.nwk_seq + 1) & 0xFF
        print("[TX] Network Route Reply")

    def zdo_node_descriptor_request(self):
        frame = build_zdo_node_descriptor_request(pan_id=self.chosen_pan, src_short=self.src_short, aps_ctr=self.aps_seq, mac_seq=self.mac_seq, nwk_seq=self.nwk_seq, zdo_tsn=self.zdo_tsn, target_nwk=0x0000)
        key_seqnum = next(reversed(self.nwk_key))
        nwk_key = self.nwk_key[key_seqnum]
        frame = self.nwk_encrypt(frame, key_seqnum, nwk_key, self.src_ieee, self.sec_nwk_fc)
        self.mac_seq = (self.mac_seq + 1) & 0xFF
        self.nwk_seq = (self.nwk_seq + 1) & 0xFF
        self.sec_nwk_fc += 1
        self.radio.inject_air_frame_with_meta(bytes(frame))
        print("[TX] ZDO Node Descriptor Request")
        for i in range(3):
            self.pull_assoc(self.chosen_pan, self.dest_short)
            sleep(5)

    def mac_gts_request(self):
        frame = build_mac_gts_request(pan_id=self.chosen_pan, src_short=self.src_short, coord_short=self.dest_short, mac_seq=self.mac_seq)
        print(frame.summary())
        self.radio.inject_air_frame_with_meta(bytes(frame))
        for i in range(3):
            self.pull_assoc(self.chosen_pan, self.dest_short)
            sleep(5)

    def mac_disassociation_notification(self):
        frame = build_mac_disassociation_notification(pan_id=self.chosen_pan, dest_short=self.dest_short, src_ieee=self.src_ieee, reason=0x02, mac_seq=self.mac_seq)
        self.radio.inject_air_frame_with_meta(bytes(frame))
        print(frame.summary())
        for i in range(3):
            self.pull_assoc(self.chosen_pan, self.dest_short)
            sleep(5)

    def mac_orphan_notification(self):
        frame = build_mac_orphan_notification(pan_id=self.chosen_pan, dest_short=self.dest_short, src_ieee=self.src_ieee, mac_seq=self.mac_seq)
        self.radio.inject_air_frame_with_meta(bytes(frame))
        print(frame.summary())
        for i in range(3):
            self.pull_assoc(self.chosen_pan, self.dest_short)
            sleep(5)

    def nwk_rejoin_request(self):
        frame = build_nwk_rejoin_request(pan_id=self.chosen_pan, dst_short=self.dest_short, src_short=self.src_short, src_ieee=self.src_ieee, mac_seq=self.mac_seq, nwk_seq=self.nwk_seq)
        self.radio.inject_air_frame_with_meta(bytes(frame))
        print(frame.show2())
        for i in range(3):
            self.pull_assoc(self.chosen_pan, self.dest_short)
            sleep(5)

    def aps_update_device(self):
        frame = build_aps_update_device(pan_id=self.chosen_pan, dst_short=self.dest_short, src_short=self.src_short, src_ieee=self.src_ieee, mac_seq=self.mac_seq, nwk_seq=self.nwk_seq, aps_seq=self.aps_seq)
        print("[TX] APS Update Device (unencrypted)")
        frame.show2()
        sleep(2)
        frame, aps_bytes = self.aps_encrypt(frame)
        key_seqnum = max(self.nwk_key.keys())
        nwk_key    = self.nwk_key[key_seqnum]
        frame = self.nwk_encrypt(frame, key_seqnum, nwk_key, self.src_ieee, aps_bytes)
        self.radio.inject_air_frame_with_meta(bytes(frame))
        print("[TX] APS Update Device (APS+NWK secured)")
        frame.show2()
        sleep(2)
        self.pull_assoc(self.chosen_pan, self.dest_short)
        self.pull_assoc(self.chosen_pan, self.dest_short)

    def rx_loop(self):
        while True:
            pkt = self.radio.receive_raw()
            # print("rx_loop: we did receive something: ", pkt)
            if not pkt:
                continue
            try:
                clean = pkt[1:-2]
                pkt = Dot15d4FCS(bytes(clean))
                raw = bytes(clean)
            except Exception:
                raw = pkt if isinstance(pkt, (bytes, bytearray)) else b""

            assert(isinstance(pkt, Packet))

            try:
                print("[RX]", pkt.summary())
                print("[RX hex]", raw.hex(" "))
            except Exception:
                if raw:
                    print("[RX hex]", raw.hex(" "))

            if pkt.haslayer(ZigbeeSecurityHeader):
                if not is_nwk_link_status(pkt):
                    decoded = self.decode_all(pkt)
                    if decoded is not None and self.final and not is_nwk_link_status(decoded):
                        pkt = decoded if decoded is not None else pkt
                        print("[DECODED]")
                        pkt.show2()
                        self.verify_aps_key()
                        self.final = False
                        sleep(2)
                        self.nwk_rejoin_request()

            assert(isinstance(pkt, Packet))

            if pkt.haslayer(Dot15d4FCS):
                self.mac_seq = (getattr(pkt, "seqnum", self.mac_seq) + 1) & 0xFF
            if pkt.haslayer(ZigbeeNWK):
                self.nwk_seq = (getattr(pkt, "nwk_seq", self.nwk_seq) + 1) & 0xFF
            if pkt.haslayer(ZigbeeAppCommandPayload) or pkt.haslayer(ZigbeeAppDataPayload):
                self.aps_seq = (getattr(pkt, "counter", self.aps_seq) + 1) & 0xFF

            if pkt.haslayer(Dot15d4Ack):
                pending = getattr(pkt, "fcf_pending", None)
                print(f"ACK pending={pending}")
                if pending:
                    self.pull_assoc(self.chosen_pan, self.dest_short)
                    sleep(5)

            # --- Beacon detection + immediate AssocReq using Scapy fields ---
            if isinstance(pkt, Dot15d4FCS) and getattr(pkt, "fcf_frametype", None) == 0 and not self.associated and not self.trying_association:
                if getattr(pkt, "sf_assocpermit", None) == True and self.chosen_pan == None:
                    # Beacon frame
                    self.chosen_pan = getattr(pkt, "src_panid", None)
                    self.dest_short = getattr(pkt, "src_addr", None)
                    if self.chosen_pan is None:
                        # Fallback to raw heuristic if needed
                        if len(raw) >= 2 and raw[0:2] == b"\x00\x80":
                            # You already confirmed Scapy shows src_panid; this is just a guard.
                            pass
                    if self.chosen_pan is not None:
                        if self.dest_short is None:
                            self.dest_short = 0x0000
                        print(f"[*] Beacon seen. PAN=0x{self.chosen_pan:04X}, coord=0x{self.dest_short:04X}. Trying to associate…")
                        self.try_assoc()
                        self.trying_association = True

            if self.trying_association:
                self.pull_assoc(self.chosen_pan, self.dest_short)
                sleep(5)

            # --- Association Response detection (MAC command id = 0x02) ---
            # if raw and 0x02 in raw[-6:] and not self.associated:
            if pkt.haslayer(Dot15d4Cmd) and pkt[Dot15d4Cmd].cmd_id == 0x02:
                self.associated = True
                self.trying_association = False
                # self.chosen_pan = getattr(pkt, "src_panid", self.chosen_pan)
                self.src_short = getattr(pkt, "short_address", self.src_short)
                print(f"[+] Association Response spotted. Marked associated with PAN_ID=0x{self.chosen_pan:04X}")

                self.pull_assoc(self.chosen_pan, self.dest_short)
                # self.zdo_device_announce()
                # self.announcing = True
                sleep(10)
                self.mac_gts_request()
                self.send_beacon_request()
                # sleep(4)
                # self.mac_orphan_notification()
                # sleep(4)
                # self.mac_disassociation_notification()

            if pkt.haslayer(Dot15d4Data) and pkt.haslayer(ZigbeeNWK) and pkt.haslayer(ZigbeeAppDataPayload):
                nwk = pkt[ZigbeeNWK]
                aps = pkt[ZigbeeAppDataPayload]

            if pkt.haslayer(ZigbeeDeviceProfile) and self.announcing:
                sleep(5)
                self.zdo_tsn = (getattr(pkt, "trans_seqnum", self.zdo_tsn) + 1) & 0xFF
                # self.zdo_node_descriptor_request()
                self.announcing = False


            if pkt.haslayer(ZigbeeAppDataPayload):
                aps = pkt[ZigbeeAppDataPayload]
                if not aps:
                    pass
                elif aps.aps_frametype == 0:
                    if int(aps.profile) == 0x0000 and int(aps.cluster) == 0x8002:
                        print("[RX] ZDO Node Descriptor Response spotted")
                        self.request_aps_key()
                        sleep(3)
                        self.pull_assoc(self.chosen_pan, self.dest_short)
                    else:
                        print("[RX]", pkt.summary())
            if pkt.haslayer(ZigbeeAppCommandPayload):
                "[RX] Transport Key maybe??"
                cmd_id = int(pkt[ZigbeeAppCommandPayload].cmd_identifier)
                if cmd_id == 0x05:
                    # pkt.show2()
                    print(f"[+] Transport Key spotted.")
                elif cmd_id == 0x0B:
                    print("[RX] APS Update Device")

            if pkt.haslayer(ZigbeeNWK) and pkt.haslayer(ZigbeeNWKCommandPayload):
                nwk = pkt[ZigbeeNWK]
                cmd = pkt[ZigbeeNWKCommandPayload]
                cmd_id = getattr(cmd, "cmd_identifier", None)
                dest_addr = getattr(cmd, "destination_address", -1)
                originator = getattr(nwk, "source", 0)
                is_rreq = (cmd_id == "route request") or (cmd_id == 1)
                route_request_identifier = getattr(cmd, "route_request_identifier", 1)

                if nwk.frametype == 1 and is_rreq and dest_addr == self.src_short:
                    print("[RX] Discover Route Request spotted")
                    key = (originator, route_request_identifier)
                    if key not in self.seen_rreq:
                        self.seen_rreq.add(key)
                        print(f"[RX] RREQ from 0x{originator:04X} -> me 0x{dest_addr:04X}, id={route_request_identifier}")
                        self.nwk_route_reply(originator, route_request_identifier)
                        # self.zdo_node_descriptor_request()


    def run(self):
        if not getattr(self, "_srv_th", None):
            self._srv_th = threading.Thread(target=self.radio.serve_once, daemon=True)
            self._srv_th.start()
        if not self.radio.wait_connect(15.0):
            raise TimeoutError("Zigbee stack did not connect in time")

        self.send_beacon_request()
        self.rx_loop()

if __name__ == "__main__":
    node = AliveNode()
    node.run()
