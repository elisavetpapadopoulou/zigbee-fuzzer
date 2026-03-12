from Cryptodome.Cipher import AES
import struct

from scapy.all import conf, raw
from scapy.layers.dot15d4 import Dot15d4FCS, Dot15d4Data
from scapy.layers.zigbee import ZigbeeAppDataPayload, ZigbeeNWK, ZigbeeNWKCommandPayload, ZigbeeSecurityHeader, ZigbeeAppCommandPayload
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
    cmd = pkt_plain.getlayer(ZigbeeNWKCommandPayload)
    if not nwk:
        return False
    if nwk.frametype != 1:
        return False
    cmd_id = getattr(cmd, "cmd_identifier", None)
    print("[is_nwk_link_status()] cmd_identifier: ", cmd_id)
    return cmd_id == 0x08

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
        elif nwk.frametype == 1:
            decrypted_layer = ZigbeeNWKCommandPayload(_pkt=plaintext)
        else:
            decrypted_layer = Raw(plaintext)
        return mac / ll / nwk / decrypted_layer

def rebuild_plain_aps(pkt, plaintext: bytes):
    """
    Return a new packet:
      Dot15d4FCS / NWK / APS(with security bit cleared) / <decrypted layer>
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

def aps_encrypt(self, pkt):
    # Force APS header bits (visible)
    print("Unencrypted APS payload: ", bytes(pkt).hex(), " (len=", len(bytes(pkt)), ")")
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
    self.sequence_numbers["sec_aps_fc"] = (self.sequence_numbers["sec_aps_fc"] + 1) & 0xFFFFFFFF
    fc_le  = self.sequence_numbers["sec_aps_fc"].to_bytes(4, "little")
    src_le = int(self.config["ieee_address"]).to_bytes(8, "little")

    # SecCtrl: wire vs fixed (Zigbee quirk)
    sec_wire  = 0x20
    sec_fixed = (sec_wire & 0xF8) | 0x05

    # Nonce & AAD (Zigator pattern)
    nonce = src_le + fc_le + bytes([sec_fixed])
    aad   = aps_hdr_b + bytes([sec_fixed]) + fc_le + src_le

    if self.config["tc_link_key"] != 0:
        print("HURRAY!! Using TC Link Key for APS encryption")
        tc_key = self.config["tc_link_key"]
    else:
        tc_key = self.config["tc_global_key"]

    ccm = AES.new(tc_key, AES.MODE_CCM, nonce=nonce, mac_len=4)
    ccm.update(aad)
    C = ccm.encrypt(PT)
    U = ccm.digest()

    # On-wire APS aux (extnonce=1 → include src EUI)
    aps_aux_b = bytes([sec_fixed]) + fc_le + src_le

    # Exact APS PDU bytes: APS header || APS aux || C || U
    aps_pdu_bytes = aps_hdr_b + aps_aux_b + C + U

    # Build packet for next step with fresh MAC/LL and a clean NWK header
    mac, ll = _mk_mac_ll(pkt)
    nwk = pkt[ZigbeeNWK].copy(); nwk.remove_payload()
    aps_pkt = mac / ll / nwk / Raw(aps_pdu_bytes)
    return aps_pkt, aps_pdu_bytes

def nwk_encrypt(self, pkt, aps_pdu_bytes):
    key_seqnum = next(reversed(self.config["network_key"]))
    nwk_key = self.config["network_key"][key_seqnum]
    my_eui64 = self.config["ieee_address"]

    mac, ll = _mk_mac_ll(pkt)

    nwk = pkt[ZigbeeNWK].copy()
    nwk.flags   = "security+extended_src"  # 0x12
    nwk.ext_src = my_eui64
    nwk.remove_payload()
    nwk_hdr_b = bytes(nwk)

    self.sequence_numbers["sec_nwk_fc"] = (self.sequence_numbers["sec_nwk_fc"] + 1) & 0xFFFFFFFF
    fc_le  = self.sequence_numbers["sec_nwk_fc"].to_bytes(4, "little")
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
    nwk_aux_b = struct.pack("<B I Q B", sec_fixed, self.sequence_numbers["sec_nwk_fc"], int(my_eui64), key_seqnum & 0xFF)


    frame = mac / ll / nwk / Raw(nwk_aux_b + C + U)
    print(f"APS_CMD_REQUEST_KEY: {bytes(frame).hex()}")
    return frame


def decode(self, pkt):
    sec = pkt.getlayer("ZigbeeSecurityHeader")
    # if self.final and not is_nwk_link_status(pkt):
    #     print("APS_CMD_REQUEST_KEY")
    #     pkt.show2()

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

    if self.config["tc_link_key"] != 0:
        tc_key = self.config["tc_link_key"]
    else:
        tc_key = self.config["tc_global_key"]

    if key_id == 1:
        if self.config["network_key"] != {}:
            key = self.config["network_key"][key_seqnum]
            keylen = len(key)
        else:
            return None, key_id
    elif key_id == 2:
        key = zigbee_hmac(self, b"\x00", tc_key)
    elif key_id == 3:
        key = zigbee_hmac(self, b"\x02", tc_key)
    else:
        key = tc_key

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
    if len(U) != M:
        raise ValueError(f"MIC length mismatch: expected {M}, got {len(U)}")

    encrypted_layer = str(sec.underlayer)
    if encrypted_layer.startswith("ZigbeeApp"):
        aps = pkt.getlayer("ZigbeeAppDataPayload")
        aps_header = aps.copy()
        aps_header.remove_payload()
        aps_header = bytes(aps_header)[:2]

        aux = bytes([security_control]) + received_frame_counter + sender_address
        if key_id == 1:
            aux += bytes([sec.key_seqnum])
        aad = aps_header + aux

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
    else:
        return None, key_id

    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=M)
    cipher.update(bytes(aad))
    plaintext = cipher.decrypt(C)
    cipher.verify(mic)

    print(f"[APS] Decrypted OK (key_id={key_id}, sec_ctrl_wire=0x{security_control:02x})")

    return plaintext, key_id
def zigbee_hmac(self, message, key):
    # HMAC uses the following inner and outer pads
    inner_pad = 0x36
    outer_pad = 0x5c

    # Hash the key if it is longer than the block size
    if len(key) > 16:
        key = bytearray(zigbee_mmo_hash(self, key))
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

    return zigbee_mmo_hash(self, outer_key + zigbee_mmo_hash(self, inner_key + message))

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
    print("[*] Attempting to decode packet with security header...")
    print(bytes(pkt).hex())
    for _ in range(2):
        owner = _sec_owner(pkt)
        if owner is None:
            break
        plaintext, key_id = decode(self, pkt)
        if plaintext is None:
            return None
        # TODO: Return decoded pkt and let _post handlers extract the information
        if owner is ZigbeeNWK:
            pkt = rebuild_plain_nwk(pkt, plaintext)
            # if is_nwk_link_status(pkt):
            #     return None
        elif owner is ZigbeeAppDataPayload:
            pkt = rebuild_plain_aps(pkt, plaintext)
            # aps_cmd = pkt.getlayer(ZigbeeAppCommandPayload)
            # if aps_cmd:
            #     cmd_id = getattr(aps_cmd, "cmd_identifier", -1)
            #     if cmd_id == 0x05:
            #         transported_key = getattr(aps_cmd, "key_type", -1)
            #         key_bytes = bytes(getattr(aps_cmd, "key", b""))
            #         if key_bytes:
            #             if transported_key == 0x01:
            #                 self.config["network_key"] = {aps_cmd.key_seqnum: key_bytes}
            #             elif transported_key == 0x04:
            #                 self.config["tc_link_key"] = key_bytes
            # else:
            #     break
    return Dot15d4FCS(bytes(pkt))



