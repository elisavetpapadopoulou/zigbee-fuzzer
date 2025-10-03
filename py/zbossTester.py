import os, time, threading
from typing import assert_never
from time import sleep

from scapy.all import conf
from scapy.layers.dot15d4 import Dot15d4, Dot15d4Data, Dot15d4Ack, Dot15d4CmdAssocReq, Dot15d4Cmd, Dot15d4CmdAssocResp
from scapy.layers.zigbee import Dot15d4FCS, ZDPDeviceAnnce, ZigbeeAppDataPayload, ZigbeeDeviceProfile, ZigbeeNWK, ZigbeeNWKCommandPayload, ZigbeeSecurityHeader, ZigbeeAppCommandPayload
# from ZbossSimulatorDriver import *
from zigbeeOnHostDriver import zigbeeOnHostDriver
from scapy.packet import Raw

conf.dot15d4_protocol = "zigbee"

def build_aps_request_key(pan_id, dst_short, src_short,
                          mac_seq, nwk_seq, aps_ctr, key_type):
    return Dot15d4(
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
            source=src_short,
            radius=30,
            seqnum=nwk_seq & 0xFF
        )/ ZigbeeAppDataPayload(
            frame_control=4,
            aps_frametype=1,
            delivery_mode=0,
            counter=aps_ctr & 0xFF
        )/ ZigbeeAppCommandPayload(
            cmd_identifier=0x08,
            key_type=key_type
        )

def build_zdo_node_descriptor_request(pan_id, src_short, aps_ctr, mac_seq, nwk_seq, zdo_tsn, target_nwk):
    return (
        Dot15d4(
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
    return Dot15d4(
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
    return Dot15d4(
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
    return Dot15d4(
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
    return Dot15d4(
            fcf_frametype=3,
            fcf_security=0,
            fcf_ackreq=0,
            fcf_panidcompress=1,
            fcf_destaddrmode=2,
            fcf_srcaddrmode=3,
            seqnum=mac_seq & 0xFF
            )/Dot15d4Cmd(
                cmd_id=0x01,
                dest_panid=0x6963,
                dest_addr=0x0000,
                src_addr=src_ieee
            )/Dot15d4CmdAssocReq(
                device_type=0,
                security_capability=1,
                allocate_address=1
            )

def build_beacon_request_noaddr(pan_id, dest_short, src_ieee, mac_seq=1):
    return Dot15d4(
            fcf_frametype=3,
            fcf_security=0,
            fcf_ackreq=0,
            fcf_panidcompress=0,
            fcf_destaddrmode=2,
            fcf_srcaddrmode=0,
            seqnum=mac_seq
        )/ Dot15d4Cmd(
            cmd_id = 0x07,
            dest_panid = pan_id,
            dest_addr = dest_short,
        )


class AliveNode:
    def __init__(self):
        self.radio = zigbeeOnHostDriver()
        self.mac_seq = 1
        self.nwk_seq = 1
        self.aps_seq = 1
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

    # In your AliveNode, add this test:
    def inject_test_beacon(self):
        # Proper beacon frame matching coordinator's network
        beacon_hex = bytes([
        0x08, 0x03,  # Frame Control: MAC command, no addr
        0x01,        # Sequence  
        0xFF, 0xFF,  # Dest PAN (broadcast)
        0xFF, 0xFF,  # Dest addr (broadcast)
        0x07         # Beacon Request command
        ])
        self.radio.inject_air_frame_with_meta(beacon_hex)

    def send_beacon_request(self):
        self.radio.enable_raw()
        sleep(10)
        pkt = build_beacon_request_noaddr(pan_id=0xFFFF, dest_short=0xFFFF, src_ieee=self.src_ieee, mac_seq=self.mac_seq & 0xFF)
        self.mac_seq += 1
        self.radio.inject_air_frame_with_meta(bytes(pkt))
        print(f"[TX] Beacon Request (no addressing): {bytes(pkt).hex(" ")}")

    def try_assoc(self):
        frame = build_assoc_request_raw(pan_id=self.chosen_pan, dest_short=self.dest_short, src_ieee=self.src_ieee, mac_seq=self.mac_seq & 0xFF)
        self.mac_seq += 1
        self.radio.inject_air_frame_with_meta(bytes(frame))
        print(f"Sent AssocReq --> PAN=0x{self.chosen_pan:04X}, coord=0x{self.dest_short}")

    def pull_assoc(self, pan_id, dest_short):
        frame = build_mac_data_request(pan_id, dest_short, self.src_ieee, self.mac_seq)
        self.mac_seq += 1
        self.radio.inject_air_frame_with_meta(bytes(frame))

    def request_aps_key(self):
        frame = build_aps_request_key(pan_id=self.chosen_pan, dst_short=0x0000, src_short=self.src_short, 
                                      mac_seq=self.mac_seq & 0xFF, nwk_seq=self.nwk_seq, aps_ctr=self.aps_seq, key_type=0x01)
        self.mac_seq = (self.mac_seq + 1) & 0xFF
        self.radio.inject_air_frame_with_meta(bytes(frame))
        print("[TX] APS Request Key")

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
        self.mac_seq = (self.mac_seq + 1) & 0xFF
        self.nwk_seq = (self.nwk_seq + 1) & 0xFF
        self.radio.inject_air_frame_with_meta(bytes(frame))
        print("[TX] ZDO Node Descriptor Request")

    def rx_loop(self):
        while True:
            self.inject_test_beacon()
            pkt = self.radio.receive_raw()
            self.send_beacon_request()
            # print("rx_loop: we did receive something: ", pkt)
            if not pkt:
                continue
            try:
                clean = pkt[1:-2]
                pkt = Dot15d4(bytes(clean))
                raw = bytes(clean)
            except Exception:
                raw = pkt if isinstance(pkt, (bytes, bytearray)) else b""

            try:
                print("[RX]", pkt.summary())
                print("[RX hex]", raw.hex(" "))
            except Exception:
                if raw:
                    print("[RX hex]", raw.hex(" "))

            if pkt.haslayer(Dot15d4):
                self.mac_seq = (getattr(pkt, "seqnum", self.mac_seq) + 1) & 0xFF
            if pkt.haslayer(ZigbeeNWK):
                self.nwk_seq = (getattr(pkt, "nwk_seq", self.nwk_seq) + 1) & 0xFF
            if pkt.haslayer(ZigbeeAppCommandPayload) or pkt.haslayer(ZigbeeAppDataPayload):
                self.aps_seq = (getattr(pkt, "counter", self.aps_seq) + 1) & 0xFF

            if pkt.haslayer(Dot15d4Ack) and self.trying_association:
                pending = getattr(pkt, "fcf_pending", None)
                print(f"ACK pending={pending}")
                if pending:
                    sleep(5)

            # --- Beacon detection + immediate AssocReq using Scapy fields ---
            if isinstance(pkt, Dot15d4) and getattr(pkt, "fcf_frametype", None) == 0 and not self.associated and not self.trying_association:
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
                continue

            if self.trying_association == True:
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

                self.zdo_device_announce()
                self.announcing = True
                sleep(10)

            if pkt.haslayer(Dot15d4Data) and pkt.haslayer(ZigbeeNWK) and pkt.haslayer(ZigbeeAppDataPayload):
                nwk = pkt[ZigbeeNWK]
                aps = pkt[ZigbeeAppDataPayload]

            if pkt.haslayer(ZigbeeDeviceProfile) and self.announcing:
                sleep(5)
                self.zdo_tsn = (getattr(pkt, "trans_seqnum", self.zdo_tsn) + 1) & 0xFF
                self.zdo_node_descriptor_request()
                self.announcing = False


            if pkt.haslayer(ZigbeeAppDataPayload):
                aps = pkt[ZigbeeAppDataPayload]
                if getattr(aps, "aps_frametype", None) in (2, "ack"):
                    self.request_aps_key()
                if int(aps.profile) == 0x0000 and int(aps.cluster) == 0x8002:
                    print("[RX] ZDO Node Descriptor Response spotted")
                else:
                    print("[RX]", pkt.summary())

            if pkt.haslayer(ZigbeeSecurityHeader) & (not self.requesting_aps_key):
                print("[RX-bytes]", pkt.show2())
                self.requesting_aps_key = True
                if pkt.haslayer(ZigbeeAppCommandPayload):
                    cmd_id = int(pkt[ZigbeeAppCommandPayload].cmd_identifier)
                    if cmd_id == 0x05:
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
                        self.zdo_node_descriptor_request()


    def run(self):
        if not getattr(self, "_srv_th", None):
            self._srv_th = threading.Thread(target=self.radio.serve_once, daemon=True)
            self._srv_th.start()
        if not self.radio.wait_connect(15.0):
            raise TimeoutError("Zigbee stack did not connect in time")

        self.inject_test_beacon()
        self.rx_loop()

if __name__ == "__main__":
    node = AliveNode()
    node.run()
