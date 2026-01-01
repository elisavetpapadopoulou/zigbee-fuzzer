from struct import pack
import threading
import traceback

from scapy import config
from ZigbeePackets import *
from ZigbeeEncryption import *
import re
import time
from typing import List, Union, Tuple

from ZigbeeEncryption import decode_all, is_nwk_link_status
from zigbeeOnHostDriver import zigbeeOnHostDriver

class ZigbeeSUL:
    def __init__(self, serial_port, target_mac=0x0000, ):
        self.driver = zigbeeOnHostDriver(
                host="127.0.0.1",
                port=6000,
                restart_cmd=["/bin/bash", "/home/elizabeth/Coding/Thesis/zigbee-fuzzer/scripts/restartZOHStack.sh"],
                restart_on_reset=True,
                restart_on_disconnect=True,
                restart_cooldown_s=2.0,
                )
        self.packets = PACKET_TEMPLATES
        self.seq = 0
        self.config = {
            "pan_id": 0xFFFF,
            "coord_addr": 0xFFFF,
            "ieee_address": 0x79bc000000010002,
            "short_address": 0x0000,
            "tc_link_key": bytes([90,105,103,66,101,101,65,108,108,105,97,110,99,101,48,57]),
            "network_key": {}
        }
        self.sequence_numbers = {
            "mac_seq": 1,
            "nwk_seq": 1,
            "aps_seq": 1,
            "zdo_tsn": 1,
            "sec_nwk_fc": 0x01000000,
            "sec_aps_fc": 0x01000000
        }
        self.input_sequence = []
        self.output_sequence = []
        self.noise = ["NWK_DISCOVER_ROUTE_REQUEST", "NWK_LINK_STATUS"]
        self.primed = False
        self.network_secured = False

    def pre(self, timeout_s=15.0):
        try:
            self.reset()
            if not getattr(self, "_srv_th", None):
                self._srv_th = threading.Thread(target=self.driver.serve_once, daemon=True)
                self._srv_th.start()
                time.sleep(7)
            self.driver._restart_stack("manual-start")
            if not self.driver.wait_connect(timeout_s):
                raise TimeoutError("Zigbee stack did not connect in time")
            self.driver.wait_ready(15)
            self.primed = True
        except Exception as e:
            print(traceback.format_exc())
            raise e

    def step(self, input_symbol):
        try:
            output_symbol = self.step_internal(input_symbol)
            # Will probably need some filtering (+ etc, basically when there's 
            # a combination of outputs)
            return output_symbol
        except Exception as e:
            print(traceback.format_exc())
            raise e

    def post(self):
        pass

    def step_internal(self, input_symbol):
        pkt = self.packets[input_symbol](self)
        if not pkt:
            return "TIMEOUT"
        # Just bypassing some specific frames
        if hasattr(self, input_symbol.lower()):
            output_symbol = getattr(self, input_symbol.lower())(pkt)
        else:
            if hasattr(self, input_symbol.lower() + '_pre'):
                getattr(self, input_symbol.lower() + '_pre')(pkt)

            self.send(pkt, input_symbol)
            output_pkts = self.receive(pkt)


            if hasattr(self, input_symbol.lower() + '_post'):
                getattr(self, input_symbol.lower() + '_post')(output_pkts)

            output_symbol = self.format_output(output_pkts)
            if input_symbol == "MAC_DATA_REQUEST" and output_symbol == "EMPTYRESPONSE":
                time.sleep(2)
                pkt[Dot15d4FCS].seqnum += 1
                self.send(pkt, input_symbol)
                output_pkts = self.receive(pkt)

        self.input_sequence.append(input_symbol)
        self.output_sequence.append(output_symbol)

        # here there's a function that checks for suspicious behavior 
        # if it finds it, it retries

        return output_symbol

    def send(self, pkt, input_symbol):
        print(f"TX ---> {pkt.summary()}")
        print(f"TX ---> {bytes(pkt).hex()}")
        self.driver.inject_air_frame_with_meta(bytes(pkt))


    def receive(self, pkt, max_pkts=1, timeout=7.0):
        packets = []
        time_start = time.time()
        time_now = time_start
        while True:
            # time.sleep(2)
            data = self.driver.receive_raw()
            if data is not None:
                try:
                    clean = data[1:-2]
                    pkt = Dot15d4FCS(bytes(clean))
                    if pkt.haslayer(ZigbeeSecurityHeader):
                        decoded = decode_all(self, pkt)
                        pkt = decoded
                    if pkt is not None:
                        packets.append(pkt)
                        assert(isinstance(pkt, Packet))
                        print(f"RX ---> {pkt.summary()}")
                except Exception as e:
                    print("Exception", e)
            else:
                # print("It's None!")
                time_now = time.time()
                if time_now - time_start > timeout:
                    break
                continue
            time.sleep(0.5)
            time_now = time.time()
            if time_now - time_start > timeout:
                break
            # if (self.is_receive_complete(packets, time_now - time_start, ))
            # if (max_pkts > 0 and len(packets) == max_pkts):
            #     break
        return packets


    def format_output(self, output_pkts):
        if not hasattr(self,'symbols'):
            self.symbols = {pkt(self).summary(): sym for sym, pkt in self.packets.items()}

        if len(output_pkts) == 0:
            return 'EMPTYRESPONSE'

        entries = []
        for output_pkt in output_pkts:
            if output_pkt.haslayer(Dot15d4FCS):
                self.sequence_numbers["mac_seq"] = (getattr(output_pkt, "seqnum", self.sequence_numbers["mac_seq"]) + 1) & 0xFF
            if output_pkt.haslayer(ZigbeeNWK):
                self.sequence_numbers["nwk_seq"] = (getattr(output_pkt, "nwk_seq", self.sequence_numbers["nwk_seq"]) + 1) & 0xFF
            if output_pkt.haslayer(ZigbeeAppCommandPayload) or output_pkt.haslayer(ZigbeeAppDataPayload):
                self.sequence_numbers["aps_seq"] = (getattr(output_pkt, "counter", self.sequence_numbers["aps_seq"]) + 1) & 0xFF

            print("Output packet summary:", output_pkt.summary())
            output_pkt.show2()
            # sym = self.symbols.get(s, s.replace(' / ', '>'))
            sym = self._handlers(output_pkt)
            entries.append((output_pkt, sym))
            print("Entries:", entries)

        entries.sort(key=lambda x: x[1])
        for pkt, sym in entries:
            # base = sym.split(":",1)[0]
            # ident = re.sub(r'[^0-9a-zA-Z]+', '_', base).strip('_').lower()
            ident = sym.lower()
            handler_name = f"_h_{ident}"
            handler = getattr(self, handler_name, None)
            print(f"Handler name: {handler_name}")
            if callable(handler):
                handler(pkt)
        official_entries = '+'.join(sym for _, sym in entries if sym not in self.noise)
        if len(official_entries) == 0:
            return 'EMPTYRESPONSE'
        return official_entries

    def reset(self, wait: float = 0.2):
        self.input_sequence = []
        self.output_sequence = []
        self.seq = 0
        self.config.update({
            "pan_id": 0xFFFF,
            "coord_addr": 0xFFFF,
            "short_address": 0x0000,
            "network_key": {}
        })
        self.sequence_numbers = {k: 1 for k in self.sequence_numbers}
        self.sequence_numbers["sec_nwk_fc"] = 0x01000000
        self.sequence_numbers["sec_aps_fc"] = 0x01000000
        self.network_secured = False
        time.sleep(wait)

    def close(self):
        try:
            if hasattr(self, 'driver') and self.driver:
                self.driver._stop_stack()
                if hasattr(self.driver, 'close'):
                    self.driver.close()
        except Exception as e:
            print("[CLOSE] driver close error:", e)

    """
    Classifier for incoming frames
    """
    def _handlers(self, pkt):

        if Dot15d4Beacon in pkt:
            return "MAC_BEACON"

        if Dot15d4CmdAssocResp in pkt:
            return "MAC_ASSOCIATION_RESPONSE"

        if ZigbeeAppCommandPayload in pkt:
            print("Found the handler")
            aps = pkt[ZigbeeAppCommandPayload]
            aps_cmd = int(getattr(aps, "cmd_identifier", 0))
            if aps_cmd == 0x05:
                key_type = int(getattr(aps, "key_type", -1))
                if key_type == 0x01:
                    self.network_secured = True
                    return "APS_CMD_TRANSPORT_NWK_KEY"
                elif key_type == 0x03:
                    return "APS_CMD_TRANSPORT_TC_LINK_KEY"
                else:
                    return "APS_CMD_TRANSPORT_KEY_OTHER"
            elif aps_cmd == 0x0B:
                return "APS_UPDATE_DEVICE"

        if ZigbeeAppDataPayload in pkt:
            aps = pkt[ZigbeeAppDataPayload]
            if getattr(aps, "aps_frametype", None) == 2:
                return "APS_ACK"
            elif getattr(aps, "aps_frametype", None) == 0 :
                if aps.profile == 0x0000 and int(aps.cluster) == 0x8002:
                    return "ZDO_NODE_DESCRIPTOR_RESPONSE"


        if ZigbeeNWK in pkt and ZigbeeNWKCommandPayload in pkt:
            nwk_cmd = pkt[ZigbeeNWKCommandPayload]
            cmd_id = int(getattr(nwk_cmd, "cmd_identifier", -1))
            if cmd_id == 0x01:
                return "NWK_DISCOVER_ROUTE_REQUEST"
            elif cmd_id == 0x02:
                return "NWK_DISCOVER_ROUTE_REPLY"
            elif cmd_id == 0x06:
                return "NWK_REJOIN_REQUEST"
            elif cmd_id == 0x07:
                return "NWK_REJOIN_RESPONSE"
            elif cmd_id == 0x08:
                return "NWK_LINK_STATUS"


    """
    Handlers that will extract and symbolize the incoming frames
    """
    def _h_mac_beacon(self, pkt):
        self.config["pan_id"] = getattr(pkt, "src_panid", -1)
        self.config["coord_addr"] = getattr(pkt, "src_addr", -1)
        association_permit = getattr(pkt, "sf_assocpermit", None)

    def _h_mac_association_response(self, pkt):
        assoc_response_pl = pkt[Dot15d4CmdAssocResp]
        status = getattr(pkt, "association_status", None)
        if status == 0x00:
            self.config["short_address"] = getattr(pkt, "short_address", -1)

    def _h_aps_ack(self, pkt):
        pass

    def _h_zdo_node_descriptor_response(self, pkt):
        pass

    def _h_aps_transport_key(self, pkt):
        pass

    def _h_aps_update_device(self, pkt):
        pass

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

    def _h_nwk_rejoin_response(self, pkt):
        nwk = pkt[ZigbeeNWKCommandPayload]
        rejoin_status = nwk.rejoin_status
        if rejoin_status == 0x00:
            self.config["short_address"] = getattr(pkt, "short_address", -1)

    def beacon_request_pre (self, pkt):
        pass

    def beacon_request_post (self, pkt):
        pass

    def mac_association_request_pre(self, pkt):
        pass

    def mac_association_request_post(self, pkt):
        pass

    def mac_data_request_pre(self, pkt):
        pass

    def mac_data_request_post(self, pkt):
        pass

    def mac_gts_request_pre(self, pkt):
        pkt[Dot15d4CmdGTSReq].gts_len = 1
        pkt[Dot15d4CmdGTSReq].direction = 1
        pkt[Dot15d4CmdGTSReq].charact_type = 0

    def mac_gts_request_post(self, pkt):
        pass

    def mac_disassociation_notification_pre(self, pkt):
        pkt[Dot15d4CmdDisassociation] = 0x02 & 0xFF

    def mac_disassociation_notification_post(self, pkt):
        self.reset()

    def mac_orphan_notification_pre(self, pkt):
        pass

    def mac_orphan_notification_post(self, pkt):
        pass

    def aps_request_key_pre(self, pkt):
        frame, aps_bytes = aps_encrypt(self, pkt)
        if self.network_secured:
            pkt = nwk_encrypt(self, frame, aps_bytes)

    def aps_request_key_post(self, pkt):
        pass

    def aps_verify_key_pre(self, pkt):
        pass

    def aps_verify_key_post(self, pkt):
        pass

    def zdo_end_device_announce_pre(self, pkt):
        aps = pkt[ZigbeeAppDataPayload]
        aps_pdu_bytes = bytes(aps)
        if self.network_secured:
            pkt = nwk_encrypt(self, pkt, aps_pdu_bytes)

    def zdo_end_device_announce_post(self, pkt):
        pass

    def nwk_route_reply_pre(self, pkt):
        pass

    def nwk_route_reply_post(self, pkt):
        pass

    def zdo_node_descriptor_request_pre(self, pkt):
        aps = pkt[ZigbeeAppDataPayload]
        aps_pdu_bytes = bytes(aps)
        if self.network_secured:
            pkt = nwk_encrypt(self, pkt, aps_pdu_bytes)


    def zdo_node_descriptor_request_post(self, pkt):
        pass

    def zcl_read_attributes_pre(self, pkt):
        aps = pkt[ZigbeeAppDataPayload]
        aps_pdu_bytes = bytes(aps)
        if self.network_secured:
            pkt = nwk_encrypt(self, pkt, aps_pdu_bytes)

    def zcl_read_attributes_post(self, pkt):
        pass

    def zcl_discover_attributes_pre(self, pkt):
        aps = pkt[ZigbeeAppDataPayload]
        aps_pdu_bytes = bytes(aps)
        if self.network_secured:
            pkt = nwk_encrypt(self, pkt, aps_pdu_bytes)

    def zcl_discover_attributes_post(self, pkt):
        pass

