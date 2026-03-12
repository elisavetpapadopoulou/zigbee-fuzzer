import threading
import traceback

from ZigbeePackets import *
from ZigbeeEncryption import *
import time

from ZigbeeEncryption import decode_all
from zigbeeOnHostDriver import zigbeeOnHostDriver

#TODO: Why is Association Request replied to even when I don't know the coordinator' short address yet?'
class ZigbeeSUL:
    def __init__(self, serial_port, target_mac=0x0000, ):
        self.driver = zigbeeOnHostDriver(
                host="127.0.0.1",
                port=6000,
                restart_cmd=["/bin/bash", "/home/eliza/Coding/Thesis/zigbee-fuzzer/scripts/restartZOHStack.sh"],
                restart_on_reset=True,
                restart_on_disconnect=True,
                restart_cooldown_s=2.0,
                )
        self.packets = PACKET_TEMPLATES
        self.seq = 0
        self.config = {
            "pan_id": 0xFFFF,
            "coord_addr": 0xFFFF,
            #TODO: Save the coordinator's IEEE address dynamically
            "coord_ieee": 0x6c63696c63696c63,
            "short_address": 0xFFFE,
            "ieee_address": 0x79bc000000010002,
            "tc_global_key": bytes([90,105,103,66,101,101,65,108,108,105,97,110,99,101,48,57]),
            "tc_link_key": bytes([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
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
            print("First connection attempt...")
            if not getattr(self, "_srv_th", None):
                self._srv_th = threading.Thread(target=self.driver.serve_once, daemon=True)
                self._srv_th.start()
                time.sleep(7)
            else:
                self.driver._run_restart_cmd("manual-start")
            if not self.driver.wait_connect(timeout_s):
                raise TimeoutError("Zigbee stack did not connect in time")
            self.driver.wait_ready(7)
            time.sleep(1)
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

    def increment_counters(self, pkt):
        # Increment the correct counters AFTER crafting the packet
        if pkt.haslayer(Dot15d4FCS):
            self.sequence_numbers["mac_seq"] =  (self.sequence_numbers["mac_seq"] + 1) & 0xFF
        if pkt.haslayer(ZigbeeNWK):
            self.sequence_numbers["nwk_seq"] = (self.sequence_numbers["nwk_seq"] + 1) & 0xFF
        if pkt.haslayer(ZigbeeAppCommandPayload) or pkt.haslayer(ZigbeeAppDataPayload):
            self.sequence_numbers["aps_seq"] = (self.sequence_numbers["aps_seq"] + 1) & 0xFF


    def step_internal(self, input_symbol):
        pkt = self.packets[input_symbol](self)

        self.increment_counters(pkt)

        if not pkt:
            return "TIMEOUT"

        # Just bypassing some specific frames
        if hasattr(self, input_symbol.lower()):
            output_symbol = getattr(self, input_symbol.lower())(pkt)

        else:
            ident = input_symbol.lower()
            handler_name = f"{ident}_pre"
            pre_handler = getattr(self, handler_name, None)
            print(f"Pre handler name: {pre_handler}")
            if callable(pre_handler):
                pkt, input_symbol = pre_handler(pkt, input_symbol)

            self.send(pkt, input_symbol)
            output_pkts = self.receive(pkt)

            # TODO: Let's see if we're gonna use this one in the end
            if hasattr(self, input_symbol.lower() + '_post'):
                output_pkts = getattr(self, input_symbol.lower() + '_post')(input_symbol, pkt, output_pkts)

            output_symbol = self.format_output(output_pkts)

            # Poll for response if the input pkt is supposed to be polled to return a response
            if output_symbol == "EMPTYRESPONSE":
                if input_symbol not in ["MAC_BEACON_REQUEST", "MAC_DATA_REQUEST", "APS_REQUEST_NWK_KEY"]:
                    poll = self.packets["MAC_DATA_REQUEST"](self)
                    self.increment_counters(poll)
                    self.send(poll, "MAC_DATA_REQUEST")
                    output_pkts = self.receive(poll)
                    output_symbol = self.format_output(output_pkts)

        self.input_sequence.append(input_symbol)
        self.output_sequence.append(output_symbol)

        # here there's a function that checks for suspicious behavior 
        # if it finds it, it retries

        return output_symbol

    def send(self, pkt, input_symbol):
        print(f"TX ---> {pkt.summary()}")
        # print(f"TX ---> {bytes(pkt).hex()}")
        self.driver.inject_air_frame_with_meta(bytes(pkt))


    def receive(self, pkt, max_pkts=1, timeout=6.0):
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
                        # print(f"RX ---> {pkt.summary()}")
                except Exception as e:
                    print("Exception", e)
            else:
                # print("It's None!")
                time_now = time.time()
                if time_now - time_start > timeout:
                    break
                continue
            #time.sleep(0.5)
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
            # This is another increment of the counters - more of a safety measure

            print("Output packet summary:", output_pkt.summary())
            output_pkt.show2()
            # sym = self.symbols.get(s, s.replace(' / ', '>'))
            sym = self._handlers(output_pkt)
            entries.append((output_pkt, sym))
            print("Entries:", entries)

        entries.sort(key=lambda x: x[1])
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
            "short_address": 0xFFFE,
            "tc_link_key": 0,
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
        sym = ""

        if Dot15d4Beacon in pkt:
            sym = "MAC_BEACON"

        if Dot15d4CmdAssocResp in pkt:
            sym = "MAC_ASSOCIATION_RESPONSE"

        if ZigbeeAppCommandPayload in pkt:
            aps = pkt[ZigbeeAppCommandPayload]
            aps_cmd = int(getattr(aps, "cmd_identifier", 0))
            if aps_cmd == 0x05:
                sym = "APS_CMD_TRANSPORT_KEY"
            elif aps_cmd == 0x0B:
                sym = "APS_UPDATE_DEVICE"
            elif aps_cmd == 0x10:
                sym = "APS_CONFIRM_KEY"

        if ZigbeeAppDataPayload in pkt:
            aps_data = pkt[ZigbeeAppDataPayload]
            aps_frametype = getattr(aps_data, "aps_frametype", None)
            if  aps_frametype == 0 :
                if int(aps_data.profile) == 0x0000 and int(aps_data.cluster) == 0x8002:
                    sym = "ZDO_NODE_DESCRIPTOR_RESPONSE"
            elif aps_frametype == 2:
                sym = "APS_ACK"


        if ZigbeeNWK in pkt and ZigbeeNWKCommandPayload in pkt:
            nwk_cmd = pkt[ZigbeeNWKCommandPayload]
            cmd_id = int(getattr(nwk_cmd, "cmd_identifier", -1))
            if cmd_id == 0x01:
                sym = "NWK_DISCOVER_ROUTE_REQUEST"
            elif cmd_id == 0x02:
                sym = "NWK_DISCOVER_ROUTE_REPLY"
            elif cmd_id == 0x06:
                sym = "NWK_REJOIN_REQUEST"
            elif cmd_id == 0x07:
                sym = "NWK_REJOIN_RESPONSE"
            elif cmd_id == 0x08:
                sym = "NWK_LINK_STATUS"

        ident = sym.lower()
        handler_name = f"_h_{ident}"
        handler = getattr(self, handler_name, None)
        print(f"Handler name: {handler_name}")
        if callable(handler):
            return handler(pkt, sym)
        else:
            return sym

    """
    Handlers that will extract and symbolize the incoming frames
    """
    def _h_mac_beacon(self, pkt, sym):
        self.config["pan_id"] = getattr(pkt, "src_panid", -1)
        self.config["coord_addr"] = getattr(pkt, "src_addr", -1)
        association_permit = getattr(pkt, "sf_assocpermit", None)
        return sym+f"(assoc_permit={association_permit})"

    #TODO: For some reason association succeeds without definition of specific pan_id and coordinator address, need to check if this is expected behavior or if there's some issue with the way I'm handling the association response
    def _h_mac_association_response(self, pkt, sym):
        if self.config["pan_id"] == 0xFFFF:
            self.config["pan_id"] = 0x6963
            self.config["coord_addr"] = 0x0000
        status = getattr(pkt, "association_status", None)
        if status == 0x00:
            self.config["short_address"] = getattr(pkt, "short_address", -1)
        return sym+f"(status={status})"

    def _h_aps_ack(self, pkt, sym):
        return sym

    def _h_zdo_node_descriptor_response(self, pkt, sym):
        return sym

    def _h_aps_cmd_transport_key(self, pkt, sym):
        aps_cmd = pkt[ZigbeeAppCommandPayload]
        key_type = int(getattr(aps_cmd, "key_type", -1))
        if key_type == 0x01:
            sym = "APS_CMD_TRANSPORT_NWK_KEY"
            key_bytes = bytes(getattr(aps_cmd, "key", b""))
            if key_bytes:
                self.network_secured = True
                print("Network is now secured!")
                self.config["network_key"][aps_cmd.key_seqnum] = key_bytes
                return sym+f"(nwk_key={self.config["network_key"]})"
            return sym+"(nwk_key=no-key)"
        elif key_type == 0x04:
            sym = "APS_CMD_TRANSPORT_TC_LINK_KEY"
            key_bytes = bytes(getattr(aps_cmd, "key", b""))
            if key_bytes:
                self.config["tc_link_key"] = key_bytes
                return sym+f"(tc_link_key={self.config["tc_link_key"]})"
            return sym+"(tc_link_key=no-key)"
        else:
            sym = "APS_CMD_TRANSPORT_KEY_OTHER"
            return sym+f"(key_type={key_type})"


    def _h_aps_update_device(self, pkt, sym):
        return sym

    def _h_nwk_route_request(self, pkt, sym):
        if ZigbeeNWK in pkt and ZigbeeNWKCommandPayload in pkt:
            nwk = pkt[ZigbeeNWK]
            nwk_cmd = pkt[ZigbeeNWKCommandPayload]
            src = getattr(nwk, "source", None)
            dst = getattr(nwk, "destination", None)
            dest_addr = getattr(nwk_cmd, "destination_address", None)
            many_to_one = getattr(nwk_cmd, "many_to_one", None)
        return sym


    def _h_nwk_route_reply(self, pkt, sym):
        if ZigbeeNWK in pkt and ZigbeeNWKCommandPayload in pkt:
            nwk_cmd = pkt[ZigbeeNWKCommandPayload]
            originator = getattr(nwk_cmd, "originator_address", None)
            responder = getattr(nwk_cmd, "responder_address", None)
        return sym

    def _h_nwk_rejoin_response(self, pkt, sym):
        nwk_cmd = pkt[ZigbeeNWKCommandPayload]
        rejoin_status = nwk_cmd.rejoin_status
        if rejoin_status == 0x00:
            self.config["short_address"] = getattr(pkt, "network_address", self.config["short_address"])
            sym = "NWK_REJOIN_RESPONSE_SUCCESS"
        else:
            sym = "NWK_REJOIN_RESPONSE_FAILURE"
        return sym+f"(status={rejoin_status})"

    def _h_aps_confirm_key(self, pkt, sym):
        aps_cmd = pkt[ZigbeeAppCommandPayload]
        status = getattr(aps_cmd, "status", -1)
        return sym+f"(status={status})"


    """
        Pre-processing functions for outgoing frames
    """
    def mac_beacon_request_pre(self, pkt, input_symbol):
        return pkt, input_symbol

    def mac_association_request_pre(self, pkt, input_symbol):
        print(pkt.show2())
        return pkt, input_symbol

    def mac_data_request_pre(self, pkt, input_symbol):
        return pkt, input_symbol

    """
    def mac_data_request_post(self, input_symbol, pkt, output_pkts):
        pkt = Dot15d4FCS(bytes(pkt))
        output_symbol = self.format_output(output_pkts)
        if output_symbol == "EMPTYRESPONSE":
            time.sleep(2)
            pkt[Dot15d4FCS].seqnum += 1
            self.send(pkt)
            output_pkts = self.receive(pkt)
        return output_pkts
    """

    def mac_gts_request_pre(self, pkt, input_symbol):
        pkt[Dot15d4CmdGTSReq].gts_len = 1
        pkt[Dot15d4CmdGTSReq].direction = 1
        pkt[Dot15d4CmdGTSReq].charact_type = 0
        return pkt, input_symbol

    def mac_disassociation_notifi_pre(self, pkt, input_symbol):
        pkt[Dot15d4CmdDisassociation] = 0x02 & 0xFF
        return pkt, input_symbol

    def mac_orphan_notification_pre(self, pkt, input_symbol):
        return pkt, input_symbol

    def aps_request_tclk_pre(self, pkt, input_symbol):
        print("Request Key - Pre Handler")
        frame, aps_bytes = aps_encrypt(self, pkt)
        if self.network_secured:
            pkt = nwk_encrypt(self, frame, aps_bytes)
            input_symbol = input_symbol+"_ENCRYPTED"
            print("Request Key - Network Secured")
        else:
            pkt = frame
            input_symbol = input_symbol+"_PLAIN"
        print("New input_symbol:", input_symbol)
        return pkt, input_symbol

    def aps_request_nwk_key_pre(self, pkt, input_symbol):
        print("Request Key - Pre Handler")
        frame, aps_bytes = aps_encrypt(self, pkt)
        pkt = frame
        input_symbol = input_symbol+"_PLAIN"
        print("New input_symbol:", input_symbol)
        return frame, input_symbol

    #TODO: Check that this hash assignment works
    def aps_verify_tclk_pre(self, pkt, input_symbol):
        if self.config["tc_link_key"] == 0:
            print("TC Link Key not set, skipping hash assignment")
            return pkt, input_symbol
        verify_hash = zigbee_hmac(self, b"\x03", self.config["tc_link_key"])
        pkt[ZigbeeAppCommandPayload].key_hash = verify_hash
        frame, _ = aps_encrypt(self, pkt)
        return frame, input_symbol

    def aps_verify_global_key_pre(self, pkt, input_symbol):
        verify_hash = zigbee_hmac(self, b"\x03", self.config["tc_global_key"])
        print(input_symbol)
        pkt[ZigbeeAppCommandPayload].key_hash = verify_hash
        frame, _ = aps_encrypt(self, pkt)
        return frame, input_symbol

    def zdo_device_announce_pre(self, pkt, input_symbol):
        aps = pkt[ZigbeeAppDataPayload]
        aps_pdu_bytes = bytes(aps)
        if self.network_secured:
            pkt = nwk_encrypt(self, pkt, aps_pdu_bytes)
            input_symbol = input_symbol+"_ENCRYPTED"
        else:
            input_symbol = input_symbol+"_PLAIN"
        return pkt, input_symbol

    def nwk_rejoin_request_tc_pre(self, pkt, input_symbol):
        # self.network_secured = False
        return pkt, input_symbol

    def nwk_rejoin_request_secure_pre(self, pkt, input_symbol):
        nwk_cmd = pkt[ZigbeeNWKCommandPayload]
        nwk_cmd_bytes = bytes(nwk_cmd)
        if self.network_secured:
            pkt = nwk_encrypt(self, pkt, nwk_cmd_bytes)
            input_symbol = input_symbol+"_ENCRYPTED"
        else:
            input_symbol = input_symbol+"_PLAIN"
        return pkt, input_symbol

    def nwk_route_reply_pre(self, pkt, input_symbol):
        return pkt, input_symbol

    def zdo_node_descriptor_request_pre(self, pkt, input_symbol):
        aps = pkt[ZigbeeAppDataPayload]
        aps_bytes = bytes(aps)
        if self.network_secured:
            pkt = nwk_encrypt(self, pkt, aps_bytes)
            input_symbol = input_symbol+"_ENCRYPTED"
        else:
            input_symbol = input_symbol+"_PLAIN"
        return pkt, input_symbol

    def zcl_read_attributes_pre(self, pkt, input_symbol):
        aps = pkt[ZigbeeAppDataPayload]
        aps_pdu_bytes = bytes(aps)
        if self.network_secured:
            pkt = nwk_encrypt(self, pkt, aps_pdu_bytes)
            input_symbol = input_symbol+"_ENCRYPTED"
        else:
            input_symbol = input_symbol+"_PLAIN"
        return pkt, input_symbol

    def zcl_discover_attributes_pre(self, pkt, input_symbol):
        aps = pkt[ZigbeeAppDataPayload]
        aps_pdu_bytes = bytes(aps)
        if self.network_secured:
            pkt = nwk_encrypt(self, pkt, aps_pdu_bytes)
            input_symbol = input_symbol+"_ENCRYPTED"
        else:
            input_symbol = input_symbol+"_PLAIN"
        return pkt, input_symbol
