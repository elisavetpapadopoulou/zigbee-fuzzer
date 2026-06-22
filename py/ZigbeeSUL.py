from pathlib import Path
import traceback
import yaml

from normalize_test import *
from ZigbeeDriver import *
from ZigbeePackets import *
from ZigbeeEncryption import *
from ZigbeeEncryption import decrypt_all

CONFIG_PATH = Path(__file__).resolve().parent / "config.yaml"

class ZigbeeSUL:
    def __init__(self, serial_port, target_mac=0x0000, ):

        with open(CONFIG_PATH, "r") as f:
            general_config = yaml.safe_load(f)

        self.general_config = config_factory(general_config, serial_port)
        self.driver = self.general_config["driver"]
        self.dot15d4_layer = self.general_config["dot15d4_layer"]
        self.packets = PACKET_TEMPLATES
        self.seq = 0
        self.config = {
            "pan_id": 0xFFFF,
            "coord_addr": 0xFFFF,
            "coord_ieee": 0x0000000000000000,
            "short_address": 0xFFFE,
            "ieee_address": 0x79bc000000010001,
            "preconf_link_key": b"",
            "tc_global_key": bytes([90,105,103,66,101,101,65,108,108,105,97,110,99,101,48,57]),
            "tc_link_key": b"",
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
        self.noise = ["NWK_DISCOVER_ROUTE_REQUEST", "NWK_LINK_STATUS", "MAC_ACK"]
        self.primed = False
        self.associated = False
        self.network_secured = False

    def pre(self, timeout_s=9.0):
        try:
            driver_pre(self, timeout_s=timeout_s)
            self.reset()

            while self.driver.receive_raw(timeout=0.05):
                pass
            self._session_start = time.time()
            self.primed = True

        except Exception as e:
            print(traceback.format_exc())
            raise e

    def step(self, input_symbol):
        try:
            if self.primed is True:
                log.state(f"STEP [{input_symbol}]")
                output_symbol = self.step_internal(input_symbol)
                # TODO: Will probably need some filtering (+ etc, basically when there's 
                # a combination of outputs)
                self.input_sequence.append(input_symbol)
                self.output_sequence.append(output_symbol)
                return output_symbol
        except Exception as e:
            print(traceback.format_exc())
            raise e

    def post(self):
        if isinstance(self.driver, WpanSerialDriver):
            self.input_sequence, self.output_sequence = normalize_beacons(self.input_sequence, self.output_sequence)
            print("Final output sequence:")
            for inp, out in zip(self.input_sequence, self.output_sequence):
                print(f"{inp} -> {out}")

    def increment_counters(self, pkt):
        # Increment the correct counters AFTER crafting the packet
        if pkt.haslayer(self.dot15d4_layer):
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

        # TODO: maybe this will be the key if the assoc_permit deletion doesn't work. 
        # if time.time() - self._session_start > 240:
        #     self.reset()

        # Just bypassing some specific frames
        if hasattr(self, input_symbol.lower()):
            output_symbol = getattr(self, input_symbol.lower())(pkt)

        else:
            ident = input_symbol.lower()
            handler_name = f"{ident}_pre"
            pre_handler = getattr(self, handler_name, None)
            if callable(pre_handler):
                pkt, input_symbol = pre_handler(pkt, input_symbol)

            self.send(pkt, input_symbol)
            output_pkts = self.receive(pkt, self.general_config.get("receive_timeout", 5.0))


            output_symbol = self.format_output(input_symbol, output_pkts)

            # TODO: Let's see if we're gonna use this one in the end
            if hasattr(self, input_symbol.lower() + '_post'):
                output_symbol = getattr(self, input_symbol.lower() + '_post')(output_symbol)

        # here there's a function that checks for suspicious behavior 
        # if it finds it, it retries

        return output_symbol

    def send(self, pkt, input_symbol):
        log.tx(pkt.summary())
        # print(f"TX ---> {bytes(pkt).hex()}")
        self.driver.inject_air_frame_with_meta(bytes(pkt))


    def receive(self, pkt, timeout=5.0):
        packets = []
        time_start = time.time()
        time_now = time_start
        while True:
            # time.sleep(2)
            data = self.driver.receive_raw()
            if data is not None:
                try:
                    pkt = self.dot15d4_layer(bytes(data))
                    log.rx(pkt.summary())
                    if pkt.haslayer(ZigbeeSecurityHeader):
                        decrypted = decrypt_all(self, pkt)
                        pkt = decrypted
                    if pkt is not None:
                        packets.append(pkt)
                        assert(isinstance(pkt, Packet))

                        # Here we need to make an exception and handle the transport key command before receiving more packets, 
                        # because it can contain the network key that we need to decrypt the following packets.
                        if ZigbeeAppCommandPayload in pkt:
                            aps = pkt[ZigbeeAppCommandPayload]
                            aps_cmd = int(getattr(aps, "cmd_identifier", 0))
                            if aps_cmd == 0x05:
                                _ = self._h_aps_cmd_transport_key(pkt, "APS_CMD_TRANSPORT_KEY")

                except Exception as e:
                    log.log_error(f"Exception: {e}")
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


    def format_output(self, input_symbol, output_pkts):

        if not output_pkts:
            return 'EMPTYRESPONSE'

        entries = set()

        for output_pkt in output_pkts:
            summary = output_pkt.summary().replace(' / ', '>')
            # log.rx(summary)
            sym = self._handlers(output_pkt)
            if sym == "":
                new_pkt = Dot15d4(bytes(output_pkt))
                sym = self._handlers(new_pkt)
            if not sym or sym == "EMPTYRESPONSE":
                continue

            for part in sym.split("+"):
                if not part or part == "EMPTYRESPONSE":
                    continue

                if part in self.noise:
                    continue

                if part == "ZDO_NODE_DESCRIPTOR_RESPONSE":
                    if input_symbol == "ZDO_NODE_DESCRIPTOR_REQUEST":
                        entries.add(part)
                else:
                    entries.add(part)

        if not entries:
            return 'EMPTYRESPONSE'
        print(f"Output symbols: {entries}")

        return "+".join(sorted(entries))


    def reset(self, wait: float = 0.2):
        self.input_sequence = []
        self.output_sequence = []
        self.seq = 0
        self.config.update({
            "pan_id": 0xFFFF,
            "coord_addr": 0xFFFF,
            "short_address": 0xFFFE,
            "tc_link_key": b"",
            "network_key": {}
        })
        self.sequence_numbers = {k: 1 for k in self.sequence_numbers}
        self.sequence_numbers["sec_nwk_fc"] = 0x01000000
        self.sequence_numbers["sec_aps_fc"] = 0x01000000
        self.associated = False
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
    Classifiers for incoming frames
    """
    def _handlers(self, pkt):
        # pkt.show2()
        sym = ""

        if Dot15d4Beacon in pkt:
            sym = "MAC_BEACON"

        elif Dot15d4Ack in pkt:
            sym = "MAC_ACK"

        elif Dot15d4CmdAssocResp in pkt:
            sym = "MAC_ASSOCIATION_RESPONSE"

        elif ZigbeeAppCommandPayload in pkt:
            aps = pkt[ZigbeeAppCommandPayload]
            aps_cmd = int(getattr(aps, "cmd_identifier", 0))
            if aps_cmd == 0x05:
                sym = "APS_CMD_TRANSPORT_KEY"
            elif aps_cmd == 0x0B:
                sym = "APS_UPDATE_DEVICE"
            elif aps_cmd == 0x10:
                sym = "APS_CONFIRM_KEY"

        elif ZigbeeAppDataPayload in pkt:
            aps_data = pkt[ZigbeeAppDataPayload]
            aps_frametype = getattr(aps_data, "aps_frametype", None)
            if  aps_frametype == 0 :
                cluster = int(getattr(aps_data, "cluster", -1))
                profile = int(getattr(aps_data, "profile", -1))
                if profile == 0x0000 and cluster == 0x0002:
                    sym = "ZDO_NODE_DESCRIPTOR_REQUEST"
                elif profile == 0x0000 and cluster == 0x8002:
                    sym = "ZDO_NODE_DESCRIPTOR_RESPONSE"
                elif profile == 0x0000 and cluster == 0x0001:
                    sym = "ZDO_EXTENDED_ADDRESS_REQUEST"
                elif profile == 0x0000 and cluster == 0x0005:
                    sym = "ZDO_ACTIVE_ENDPOINT_REQUEST"
                elif profile == 0x0000 and cluster == 0x0004:
                    sym = "ZDO_SIMPLE_DESCRIPTOR_REQUEST"
                elif profile == 0x0104 and cluster == 0x0000:
                    zcl = bytes(aps_data.payload)
                    if len(zcl) >= 3:
                        zcl_seq = zcl[1]
                        zcl_cmd = zcl[2]

                        if zcl_cmd == 0x00:
                            sym = "ZCL_READ_ATTRIBUTES_REQUEST"
                            self.last_zcl_seq = zcl_seq
                            self.last_zcl_request_src = pkt[ZigbeeNWK].source
                            self.last_zcl_src_endpoint = aps_data.src_endpoint
                            self.last_zcl_dst_endpoint = aps_data.dst_endpoint

            elif aps_frametype == 2:
                sym = "APS_ACK"


        elif ZigbeeNWK in pkt and ZigbeeNWKCommandPayload in pkt:
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
        log.output(sym)
        # print(f"Handler name: {handler_name}")
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
        return sym

    def _h_mac_association_response(self, pkt, sym):
        if self.config["pan_id"] == 0xFFFF:
            self.config["pan_id"] = getattr(pkt, "dest_panid", -1)
            self.config["coord_ieee"] = getattr(pkt, "src_addr", -1)
        status = getattr(pkt, "association_status", None)
        if status == 0x00:
            self.config["short_address"] = getattr(pkt, "short_address", -1)
            if isinstance(self.driver, WpanSerialDriver):
                self.driver.set_addresses(self.config["pan_id"], self.config["short_address"])
            self.associated = True
        return sym

    def _h_aps_ack(self, pkt, sym):
        return sym

    def _h_zdo_node_descriptor_response(self, pkt, sym):
        return sym

    def _h_aps_cmd_transport_key(self, pkt, sym):
        aps_cmd = pkt[ZigbeeAppCommandPayload]
        key_type = int(getattr(aps_cmd, "key_type", -1))
        if key_type == 0x01:
            mac_data = pkt[Dot15d4Data]
            if self.config["short_address"] == 0xFFFE:
                self.config["pan_id"] = getattr(mac_data, "dest_panid", -1)
                self.config["coord_addr"] = getattr(mac_data, "src_addr", -1)
                self.config["short_address"] = getattr(mac_data, "dest_addr", -1)
                if isinstance(self.driver, WpanSerialDriver):
                    self.driver.set_addresses(self.config["pan_id"], self.config["short_address"])
            sym = "APS_CMD_TRANSPORT_NWK_KEY"
            key_bytes = bytes(getattr(aps_cmd, "key", b""))
            if key_bytes:
                self.network_secured = True
                log.state("network_secured = True")
                self.config["network_key"][aps_cmd.key_seqnum] = key_bytes
                self.associated = True
        elif key_type == 0x04:
            sym = "APS_CMD_TRANSPORT_TC_LINK_KEY"
            key_bytes = bytes(getattr(aps_cmd, "key", b""))
            if key_bytes:
                self.config["tc_link_key"] = key_bytes
        else:
            sym = "APS_CMD_TRANSPORT_KEY_OTHER"
        return sym


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
            sym += f"(status={rejoin_status})"
        return sym

    def _h_aps_confirm_key(self, pkt, sym):
        aps_cmd = pkt[ZigbeeAppCommandPayload]
        status = getattr(aps_cmd, "status", -1)
        return sym+f"(status={status})"

    def _h_zdo_node_descriptor_request(self, pkt, sym):
        zdo_tsn = getattr(pkt, "trans_seqnum", None)
        if zdo_tsn is not None:
            # print(f"Updating ZDO TSN to {zdo_tsn}")
            self.sequence_numbers["zdo_tsn"] = int(zdo_tsn)

        sym = self.step_internal("ZDO_NODE_DESCRIPTOR_RESPONSE")
        return sym

    def _h_zdo_simple_descriptor_request(self, pkt, sym):
        zdo_tsn = getattr(pkt, "trans_seqnum", None)
        if zdo_tsn is not None:
            # print(f"Updating ZDO TSN to {zdo_tsn}")
            self.sequence_numbers["zdo_tsn"] = int(zdo_tsn)
        sym = self.step_internal("ZDO_SIMPLE_DESCRIPTOR_RESPONSE")
        return sym

    def _h_zdo_extended_address_request(self, pkt, sym):
        zdo_tsn = getattr(pkt, "trans_seqnum", None)
        if zdo_tsn is not None:
            self.sequence_numbers["zdo_tsn"] = int(zdo_tsn)
        sym = self.step_internal("ZDO_EXTENDED_ADDRESS_RESPONSE")
        return sym

    def _h_zdo_active_endpoint_request(self, pkt, sym):
        zdo_tsn = getattr(pkt, "trans_seqnum", None)
        if zdo_tsn is not None:
            # print(f"Updating ZDO TSN to {zdo_tsn}")
            self.sequence_numbers["zdo_tsn"] = int(zdo_tsn)
        sym = self.step_internal("ZDO_ACTIVE_ENDPOINT_RESPONSE")
        return sym

    def _h_zcl_read_attributes_request(self, pkt, sym):
        sym = self.step_internal("ZCL_READ_ATTRIBUTES_RESPONSE")
        if sym == "EMPTYRESPONSE":
            sym = "ZDO_INTERVIEW_SUCCESS"
        return sym



    """
        Pre-processing functions for outgoing frames
    """
    def mac_beacon_request_pre(self, pkt, input_symbol):
        return pkt, input_symbol

    def mac_association_request_pre(self, pkt, input_symbol):
        return pkt, input_symbol

    def mac_data_request_pre(self, pkt, input_symbol):
        return pkt, input_symbol

    def mac_gts_request_pre(self, pkt, input_symbol):
        pkt[Dot15d4CmdGTSReq].gts_len = 1
        pkt[Dot15d4CmdGTSReq].direction = 1
        pkt[Dot15d4CmdGTSReq].charact_type = 0
        return pkt, input_symbol

    def mac_disassociation_notify_pre(self, pkt, input_symbol):
        return pkt, input_symbol

    def mac_orphan_notification_pre(self, pkt, input_symbol):
        return pkt, input_symbol

    def aps_request_tclk_pre(self, pkt, input_symbol):
        # print("Request Key - Pre Handler")
        frame, aps_bytes = aps_encrypt(self, pkt)
        if self.network_secured:
            pkt = nwk_encrypt(self, frame, aps_bytes)
            # print("Request Key - Network Secured")
        else:
            pkt = frame
        return pkt, input_symbol

    def aps_request_nwk_key_pre(self, pkt, input_symbol):
        # print("Request Key - Pre Handler")
        frame, aps_bytes = aps_encrypt(self, pkt)
        pkt = frame
        return frame, input_symbol

    #TODO: Check that this hash assignment works
    def aps_verify_tclk_pre(self, pkt, input_symbol):
        if not self.config["tc_link_key"]:
            log.state("TCLK: Not set")
            return pkt, input_symbol
        verify_hash = zigbee_hmac(self, b"\x03", self.config["tc_link_key"])
        pkt[ZigbeeAppCommandPayload].key_hash = verify_hash
        frame, _ = aps_encrypt(self, pkt)
        return frame, input_symbol

    def aps_verify_global_key_pre(self, pkt, input_symbol):
        verify_hash = zigbee_hmac(self, b"\x03", self.config["tc_global_key"])
        # print(input_symbol)
        pkt[ZigbeeAppCommandPayload].key_hash = verify_hash
        frame, _ = aps_encrypt(self, pkt)
        return frame, input_symbol

    def zdo_device_announce_pre(self, pkt, input_symbol):
        aps = pkt[ZigbeeAppDataPayload]
        aps_pdu_bytes = bytes(aps)
        if self.network_secured:
            pkt = nwk_encrypt(self, pkt, aps_pdu_bytes)
        return pkt, input_symbol

    def nwk_rejoin_request_tc_pre(self, pkt, input_symbol):
        # print("hex:", bytes(pkt).hex())
        # self.network_secured = False
        return pkt, input_symbol

    def nwk_rejoin_request_secure_pre(self, pkt, input_symbol):
        nwk_cmd = pkt[ZigbeeNWKCommandPayload]
        nwk_cmd_bytes = bytes(nwk_cmd)
        if self.network_secured:
            pkt = nwk_encrypt(self, pkt, nwk_cmd_bytes)
        return pkt, input_symbol

    def nwk_route_reply_pre(self, pkt, input_symbol):
        return pkt, input_symbol

    def zdo_node_descriptor_request_pre(self, pkt, input_symbol):
        aps = pkt[ZigbeeAppDataPayload]
        aps_bytes = bytes(aps)
        if self.network_secured:
            pkt = nwk_encrypt(self, pkt, aps_bytes)
        return pkt, input_symbol

    def zdo_node_descriptor_response_pre(self, pkt, input_symbol):
        aps = pkt[ZigbeeAppDataPayload]
        aps_bytes = bytes(aps)
        if self.network_secured:
            pkt = nwk_encrypt(self, pkt, aps_bytes)
        return pkt, input_symbol

    def zdo_simple_descriptor_response_pre(self, pkt, input_symbol):
        aps = pkt[ZigbeeAppDataPayload]
        aps_bytes = bytes(aps)
        if self.network_secured:
            pkt = nwk_encrypt(self, pkt, aps_bytes)
        return pkt, input_symbol

    def zdo_extended_address_response_pre(self, pkt, input_symbol):
        aps = pkt[ZigbeeAppDataPayload]
        aps_bytes = bytes(aps)
        if self.network_secured:
            pkt = nwk_encrypt(self, pkt, aps_bytes)
        return pkt, input_symbol

    def zdo_active_endpoint_response_pre(self, pkt, input_symbol):
        aps = pkt[ZigbeeAppDataPayload]
        aps_bytes = bytes(aps)
        if self.network_secured:
            pkt = nwk_encrypt(self, pkt, aps_bytes)
        return pkt, input_symbol

    def zcl_read_attributes_pre(self, pkt, input_symbol):
        aps = pkt[ZigbeeAppDataPayload]
        aps_pdu_bytes = bytes(aps)
        if self.network_secured:
            pkt = nwk_encrypt(self, pkt, aps_pdu_bytes)
        return pkt, input_symbol

    def zcl_read_attributes_response_pre(self, pkt, input_symbol):
        aps = pkt[ZigbeeAppDataPayload]
        aps_pdu_bytes = bytes(aps)
        if self.network_secured:
            pkt = nwk_encrypt(self, pkt, aps_pdu_bytes)
        return pkt, input_symbol

    def zcl_discover_attributes_pre(self, pkt, input_symbol):
        aps = pkt[ZigbeeAppDataPayload]
        aps_pdu_bytes = bytes(aps)
        if self.network_secured:
            pkt = nwk_encrypt(self, pkt, aps_pdu_bytes)
        return pkt, input_symbol


    """
        Post-processing functions for outgoing frames
    """
    def mac_association_request_post(self, output_symbol):
        if self.general_config["driver_type"] != "hardware":
            poll = self.packets["MAC_DATA_REQUEST"](self)
            self.increment_counters(poll)
            self.send(poll, "MAC_DATA_REQUEST")
            output_pkts = self.receive(poll)
            output_symbol = self.format_output("MAC_ASSOCIATION_REQUEST", output_pkts)
        elif self.general_config["driver_type"] == "hardware":
            parts = output_symbol.split("+")
            parts = [p for p in parts if p != "MAC_BEACON"]
            output_symbol = "+".join(parts) if parts else "EMPTYRESPONSE"
        return output_symbol

    def mac_beacon_request_post(self, output_symbol):
        if self.general_config["driver_type"] == "hardware":
            if output_symbol == "EMPTYRESPONSE" and not self.associated:
                output_symbol = "MAC_BEACON"
        return output_symbol

    """
    def mac_data_request_post(self, input_symbol, pkt, output_pkts):
        pkt = Dot15d4(bytes(pkt))
        output_symbol = self.format_output(output_pkts)
        if output_symbol == "EMPTYRESPONSE":
            time.sleep(2)
           pkt[Dot15d4].seqnum += 1
            self.send(pkt)
            output_pkts = self.receive(pkt)
        return output_pkts
    """

