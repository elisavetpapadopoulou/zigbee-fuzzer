from struct import pack
import threading
import traceback
# from ZbossSimulatorDriver import *
from ZigbeePackets import *
import re
import time
from typing import List, Union, Tuple

from zigbeeOnHostDriver import zigbeeOnHostDriver

class ZigbeeSUL:
    def __init__(self, serial_port, target_mac=0x0000, ):
        self.driver = zigbeeOnHostDriver()
        self.packets = PACKET_TEMPLATES
        self.seq = 0
        self.config = {
            "pan_id": 0x0,
            "coord_addr": 0x0,
            "ieee_address": 0x79bc000000010002,
            "short_address": 0x0,
            "network_key": 0x0
        }
        self.sequence_numbers = {
            "mac_seq": 1,
            "nwk_seq": 1,
            "aps_seq": 1,
            "zdo_tsn": 1
        }
        self.input_sequence = []
        self.output_sequence = []

    def pre(self, timeout_s=15.0):
        try:
            if not getattr(self, "_srv_th", None):
                self._srv_th = threading.Thread(target=self.driver.serve_once, daemon=True)
                self._srv_th.start()
            if not self.driver.wait_connect(timeout_s):
                raise TimeoutError("Zigbee stack did not connect in time")
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
        if hasattr(self, input_symbol.lower()):
            output_symbol = getattr(self, input_symbol.lower())(pkt)
        else:
            if hasattr(self, input_symbol.lower() + '_pre'):
                getattr(self, input_symbol.lower() + '_pre')(pkt)

            self.send(pkt)
            output_pkts = self.receive(pkt)

            if hasattr(self, input_symbol.lower() + '_post'):
                getattr(self, input_symbol.lower() + '_post')(output_pkts)

            output_symbol = self.format_output(output_pkts)

        self.input_sequence.append(input_symbol)
        self.output_sequence.append(output_symbol)

        # here there's a function that checks for suspicious behavior 
        # if it finds it, it retries

        return output_symbol

    def send(self, pkt):
        if Dot15d4 in pkt:
            self.sequence_numbers['mac_seq'] += 1
            self.sequence_numbers['mac_seq'] &= 0xFF
            if ZigbeeNWK in pkt:
                self.sequence_numbers['nwk_seq'] += 1
                self.sequence_numbers['nwk_seq'] &= 0xFF
                if ZigbeeAppDataPayload in pkt or ZigbeeAppCommandPayload in pkt:
                    self.sequence_numbers['aps_seq'] += 1
                    self.sequence_numbers['aps_seq'] &= 0xFF
        print(f"TX ---> {pkt.summary()}")
        self.driver.inject_air_frame_with_meta(bytes(pkt))


    def receive(self, pkt, max_pkts=1, timeout=1.0):
        packets = []
        time_start = time.time()
        time_now = time_start
        while True:
            time.sleep(0.01)
            data = self.driver.receive_raw()
            if data is not None:
                try:
                    pkt = Dot15d4(bytes(data))
                except Exception as e:
                    print("Exception", e)
            print(f"RX ---> {pkt.summary()}")
            packets.append(pkt)
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
            s = output_pkt.summary()
            sym = self.symbols.get(s, s.replace(' / ', '>'))
            entries.append((output_pkt, sym))

        entries.sort(key=lambda x: x[1])
        for pkt, sym in entries:
            base = sym.split(":",1)[0]
            ident = re.sub(r'[^0-9a-zA-Z]+', '_', base).strip('_').lower()
            handler_name = f"_h_{ident}"
            handler = getattr(self, handler_name, None)
            if callable(handler):
                handler(pkt)
        return '+'.join(sym for _, sym in entries)

    def reset(self, wait: float = 0.2):
        self.input_sequence = []
        self.output_sequence = []
        self.seq = 0
        self.config.update({
            "pan_id": 0x0,
            "coord_addr": 0x0,
            "short_address": 0x0,
            "network_key": 0x0
        })
        self.sequence_numbers = {k: 1 for k in self.sequence_numbers}
        try:
            if self.driver is None:
                self.driver = zigbeeOnHostDriver()
            else:
                if hasattr(self.driver, "reopen"):
                    try:
                        self.driver.close()
                    except Exception:
                        pass
                    self.driver = zigbeeOnHostDriver()
                else:
                    try:
                        self.driver.close()
                    except Exception:
                        pass
                    self.driver = zigbeeOnHostDriver()
        except Exception:
            pass

        time.sleep(wait)

    def close(self):
        try:
            if hasattr(self, 'driver') and self.driver:
                if hasattr(self.driver, 'close'):
                    self.driver.close()
        except Exception as e:
            print("[CLOSE] driver close error:", e)


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

    def aps_request_key_pre(self, pkt):
        pass

    def aps_request_key_post(self, pkt):
        pass

    def zdo_device_announce_pre(self, pkt):
        pass

    def zdo_device_announce_post(self, pkt):
        pass

    def nwk_route_reply_pre(self, pkt):
        pass

    def nwk_route_reply_post(self, pkt):
        pass

    def zdo_node_descriptor_request_pre(self, pkt):
        pass

    def zdo_node_descriptor_request_post(self, pkt):
        pass

