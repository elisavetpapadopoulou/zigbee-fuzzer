import time, threading
from WpanSerialDriver import WpanSerialDriver
from zigbeeOnHostDriver import zigbeeOnHostDriver
from ZbossSimulatorDriver import ZbossSimulatorDriver
from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS


def driver_factory(config, serial_port):
    driver_type = config.get("driver_type", "default")

    if driver_type in ["zoh", "default"]:
        return zigbeeOnHostDriver(
                host=config["zoh_host"],
                port=config["zoh_port"],
                restart_cmd=config["zoh_restart_cmd"],
                restart_on_reset=True,
                restart_on_disconnect=True,
                restart_cooldown_s=2.0,
                )
    elif driver_type == "zboss":
        return ZbossSimulatorDriver(
                rpipe=config.get("zboss_rpipe", "/tmp/zt1.write"),
                wpipe=config.get("zboss_wpipe", "/tmp/zt1.read"),
                )
    elif driver_type == "hardware":
        return WpanSerialDriver(
                port=serial_port,
                baudrate=config["baud_rate"],
                restart_cmd=config["hardware_restart_cmd"],
                restart_wait_s=30.0
                )
    else:
        raise ValueError(f"Unknown driver type: {driver_type}")

def config_factory(config, serial_port):
    driver_type = config.get("driver_type", "zoh")
    if driver_type in ["zoh", "default"]:
        return {
            "driver_type": driver_type,
            "serial_port": config["zoh_port"],
            "target_mac": config["zoh_mac"],
            "receive_timeout": config.get("zoh_timeout"),
            "dot15d4_layer": Dot15d4FCS,
            "driver": driver_factory(config, serial_port),
        }
    elif driver_type == "zboss":
        return {
            "driver_type": driver_type,
            "serial_port": None,
            "target_mac": config["zboss_mac"],
            "receive_timeout": config.get("zboss_timeout"),
            "dot15d4_layer": Dot15d4FCS,
            "driver": driver_factory(config, serial_port),
        }
    elif driver_type == "hardware":
        return {
            "driver_type": driver_type,
            "serial_port": config["hardware_port"],
            "target_mac": config["hardware_mac"],
            "receive_timeout": config.get("hardware_timeout"),
            "dot15d4_layer": Dot15d4,
            "channel": config["channel"],
            "driver": driver_factory(config, serial_port),
        }
    else:
        raise ValueError(f"Unknown driver type: {driver_type}")


def driver_pre(self, timeout_s=0.0):
    if isinstance(self.driver, zigbeeOnHostDriver):
        if not getattr(self, "_srv_th", None):
            self._srv_th = threading.Thread(target=self.driver.serve_once, daemon=True)
            self._srv_th.start()
            time.sleep(3)
        else:
            self.driver._run_restart_cmd("manual-start")
        if not self.driver.wait_connect(timeout_s):
            raise TimeoutError("Zigbee stack did not connect in time")
        self.driver.wait_ready(8)
        v = self.general_config["target_mac"]
        time.sleep(5)

    elif isinstance(self.driver, WpanSerialDriver):
        self.driver.restart()
        self.driver.set_channel(self.general_config["channel"])
        self.driver.enter_promiscuous_mode()
        v = self.general_config["target_mac"]
        print("Waiting for hardware driver to be ready...")
        time.sleep(10)

    elif isinstance(self.driver, ZbossSimulatorDriver):
        print("Using ZBOSS simulator pipes")
        self.config["preconf_link_key"] = bytes([171,205,239,1,35,69,103,137,0,0,0,0,0,0,0,0])
        v = self.general_config["target_mac"]
        time.sleep(1)
    else:
        raise ValueError(f"Unknown driver type: {type(self.driver)}")
    self.config["coord_ieee"] = int(v, 0) if isinstance(v, str) else int(v)
