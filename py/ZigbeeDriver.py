import time, threading
from WpanSerialDriver import WpanSerialDriver
from zigbeeOnHostDriver import zigbeeOnHostDriver


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
    elif driver_type == "hardware":
        return WpanSerialDriver(
                port=serial_port,
                baudrate=config["baud_rate"],
                restart_cmd=config["hardware_restart_cmd"],
                restart_wait_s=30.0
                )
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
        v = self.general_config["zoh_mac"]
        time.sleep(5)

    elif isinstance(self.driver, WpanSerialDriver):
        self.driver.restart()
        self.driver.set_channel(self.general_config["channel"])
        self.driver.enter_promiscuous_mode()
        v = self.general_config["hardware_mac"]
        print("Waiting for hardware driver to be ready...")
        time.sleep(10)

    else:
        raise ValueError(f"Unknown driver type: {type(self.driver)}")
    self.config["coord_ieee"] = int(v, 0) if isinstance(v, str) else int(v)
