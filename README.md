# Zigbee-Fuzzer

Protocol state fuzzer for Zigbee coordinators and stacks, built on [ProtocolState-Fuzzer](https://github.com/protocol-fuzzing/protocol-state-fuzzer) 0.2.0 (LearnLib `SUL` API).

Java (`src/`) drives learning. A Python mapper (`py/ZigbeeSUL.py`) turns abstract symbols into IEEE 802.15.4 / Zigbee frames with Scapy. The two sides talk through [jep](https://github.com/ninia/jep). Which radio/stack you hit is **not** chosen on the Java command line: it is `driver_type` in `py/config.yaml`.

## What actually runs

| Path | Used at runtime? |
| --- | --- |
| `src/main/java/...` | Yes — PSF entrypoint |
| `py/ZigbeeSUL.py`, `ZigbeeDriver.py`, `ZigbeePackets.py`, `ZigbeeEncryption.py`, drivers, `config.yaml` | Yes — mapper |
| `experiments/alphabets/association-nwkEntering.xml` | Yes — alphabet that matches `PACKET_TEMPLATES` |
| `experiments/args/` | Yes — PSF argument files |
| `scripts/setup_venv.sh` | Yes — Python env |
| `scripts/restartZOHStack.sh`, `restartSonoffCoord.sh` | Yes, if `config.yaml` restart commands point at them |
| `src/main/resources/default_alphabet.xml` | Only if you omit `-alphabet`. **Do not:** it still has `APS_REQUEST_KEY` / `APS_VERIFY_KEY`, which the mapper does not implement |
| `experiments/alphabets/ZigbeeAssoc.xml`, `tclinkkeytest.xml` | Stale names (`APS_REQUEST_KEY`). Will crash |
| `-mapper` / `py/ZigbeeSUL_<name>.py` | Java can load it; **no such files exist** |
| `py/Zigbee/`, `py/zoh_files/`, `py/testing-scripts/` | Scratch copies, not imported by the live mapper |
| `scripts/beautify_model.py` | Optional; needs `pydot`, which is not in `requirements.txt` |

Java **requires** `-adapter` and `-connect`. The Python SUL currently **ignores `-connect`** and takes the coordinator IEEE from `py/config.yaml` (`zoh_mac` / `hardware_mac` / `zboss_mac`). `-adapter` is used only for `driver_type: hardware` (serial device). For `zoh` and `zboss` it is a dummy required flag.

## Prerequisites

Linux. Java 21 + Maven. Python 3. graphviz (`dot`) if you want PDF models.

```bash
java -version
mvn -version
python3 --version
dot -V
```

Keep the virtualenv **activated** for `java -jar` as well as for Python: jep loads this interpreter.

## Setup

```bash
source scripts/setup_venv.sh
mvn package
```

Then edit `py/config.yaml` for the machine you are on:

- `driver_type: "zoh"` — Zigbee-on-Host over TCP (`zoh_host` / `zoh_port`). Default in the file.
- `driver_type: "hardware"` — WPAN USB serial. `-adapter` must be the real tty.
- `driver_type: "zboss"` — ZBOSS simulator pipes.

Restart scripts still assume a lab layout (`$HOME/Coding/Thesis/suts/zigbee-on-host` for ZOH, `$HOME/Coding/Thesis/hardware_setup` for the Sonoff helper). Change those scripts if your trees live elsewhere.

## Learning (commands that match the code)

Default config is **zoh**. After Zigbee-on-Host is listening on `127.0.0.1:6000`:

```bash
source scripts/setup_venv.sh
java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar @experiments/args/zoh_args
```

`zoh_args` still passes `-adapter` / `-connect` because PSF requires them; they are unused for ZOH.

For **hardware**, set `driver_type: "hardware"` in `py/config.yaml`, then:

```bash
java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar @experiments/args/hw_args \
  -adapter /dev/ttyACM0
```

Replace the tty with your adapter. The coordinator IEEE comes from `hardware_mac` in `config.yaml`, not from `-connect`.

Equivalent expanded command (same alphabet and bound as the arg files):

```bash
java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar state-fuzzer-server \
  -output experiments/results/zoh \
  -alphabet experiments/alphabets/association-nwkEntering.xml \
  -equivalenceQueryBound 5000 \
  -logQueries \
  -adapter unused \
  -connect unused
```

## Replay a test sequence

Symbols in the test file must exist in the alphabet **and** in `PACKET_TEMPLATES`. `experiments/tests/simple_hw_test.txt` does:

```bash
java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar @experiments/args/zoh_args \
  -test experiments/tests/simple_hw_test.txt \
  -times 5
```

## Timing probe

Needs `-test` plus `-probeCmd`. Probe names must be `responseWait` / `startWait` or symbols from the alphabet:

```bash
java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar @experiments/args/zoh_args \
  -test experiments/tests/simple_hw_test.txt \
  -probeCmd responseWait,MAC_BEACON_REQUEST,MAC_ASSOCIATION_REQUEST,ZDO_NODE_DESCRIPTOR_REQUEST \
  -times 7 \
  -probeLow 0 \
  -probeHigh 20000 \
  -probeTol 25 \
  -probeExport timing_alphabet.txt
```

## Differential testing

```bash
java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar diff-test \
  -model-a path/to/modelA.dot \
  -model-b path/to/modelB.dot \
  -alphabet experiments/alphabets/association-nwkEntering.xml
```

## Logging

`src/main/resources/log4j2.xml` sets TRACE for this project and PSF. Override with:

```bash
java -Dlog4j2.configurationFile=/path/to/log4j2.xml -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar ...
```

## Credits

Java wiring follows [ble-fuzzer](https://github.com/protocol-fuzzing/ble-fuzzer). Learning/testing/timing/diff-test are ProtocolState-Fuzzer. `scripts/diff_hyps.sh` is from [edhoc-fuzzer](https://github.com/protocol-fuzzing/edhoc-fuzzer).
