# Zigbee-Fuzzer

Test setup for applying [protocol state fuzzing](https://github.com/protocol-fuzzing/protocol-state-fuzzer) to Zigbee coordinators and stacks. It is built on ProtocolState-Fuzzer 0.2.0 (LearnLib `SUL` API) and can drive either a hardware IEEE 802.15.4 adapter, a Zigbee-on-Host process, or a ZBOSS simulator.

**`src/`** contains Java code that configures ProtocolState-Fuzzer and bridges it to the Python mapper with [jep](https://github.com/ninia/jep) (embedded CPython).

**`py/`** contains the mapper. `ZigbeeSUL` builds and parses Zigbee packets with Scapy and talks to the system under learning through a driver selected in `py/config.yaml`.

**`experiments/alphabets/`** contains input alphabets (subsets of Zigbee / IEEE 802.15.4 message types).

**`experiments/args/`** contains ProtocolState-Fuzzer argument files for runs that have already been used.

**`experiments/results/`** contains models and logs from learning runs.

**`experiments/tests/`** contains concrete input sequences, for reproducing bugs or checking non-determinism.

**`scripts/`** contains helpers for resetting targets, comparing hypotheses, and setting up the Python environment.

## Prerequisites

- Linux (serial adapters, Zigbee-on-Host, and jep are used that way in this project).
- Java 21 JDK and Maven pointed at that JDK.
- Python 3, with a virtualenv for the mapper.
- graphviz (`dot` on `PATH`), so ProtocolState-Fuzzer can export learned models from DOT to PDF.

Check:

```bash
java -version
mvn -version
python3 --version
dot -V
```

## Getting started

1. Create and activate the Python environment (this also installs `requirements.txt`, including jep **4.3.2**, which must match the Java jep dependency):

   ```bash
   source scripts/setup_venv.sh
   ```

2. Edit `py/config.yaml` for the target you will actually run:
   - `driver_type: "hardware"` — IEEE 802.15.4 USB adapter (WPAN serial).
   - `driver_type: "zoh"` — Zigbee-on-Host over TCP (`zoh_host` / `zoh_port`).
   - `driver_type: "zboss"` — ZBOSS simulator over named pipes.

   Update MAC addresses, serial device paths, timeouts, and the restart scripts so they match **your** machine. The checked-in paths are from the original lab setup.

3. Build the fuzzer:

   ```bash
   mvn package
   ```

4. Make sure the chosen stack or adapter is up (for hardware, the adapter should appear as a serial device; for Zigbee-on-Host, `scripts/restartZOHStack.sh` starts the local CLI).

5. Start learning, for example:

   ```bash
   java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar @experiments/args/hw_args \
     -adapter /dev/ttyACM0 \
     -connect 00:12:4B:00:3A:05:3E:FE
   ```

   `-adapter` and `-connect` are required. Override the values in the argument file on the command line as above.

## Arguments

Most ProtocolState-Fuzzer flags can be collected in a file under `experiments/args` and passed with `@`. A full command looks like this:

```bash
java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar state-fuzzer-server \
  -output experiments/results/hardware_trial \
  -alphabet experiments/alphabets/association-nwkEntering.xml \
  -equivalenceQueryBound 5000 \
  -logQueries \
  -adapter /dev/ttyACM0 \
  -connect 00:12:4B:00:3A:05:3E:FE
```

**state-fuzzer-server** means a server-side implementation (a coordinator / stack that accepts joining devices) is being learned. That is the supported mode.

**-output** directory for learned models and statistics.

**-alphabet** XML file of input symbols. If omitted, `src/main/resources/default_alphabet.xml` is used.

**-equivalenceQueryBound** how many tests to use when checking a hypothesis against the SUL. `5000` is the value used in `experiments/args/hw_args`.

**-logQueries** logs membership / equivalence queries.

**-mapper** optional device-specific mapper. If omitted, `py/ZigbeeSUL.py` is used. If set, the mapper `py/ZigbeeSUL_<name>.py` is loaded.

**-adapter** serial device or connection string passed into the Python SUL (for hardware, a tty such as `/dev/ttyACM0`; for some tests, `localhost:6000`).

**-connect** IEEE / MAC address of the device under learning.

**-ceReruns** (ProtocolState-Fuzzer) how many times to re-run a counterexample; useful against wireless non-determinism.

## Testing specific input sequences

To replay a stored sequence (for example to reproduce a bug):

```bash
java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar @experiments/args/hw_args \
  -test experiments/tests/simple_hw_test.txt \
  -times 5
```

Test files list input symbols, either one per line or space-separated on one line.

## Timing probe

Timing is an extension of testing (`-test` plus `-probeCmd`). It searches for wait values that reduce time-related non-determinism. Example:

```bash
java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar @experiments/args/hw_args \
  -test experiments/tests/simple_hw_test.txt \
  -probeCmd responseWait,MAC_BEACON_REQUEST,MAC_ASSOCIATION_REQUEST,ZDO_NODE_DESCRIPTOR_REQUEST \
  -times 7 \
  -probeLow 0 \
  -probeHigh 20000 \
  -probeTol 25 \
  -probeExport timing_alphabet.txt
```

## Differential testing

Compare two learned models that share an alphabet:

```bash
java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar diff-test \
  -model-a path/to/modelA.dot \
  -model-b path/to/modelB.dot \
  -alphabet experiments/alphabets/association-nwkEntering.xml
```

## Logging

Default ProtocolState-Fuzzer log level is `ERROR`. This project ships `src/main/resources/log4j2.xml` with TRACE for the fuzzer and PSF packages. To use another file at runtime:

```bash
java -Dlog4j2.configurationFile=/path/to/log4j2.xml -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar ...
```

## Layout notes

| Path | Role |
| --- | --- |
| `py/config.yaml` | Driver selection and target-specific paths |
| `py/ZigbeeSUL.py` | Abstract-to-concrete mapping |
| `py/ZigbeeDriver.py` | `hardware` / `zoh` / `zboss` driver factory |
| `experiments/alphabets/association-nwkEntering.xml` | Alphabet used for association and network joining |
| `scripts/restartZOHStack.sh` | Restart Zigbee-on-Host |
| `scripts/restartSonoffCoord.sh` | Restore and restart a Sonoff coordinator used as the SUL |
| `scripts/diff_hyps.sh` | Diff the first *n* hypotheses of two result directories |

## Credits

- Java / PSF wiring follows [protocol-fuzzing/ble-fuzzer](https://github.com/protocol-fuzzing/ble-fuzzer).
- Learning, testing, timing, and differential testing come from [ProtocolState-Fuzzer](https://github.com/protocol-fuzzing/protocol-state-fuzzer).
- `scripts/diff_hyps.sh` is copied from [protocol-fuzzing/edhoc-fuzzer](https://github.com/protocol-fuzzing/edhoc-fuzzer).
