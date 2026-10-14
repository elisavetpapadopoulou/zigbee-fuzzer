# Zigbee-Fuzzer

This is a test setup to apply protocol state fuzzing to Zigbee coordinators and stacks. It is built upon the [ProtocolState-Fuzzer](https://github.com/protocol-fuzzing/protocol-state-fuzzer) framework and can be used to either test a hardware IEEE 802.15.4 adapter over-the-air or to test a Zigbee-on-Host (or ZBOSS) stack in a Linux process.

**src/** contains code that configures ProtocolState-Fuzzer (PSF) and acts as a bridge between PSF and the mapper. This is done using [jep](https://github.com/ninia/jep), which allows embedding a CPython interpreter in a Java process.

**py/** contains the mapper. `ZigbeeSUL` uses Scapy to construct and parse IEEE 802.15.4 / Zigbee packets. The radio or stack is selected in `py/config.yaml` (`driver_type`: `hardware`, `zoh`, or `zboss`).

**experiments/alphabets/** contains different alphabets (subsets of Zigbee packet types) that can be used for testing. Use `association-nwkEntering.xml` for learning; it matches the symbols the mapper implements.

**experiments/args/** contains test configurations (lists of PSF arguments) for setups that have already been used.

**experiments/results/** contains results after tests have been run.

**experiments/tests/** contains test sequences of interest. For example, specific test sequences can be run to reproduce bugs.

**scripts/** contains miscellaneous scripts for resetting targets and setting up the Python environment.

## Getting Started

1. Set up and activate a python environment for zigbee-fuzzer: `source scripts/setup_venv.sh`
2. Build zigbee-fuzzer: `mvn package`
3. Edit `py/config.yaml` for the target (`driver_type`, addresses, serial device / TCP port, restart commands). The checked-in restart scripts assume a local Zigbee-on-Host or Sonoff helper tree; change the paths if yours differ.
4. Start the stack or plug in the adapter (for `zoh`, Zigbee-on-Host must be listening on `zoh_host`:`zoh_port`).
5. Start learning. Keep the venv activated so jep can find the interpreter.

Default config is Zigbee-on-Host:

```sh
java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar @experiments/args/zoh_args
```

For hardware, set `driver_type: "hardware"` in `py/config.yaml`, then:

```sh
java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar @experiments/args/hw_args -adapter /dev/ttyACM0
```

### Arguments

For convenience, most required arguments for ProtocolState-Fuzzer have been collected in files under `experiments/args` and can be used on the command line by prefixing the file with an "@" (see [Getting Started](#getting-started) for an example). A full command to start learning would look like this:

```sh
java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar state-fuzzer-server -output experiments/results/zoh -alphabet experiments/alphabets/association-nwkEntering.xml -equivalenceQueryBound 5000 -logQueries -adapter unused -connect unused
```

**state-fuzzer-server** means that a server implementation (a coordinator / stack) is being fuzzed. This is the only supported mode in this setup.

**-output** allows specifying a path to a directory where the learned models and statistics will be written to.

**-alphabet** allows specifying a file with the alphabet (input symbols) used for testing. If unspecified, the default (`src/main/resources/default_alphabet.xml`) will be used. That default still uses symbol names the mapper does not implement; pass `association-nwkEntering.xml` instead.

**-equivalenceQueryBound** allows specifying how many test sequences should be used to check if a generated hypothesis corresponds to the actual behavior of the SUT.

**-logQueries** makes sure that the generated queries are logged for debugging.

**-adapter** must be passed (PSF requires it). For `driver_type: hardware` it is the serial device of the IEEE 802.15.4 adapter. For `zoh` and `zboss` it is unused.

**-connect** must be passed (PSF requires it). The mapper currently takes the coordinator IEEE from `py/config.yaml` (`zoh_mac` / `hardware_mac` / `zboss_mac`), not from this flag.

### Testing Specific Input-Sequences

To test specific input sequences, for example to reproduce a bug, the `-test` flag can be used:

```sh
java -jar target/zigbee-fuzzer-1.0-SNAPSHOT.jar @experiments/args/zoh_args -test experiments/tests/simple_hw_test.txt
```

Specify optionally `-times <n>` to run the input sequence multiple times.

## Credits

* `src/**` PSF wiring follows [protocol-fuzzing/ble-fuzzer](https://github.com/protocol-fuzzing/ble-fuzzer)
* `scripts/diff_hyps.sh` is copied from [protocol-fuzzing/edhoc-fuzzer](https://github.com/protocol-fuzzing/edhoc-fuzzer)
