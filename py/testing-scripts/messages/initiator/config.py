MAC_FRAME_TYPES = {
    0: "0b000: MAC Beacon",
    1: "0b001: MAC Data",
    2: "0b010: MAC Acknowledgment",
    3: "0b011: MAC Command",
}

MAC_SECURITY_STATES = {
    0: "0b0: MAC Security Disabled",
    1: "0b1: MAC Security Enabled",
}

MAC_FP_STATES = {
    0: "0b0: No additional packets are pending for the receiver",
    1: "0b1: Additional packets are pending for the receiver",
}

MAC_AR_STATES = {
    0: "0b0: The sender does not request a MAC Acknowledgment",
    1: "0b1: The sender requests a MAC Acknowledgment",
}

MAC_PIC_STATES = {
    0: "0b0: Do not compress the source PAN ID",
    1: "0b1: The source PAN ID is the same as the destination PAN ID",
}

MAC_DA_MODES = {
    0: "0b00: No destination MAC address",
    2: "0b10: Short destination MAC address",
    3: "0b11: Extended destination MAC address",
}

MAC_FRAME_VERSIONS = {
    0: "0b00: IEEE 802.15.4-2003 Frame Version",
    1: "0b01: IEEE 802.15.4-2006 Frame Version",
    2: "0b10: IEEE 802.15.4-2015 Frame Version",
}

MAC_SA_MODES = {
    0: "0b00: No source MAC address",
    2: "0b10: Short source MAC address",
    3: "0b11: Extended source MAC address",
}

MAC_SECURITY_LEVELS = {
    0: "0b000: None",
    1: "0b001: MIC-32",
    2: "0b010: MIC-64",
    3: "0b011: MIC-128",
    4: "0b100: ENC",
    5: "0b101: ENC-MIC-32",
    6: "0b110: ENC-MIC-64",
    7: "0b111: ENC-MIC-128",
}

MAC_KEY_ID_MODES = {
    0: "0b00: Implicit key determination",
    1: "0b01: Explicit key determination with the 8-byte default key source",
    2: "0b10: Explicit key determination with the 4-byte Key Source subfield",
    3: "0b11: Explicit key determination with the 8-byte Key Source subfield",
}

MAC_COMMANDS = {
    1: "0x01: MAC Association Request",
    2: "0x02: MAC Association Response",
    3: "0x03: MAC Disassociation Notification",
    4: "0x04: MAC Data Request",
    5: "0x05: MAC PAN ID Conflict Notification",
    6: "0x06: MAC Orphan Notification",
    7: "0x07: MAC Beacon Request",
    8: "0x08: MAC Coordinator Realignment",
    9: "0x09: MAC GTS Request",
}

APC_STATES = {
    0: "0b0: The sender is not capable of becoming a PAN coordinator",
    1: "0b1: The sender is capable of becoming a PAN coordinator",
}

DEVICE_TYPES = {
    0: "0b0: Reduced-Function Device",
    1: "0b1: Full-Function Device",
}

POWER_SOURCES = {
    0: "0b0: The sender is not a mains-powered device",
    1: "0b1: The sender is a mains-powered device",
}

RXIDLE_STATES = {
    0: "0b0: Disables the receiver to conserve power when idle",
    1: "0b1: Does not disable the receiver to conserve power",
}

SECURITY_CAPABILITIES = {
    0: "0b0: Cannot transmit and receive secure MAC frames",
    1: "0b1: Can transmit and receive secure MAC frames",
}

ALLOCADDR_STATES = {
    0: "0b0: Does not request a short address",
    1: "0b1: Requests a short address",
}

ASSOC_STATUSES = {
    0: "0x00: Association successful",
    1: "0x01: PAN at capacity",
    2: "0x02: PAN access denied",
}

DISASSOC_REASONS = {
    1: "0x01: The coordinator wishes the device to leave the PAN",
    2: "0x02: The device wishes to leave the PAN",
}

GTS_DIRECTIONS = {
    0: "0b0: Transmit-Only GTS",
    1: "0b1: Receive-Only GTS",
}

GTS_CHARACTERISTICS_TYPES = {
    0: "0b0: GTS Deallocation",
    1: "0b1: GTS Allocation",
}

PANCOORDINATOR_STATES = {
    0: "0b0: The sender is not the PAN coordinator",
    1: "0b1: The sender is the PAN coordinator",
}

ASSOCPERMIT_STATES = {
    0: "0b0: The sender is currently not accepting association requests",
    1: "0b1: The sender is currently accepting association requests",
}
MAC_FRAME_CONTROL = {
    "fcf_panidcompress": 1,
    "fcf_ackreq": 0,
    "fcf_pending": 0,
    "fcf_srcaddrmode": 2,
    "fcf_framever" : 0,
    "fcf_destaddrmode": 2,
}
DEFAULT_MAC_BEACON_CONFIG = {
    "src_panid": 0x0,
    "src_addr": 0x0,
    "sf_sforder": 15,
    "sf_beaconorder": 15,
    "sf_assocpermit": 0,
    "sf_pancoord": 0,
    "sf_reserved": 0,
    "sf_battlifeextend": 0,
    "sf_finalcapslot": 15,
    "gts_spec_permit": 0,
    "gts_spec_reserved": 0,
    "gts_spec_desccount": 0,
    "pa_reserved_1": 0,
    "pa_num_long": 0,
    "pa_reserved_2": 0,
    "pa_num_short": 0,
    "pa_short_addresses": [],
    "pa_long_addresses": []
}

DEFAULT_ΜAC_COMMAND_CONFIG = {
    ""
}

DEFAULT_MAC_ACK_CONFIG  = {

        }

DEFAULT_MAC_

