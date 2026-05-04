def split_out(out):
    if not out or out == "EMPTYRESPONSE":
        return set()
    return set(out.split("+"))

def join_out(outs):
    return "+".join(sorted(outs)) if outs else "EMPTYRESPONSE"

def normalize_beacons(inputs, outputs):
    outs = [split_out(o) for o in outputs]
    pending = []

    for i in range(len(outs)):
        outs[i].discard("MAC_ACK")

    for i, inp in enumerate(inputs):
        outs[i].discard("MAC_ACK")

        has_beacon = "MAC_BEACON" in outs[i]

        if inp == "MAC_BEACON_REQUEST":
            if has_beacon:
                for j in pending:
                    outs[j].add("MAC_BEACON")
                pending.clear()
            else:
                pending.append(i)

        elif has_beacon and pending:
            for j in pending:
                outs[j].add("MAC_BEACON")
            pending.clear()

        # beacons only belong to beacon requests
        if inp != "MAC_BEACON_REQUEST":
            outs[i].discard("MAC_BEACON")

    return list(inputs), [join_out(o) for o in outs]

# print(normalize_beacons(["MAC_BEACON_REQUEST", "MAC_BEACON_REQUEST", "MAC_BEACON_REQUEST", "MAC_BEACON_REQUEST", "MAC_BEACON_REQUEST", "MAC_ASSOCIATION_REQUEST", "MAC_DATA_REQUEST"], ["EMPTYRESPONSE", "EMPTYRESPONSE", "MAC_ACK+MAC_BEACON", "MAC_BEACON", "MAC_BEACON", "APS_CMD_TRANSPORT_NWK_KEY", "EMPTYRESPONSE"]))
