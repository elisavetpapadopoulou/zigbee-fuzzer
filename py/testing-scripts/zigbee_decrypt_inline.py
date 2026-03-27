# Minimal, raw-bytes Zigbee APS decrypter (ZoH/Zigbee 3.0 posture)
# - Works directly on `raw = bytes.fromhex("...")`
# - NONCE = srcEUI(8) || frameCounter_LE(4) || sec_ctrl(1)  (on-wire)
# - AAD  = APS header || Aux Security Header (on-wire), but with ONLY the 3 LSBits
#         of the Aux first byte coerced to ENC_MIC32 in the AAD COPY (NOT in nonce)
# - Expects MIC-32 (4 bytes) at end (Zigbee 3.0 posture)
# - Picks NWK key when key_id==1 (if provided), else TC link key (key_id==2)

from typing import Optional, Tuple
from Cryptodome.Cipher import AES

# 802.15.4 FCF masks (little-endian)
FCF_DADDR_MASK  = 0x0C00
FCF_INTRA_PAN   = 0x0040
FCF_SADDR_MASK  = 0xC000
ADDR_NONE  = 0x0
ADDR_SHORT = 0x2
ADDR_EXT   = 0x3

SEC_LEVEL_MASK = 0x07
ENC_MIC32 = 0x05
MIC_LEN_ZB3 = 4

def _mac_header_len(raw: bytes) -> int:
    if len(raw) < 3:
        raise ValueError("Too short for 802.15.4 header")
    fcf = int.from_bytes(raw[0:2], "little")
    off = 2 + 1  # FCF + seq
    daddr_mode = (fcf & FCF_DADDR_MASK) >> 10
    saddr_mode = (fcf & FCF_SADDR_MASK) >> 14
    intra_pan  = (fcf & FCF_INTRA_PAN) != 0
    if daddr_mode != ADDR_NONE:
        off += 2  # Dest PAN
    if daddr_mode == ADDR_SHORT:
        off += 2
    elif daddr_mode == ADDR_EXT:
        off += 8
    if not intra_pan and saddr_mode != ADDR_NONE:
        off += 2  # Source PAN
    if saddr_mode == ADDR_SHORT:
        off += 2
    elif saddr_mode == ADDR_EXT:
        off += 8
    return off

def _nwk_header_len(raw: bytes, offset: int) -> int:
    # Common NWK data-frame header: 2(ctrl)+2(dst)+2(src)+1(radius)+1(seq) = 8
    if len(raw) < offset + 8:
        raise ValueError("Too short for NWK header")
    return 8

def _aps_header_len_and_vals(raw: bytes, offset: int) -> Tuple[int, int, int]:
    # APS CMD compact header: 2 bytes (fcf, counter). Extend if you need DATA with endpoints.
    if len(raw) < offset + 2:
        raise ValueError("Too short for APS header")
    return 2, raw[offset], raw[offset+1]

def decrypt_raw_aps(
    raw: bytes,
    tc_key: bytes,                   # e.g., b"ZigBeeAlliance09"
    nwk_key: Optional[bytes] = None, # e.g., bytes.fromhex("01030507090b0d0f00020406080a0c0d")
    debug: bool = False,
) -> Tuple[bool, Optional[bytes], str]:
    try:
        # --- Offsets from raw (no scapy re-builds) ---
        mac_len = _mac_header_len(raw)
        nwk_len = _nwk_header_len(raw, mac_len)
        aps_off = mac_len + nwk_len
        aps_len, aps_fcf, aps_ctr = _aps_header_len_and_vals(raw, aps_off)

        # --- Aux Security Header right after APS header ---
        aux_off = aps_off + aps_len
        if len(raw) < aux_off + 5:
            return False, None, "Too short for Aux header"
        sec_ctrl = raw[aux_off]                 # (ext<<5)|(key_id<<3)|level
        fc_le    = raw[aux_off+1:aux_off+5]     # frame counter (LE)
        ext_nonce = (sec_ctrl >> 5) & 1
        key_id    = (sec_ctrl >> 3) & 0x03      # 0=data, 1=nwk, 2=tc-link, 3=load
        level     =  sec_ctrl & 0x07

        cur = aux_off + 5
        if not ext_nonce:
            return False, None, "Extended nonce bit not set; source64 missing"
        if len(raw) < cur + 8:
            return False, None, "Too short for source EUI-64"
        src_eui = raw[cur:cur+8]
        cur += 8

        if key_id == 1:  # NWK key → has 1-byte key sequence
            if len(raw) < cur + 1:
                return False, None, "Too short for key sequence"
            key_seq = raw[cur]
            cur += 1

        # --- Ciphertext || MIC-32 tail (ZoH/ZB3 posture) ---
        if len(raw) < cur + MIC_LEN_ZB3:
            return False, None, "Too short for ciphertext+MIC"
        ct  = raw[cur:-MIC_LEN_ZB3]
        tag = raw[-MIC_LEN_ZB3:]

        # --- NONCE & AAD ---
        # NONCE uses the ON-WIRE sec_ctrl byte (no coercion)
        nonce = src_eui + fc_le + bytes([sec_ctrl])  # 8 + 4 + 1 = 13 bytes

        # AAD(on-wire) = APS header || Aux header
        aad_wire = raw[aps_off:cur]
        # For verification, coerce ONLY the level bits in the first Aux byte to ENC_MIC32 (ZB3.0)
        aad = bytearray(aad_wire)
        aad[aps_len] = (aad[aps_len] & ~SEC_LEVEL_MASK) | (ENC_MIC32 & SEC_LEVEL_MASK)

        # --- Key selection ---
        if key_id == 1 and nwk_key:
            key = nwk_key; key_name = "NWK"
        else:
            key = tc_key;  key_name = "TC"
        if not key or len(key) != 16:
            return False, None, f"Missing/invalid key (key_id={key_id}, using={key_name})"

        # --- AES-CCM decrypt + verify (mac_len=4) ---
        ccm = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=4)
        ccm.update(bytes(aad))
        pt = ccm.decrypt(ct)
        ccm.verify(tag)

        if debug:
            print(f"[OK] key={key_name} key_id={key_id}")
            print(f" mac_len={mac_len} nwk_len={nwk_len} aps_len={aps_len}")
            print(f" aps_fcf=0x{aps_fcf:02x} aps_counter={aps_ctr}")
            print(f" sec_ctrl=0x{sec_ctrl:02x} (ext={ext_nonce} key_id={key_id} level={level})")
            print(" fc_le :", fc_le.hex(), " src_eui:", src_eui.hex())
            print(" nonce :", nonce.hex())
            print(" AAD(w):", aad_wire.hex())
            print(" AAD(z3):", bytes(aad).hex())
            print(" CT    :", ct.hex())
            print(" TAG   :", tag.hex())
            print(" PT    :", pt.hex())

        return True, pt, "ok"

    except Exception as e:
        if debug:
            print("[FAIL]", e)
        return False, None, str(e)

# -------- Example usage with your provided frame --------
if __name__ == "__main__":
    raw = bytes.fromhex(
        "61 88 06 63 69 88 ea 00 00 08 00 88 ea 00 00 1d 04"
        "21 01 30 1e 58 02 00 63 6c 69 63 6c 69 63 6c 1b 86"
        "dd 18 54 34 a8 9b 16 09 7c 75 77 a5 56 16 19 9d 9c"
        "9b cf 28 29 f5 37 18 02 ee 4a 6b 1f 43 24 12 4a 50 75 dc"
    )
    TC_KEY  = b"ZigBeeAlliance09"
    NWK_KEY = bytes.fromhex("01030507090b0d0f00020406080a0c0d")
    ok, pt, msg = decrypt_raw_aps(raw, TC_KEY, NWK_KEY, debug=True)
    if not ok:
        print("[ERROR]", msg)
    else:
        print("PLAINTEXT_HEX:", pt.hex())

