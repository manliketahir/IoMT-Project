#!/usr/bin/env python3
"""Shared HL7 v2 / MLLP helpers for E6.

One module so the gateway, the listener and both attack harnesses agree on
framing, nomenclature codes and message shape. If they disagree, the
experiment measures the disagreement instead of the mitigation.

MLLP framing (Minimal Lower Layer Protocol) is three bytes around the
message: <SB> message <EB><CR>, where segments inside the message are
separated by CR, not LF. Getting that wrong is the classic HL7 integration
bug, so it lives in exactly one place here.
"""

SB = b"\x0b"        # start block
EB = b"\x1c"        # end block
CR = b"\x0d"        # carriage return, also the segment separator
SEG = "\r"

# IANA-registered port for HL7 MLLP.
MLLP_PORT = 2575

# IEEE 11073-10101 nomenclature: metric -> (code, mnemonic, unit code, unit
# mnemonic). The three vital codes are the ones already used by the plane-B
# MQTT->DDS adapter, so a reading keeps the same code across both bridges.
#
# NOTE: the vital codes come from the adapter and are settled. The *unit*
# codes below should be checked against the 11073-10101 table before
# publication; they are not load-bearing for any E6 measurement (nothing
# keys on OBX-6), but they are visible in the recorded messages.
NOM = {
    "heartrate": (147842, "MDC_ECG_HEART_RATE", 264864, "MDC_DIM_BEAT_PER_MIN"),
    "spo2":      (150456, "MDC_PULS_OXIM_SAT_O2", 262688, "MDC_DIM_PERCENT"),
    "resp":      (151562, "MDC_RESP_RATE", 264928, "MDC_DIM_RESP_PER_MIN"),
}

# Physiological plausibility bounds per code. hl7apy validates structure
# against the HL7 schema but does NOT range-check values: OBX-5 = 9999 for a
# heart rate passes schema validation. So this check is ours.
#
# It is deliberately wide. It is not a detector and must not be described as
# one: it rejects a clumsy forgery, not a plausible one. E6a's forged value is
# inside these bounds by design, because the question E6a asks is whether an
# unauthenticated peer can write a *believable* value, not a silly one.
RANGE = {
    147842: (20.0, 300.0),    # heart rate, bpm
    150456: (50.0, 100.0),    # SpO2, %
    151562: (4.0, 60.0),      # respiration rate, breaths/min
}

# MSH is encoded specially: MSH-1 is the field separator itself and MSH-2 is
# the four encoding characters, so the header literal reads "MSH|^~\&|...".
# _ENC therefore holds the encoding characters WITHOUT a leading pipe -- the
# pipe is the separator printed by the format string. Including it here yields
# "MSH||^~\&|" and hl7apy rejects the message with
# "InvalidEncodingChars: Missing required encoding chars".
_ENC = r"^~\&"
_UNSAFE = "|^~\\&\r\n"


def clean(s) -> str:
    """Strip HL7 delimiters out of a value so it cannot break the encoding."""
    return "".join(c for c in str(s) if c not in _UNSAFE)


def frame(msg: str) -> bytes:
    """Wrap an ER7 message in MLLP framing."""
    return SB + msg.encode("utf-8") + EB + CR


def deframe(buf: bytes):
    """Pull complete MLLP frames out of a stream buffer.

    Returns (messages, remainder). The remainder is carried into the next
    read, so a frame split across TCP segments is reassembled rather than
    dropped -- which a single recv() per message would get wrong under load,
    exactly when E6b is applying load.
    """
    msgs = []
    while True:
        s = buf.find(SB)
        if s < 0:
            # Nothing framed in here. Anything before a start block is not a
            # valid frame, so it is discarded rather than buffered forever.
            return msgs, b""
        e = buf.find(EB + CR, s)
        if e < 0:
            return msgs, buf[s:]        # partial frame, keep it
        msgs.append(buf[s + len(SB):e].decode("utf-8", "replace"))
        buf = buf[e + 2:]


def ts(t=None) -> str:
    """HL7 timestamp, YYYYMMDDHHMMSS."""
    import time
    return time.strftime("%Y%m%d%H%M%S", time.localtime(t))


def msg_id(pub_id: str, seq) -> str:
    """MSH-10. Unique per message across a run, and splittable in analysis.

    seq alone collides across beds, and MSH-10 is what the ACK echoes in
    MSA-2, so correlation needs the bed in it too.
    """
    return f"{clean(pub_id)}-{clean(seq)}"


def split_msg_id(mid: str):
    """'bed-7-42' -> ('bed-7', '42'). Inverse of msg_id()."""
    pub, _, seq = mid.rpartition("-")
    return pub, seq


def build_oru(pub_id: str, seq, value, metric="heartrate",
              sending_app="IOMT-GW", sending_fac="WARD-B",
              recv_app="CLIN-LIS", recv_fac="CLIN-C", when=None) -> str:
    """An IHE PCD-01 style ORU^R01 observation message.

    PID-5 (patient name) is required by the v2.5 schema -- a message without
    it is rejected, which cost a debugging cycle to discover. The name is
    obviously synthetic (SYNTH^...) because the vitals are synthetic; nothing
    here represents a real person.
    """
    code, mnem, ucode, umnem = NOM[metric]
    mid = msg_id(pub_id, seq)
    bed = clean(pub_id)
    segs = [
        f"MSH|{_ENC}|{sending_app}|{sending_fac}|{recv_app}|{recv_fac}|"
        f"{ts(when)}||ORU^R01^ORU_R01|{mid}|P|2.5",
        f"PID|1||{bed}||SYNTH^{bed.upper()}",
        f"OBR|1||{mid}|{code}^{mnem}^MDC",
        f"OBX|1|NM|{code}^{mnem}^MDC||{clean(value)}|{ucode}^{umnem}^MDC"
        f"|||||F",
    ]
    return SEG.join(segs)


def build_ack(mid: str, code="AA", text="",
              sending_app="CLIN-LIS", sending_fac="CLIN-C",
              recv_app="IOMT-GW", recv_fac="WARD-B") -> str:
    """ACK^R01. MSA-1 is AA (accept), AE (error) or AR (reject).

    Built by hand rather than through hl7apy.core.Message: the listener builds
    one of these per message while E6 is measuring its ACK latency, and
    constructing a Message object costs far more than formatting a string.
    The shape is fixed and trivial, so there is nothing for a library to get
    right here.
    """
    msa = f"MSA|{code}|{clean(mid)}"
    if text:
        msa += f"|{clean(text)[:80]}"
    segs = [
        f"MSH|{_ENC}|{sending_app}|{sending_fac}|{recv_app}|{recv_fac}|"
        f"{ts()}||ACK^R01^ACK|{clean(mid)}-A|P|2.5",
        msa,
    ]
    return SEG.join(segs)


def ack_code(msg: str):
    """Pull MSA-1 and MSA-2 out of an ACK. Returns (code, control_id)."""
    for seg in msg.split(SEG):
        if seg.startswith("MSA|"):
            f = seg.split("|")
            return (f[1] if len(f) > 1 else ""), (f[2] if len(f) > 2 else "")
    return "", ""
