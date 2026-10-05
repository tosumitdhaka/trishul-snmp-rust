#!/usr/bin/env python
"""Generate the vendored 3DES-EDE authPriv datagram.

Run with the reference implementation's venv (cryptography 48.0.0):

    /home/dhaka/trishul/trishul-snmp/.venv/bin/python generate.py

Deterministic inputs: the engine state (id 80001f88...657374, boots 2,
time 500), msg_id counter starting at 1234, and a fixed GET ScopedPDU
(request_id 0x01020304, sysUpTime.0 TimeTicks 12345). The 3DES salt is
random (usm.py:_fresh_cbc_salt) and is carried by the datagram itself, so
the vendored bytes are self-describing for the decrypt-side test.
"""

import sys

sys.path.insert(0, "/home/dhaka/trishul/trishul-snmp")

from trishul_snmp.security.usm import (
    AuthProtocol,
    PrivProtocol,
    UsmModel,
    UsmUser,
)
from trishul_snmp.types import TimeTicksValue
from trishul_snmp.wire.pdu import Pdu, PduType, RawVarBind
from trishul_snmp.wire.v3message import decode_v3_message

ENGINE_ID = bytes.fromhex("80001f8804726565646572696e76657374")
AUTH_PW = b"authpassword12345"
PRIV_PW = b"privpassword12345"

user = UsmUser(
    username="simulator",
    auth_protocol=AuthProtocol.SHA256,
    auth_key=AUTH_PW,
    priv_protocol=PrivProtocol.THREEDES_EDE,
    priv_key=PRIV_PW,
)
model = UsmModel(user=user)
model._engine_id = ENGINE_ID
model._engine_boots = 2
model._engine_time = 500
model._msg_id_counter = 1234

pdu = Pdu(
    pdu_type=PduType.GET,
    request_id=0x01020304,
    error_status=0,
    error_index=0,
    varbinds=(
        RawVarBind(oid=(1, 3, 6, 1, 2, 1, 1, 3, 0), value=TimeTicksValue(12345)),
    ),
)
raw = model.wrap_pdu(pdu)

key_material = model._priv_key(ENGINE_ID)
auth_kul = model._localize_key(AUTH_PW, ENGINE_ID)

view = decode_v3_message(raw)
print("DATAGRAM_HEX", raw.hex())
print("KEY_MATERIAL_HEX", key_material.hex())
print("AUTH_KUL_HEX", auth_kul.hex())
print("MSG_ID", view.msg_id)
print("FLAGS", view.msg_flags.hex())
print("BOOTS", view.usm_params.engine_boots)
print("TIME", view.usm_params.engine_time)
print("SALT", view.usm_params.priv_params.hex())
print("AUTH_PARAMS", view.usm_params.auth_params.hex())
