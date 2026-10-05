"""Generate deterministic SNMP wire-encoding golden fixtures for tsnmp-r.

Run with the Python reference's venv (the pinned `cryptography` version
matters for the v3 HMAC cases):

    /home/dhaka/trishul/trishul-snmp/.venv/bin/python generate.py

Emits ``golden.json`` next to this script.  Every input is fixed (pinned
request ids, communities, engine ids, keys) so the output is byte-stable.

Coverage:
  * values : all 13 SnmpValue data types, each as a varbind in a v2c
             RESPONSE message, plus one message carrying all 13;
  * v1     : GET, GETNEXT, SET, RESPONSE, TRAP (RFC 1157 trap fields);
  * v2c    : GET, GETNEXT, GETBULK (non-repeaters/max-repetitions),
             RESPONSE with error-status/index, INFORM, SNMPv2-TRAP,
             REPORT (tag 0xA8 — assembled with the library's BER
             primitives, see SOURCE.md);
  * v3     : noAuthNoPriv GET and authNoPriv GET with HMAC-MD5 and the
             RFC 3414 A.2 localized key (pinned engine boots/time).

authPriv is intentionally absent: the library's AES privacy salt is
`os.urandom(8)` with no API to pin it, so an authPriv message is never
byte-reproducible.  See SOURCE.md.
"""

from __future__ import annotations

import json
import platform
from pathlib import Path

import cryptography

import trishul_snmp
from trishul_snmp.security.usm import AuthProtocol, PrivProtocol, UsmModel, UsmUser
from trishul_snmp.types import (
    Counter32Value,
    Counter64Value,
    EndOfMibViewValue,
    Gauge32Value,
    IntegerValue,
    IpAddressValue,
    NoSuchInstanceValue,
    NoSuchObjectValue,
    NullValue,
    ObjectIdentifierValue,
    OctetStringValue,
    OpaqueValue,
    TimeTicksValue,
)
from trishul_snmp.wire.asn1 import encode_value
from trishul_snmp.wire.ber import encode_tlv
from trishul_snmp.wire.message import (
    SNMP_V1_VERSION,
    SNMP_V2C_VERSION,
    SnmpMessage,
    encode_message,
)
from trishul_snmp.wire.pdu import (
    Pdu,
    PduType,
    RawVarBind,
    build_trap_pdu,
)

OUTPUT = Path(__file__).resolve().parent / "golden.json"

COMMUNITY = "public"
SYSUPTIME_OID = (1, 3, 6, 1, 2, 1, 1, 3, 0)
SYSDESCR_OID = (1, 3, 6, 1, 2, 1, 1, 1, 0)
SYSNAME_OID = (1, 3, 6, 1, 2, 1, 1, 5, 0)
SYSLOCATION_OID = (1, 3, 6, 1, 2, 1, 1, 6, 0)

# RFC 3414 A.2: the MD5 localized key of "maplesyrup" against engineID
# 000000000000000000000002 (identical to the draft-reeder Appendix B K1).
RFC3414_A2_ENGINE_ID = bytes.fromhex("000000000000000000000002")
RFC3414_A2_LOCALIZED_MD5_KEY = bytes.fromhex(
    "526f5eed9fcce26f8964c2930787d82b79eff44a90650ee0a3a40abfac5acc12"
)[:16]

ALL_VALUE_CASES: list[tuple[str, object, str]] = [
    ("integer", IntegerValue(42), "INTEGER 42"),
    ("octet-string", OctetStringValue(b"hello"), 'OCTET STRING "hello"'),
    ("null", NullValue(), "NULL"),
    (
        "object-identifier",
        ObjectIdentifierValue((1, 3, 6, 1, 4, 1, 4242)),
        "OBJECT IDENTIFIER 1.3.6.1.4.1.4242",
    ),
    ("ip-address", IpAddressValue("192.0.2.1"), "IpAddress 192.0.2.1"),
    ("counter32", Counter32Value(4294967295), "Counter32 4294967295 (2**32-1)"),
    ("gauge32", Gauge32Value(12345), "Gauge32 12345"),
    ("timeticks", TimeTicksValue(123456), "TimeTicks 123456"),
    ("opaque", OpaqueValue(b"\x00\xff\x10"), "Opaque 00ff10"),
    ("counter64", Counter64Value(2**40), "Counter64 2**40"),
    ("no-such-object", NoSuchObjectValue(), "noSuchObject"),
    ("no-such-instance", NoSuchInstanceValue(), "noSuchInstance"),
    ("end-of-mib-view", EndOfMibViewValue(), "endOfMibView"),
]


def _vb(oid: tuple[int, ...], value: object) -> RawVarBind:
    return RawVarBind(oid=oid, value=value)  # type: ignore[arg-type]


def _v2c_response(request_id: int, varbinds: list[RawVarBind]) -> bytes:
    return encode_message(
        SnmpMessage(
            version=SNMP_V2C_VERSION,
            community=COMMUNITY,
            pdu=Pdu(
                pdu_type=PduType.RESPONSE,
                request_id=request_id,
                error_status=0,
                error_index=0,
                varbinds=tuple(varbinds),
            ),
        )
    )


def _v1_message(pdu: Pdu) -> bytes:
    return encode_message(SnmpMessage(version=SNMP_V1_VERSION, community=COMMUNITY, pdu=pdu))


def _v2c_message(pdu: Pdu) -> bytes:
    return encode_message(SnmpMessage(version=SNMP_V2C_VERSION, community=COMMUNITY, pdu=pdu))


def _report_message(request_id: int, varbinds: list[RawVarBind]) -> bytes:
    """Assemble a v2c REPORT message (PDU tag 0xA8, RFC 3412 §6.2).

    The reference's PduType enum has no REPORT entry, so the PDU body is
    built with the library's own BER/ASN.1 primitives — identical layout
    to any other read/write PDU: request-id, error-status, error-index,
    variable-bindings.
    """
    content = b"".join(
        [
            encode_value(IntegerValue(request_id)),
            encode_value(IntegerValue(0)),
            encode_value(IntegerValue(0)),
            _encode_varbind_list(varbinds),
        ]
    )
    pdu_bytes = encode_tlv(0xA8, content)
    version_and_community = b"".join(
        [
            encode_value(IntegerValue(SNMP_V2C_VERSION)),
            encode_value(OctetStringValue(COMMUNITY.encode())),
        ]
    )
    return encode_tlv(0x30, version_and_community + pdu_bytes)


def _encode_varbind_list(varbinds: list[RawVarBind]) -> bytes:
    content = b"".join(_encode_varbind(vb) for vb in varbinds)
    return encode_tlv(0x30, content)


def _encode_varbind(varbind: RawVarBind) -> bytes:
    content = encode_value(ObjectIdentifierValue(varbind.oid)) + encode_value(varbind.value)
    return encode_tlv(0x30, content)


def _v3_model(user: UsmUser) -> UsmModel:
    """Fresh UsmModel with pinned peer engine state (deterministic wrap)."""
    model = UsmModel(user=user)
    model._engine_id = RFC3414_A2_ENGINE_ID
    model._engine_boots = 1
    model._engine_time = 500
    return model


def _v3_get_request(user: UsmUser, request_id: int) -> bytes:
    model = _v3_model(user)
    return model.wrap_pdu(
        Pdu(
            pdu_type=PduType.GET,
            request_id=request_id,
            error_status=0,
            error_index=0,
            varbinds=(_vb(SYSUPTIME_OID, NullValue()),),
        )
    )


def build_cases() -> list[dict[str, str]]:
    cases: list[dict[str, str]] = []

    # ── values: all 13 SnmpValue types as varbinds ──────────────────────
    for index, (name, value, description) in enumerate(ALL_VALUE_CASES):
        cases.append(
            {
                "name": f"value-{name}",
                "description": f"v2c RESPONSE carrying one {description} varbind",
                "hex": _v2c_response(2001 + index, [_vb((1, 3, 6, 1, 4, 1, 99999, index + 1), value)]).hex(),
            }
        )
    cases.append(
        {
            "name": "value-all-types",
            "description": "v2c RESPONSE carrying all 13 SnmpValue types, one per varbind",
            "hex": _v2c_response(
                2014,
                [
                    _vb((1, 3, 6, 1, 4, 1, 99999, arc), value)
                    for arc, (_name, value, _descr) in enumerate(ALL_VALUE_CASES, start=1)
                ],
            ).hex(),
        }
    )

    # ── v1 ───────────────────────────────────────────────────────────────
    cases.append(
        {
            "name": "v1-get",
            "description": "SNMPv1 GET request, two NULL varbinds, request-id 1001",
            "hex": _v1_message(
                Pdu(
                    pdu_type=PduType.GET,
                    request_id=1001,
                    error_status=0,
                    error_index=0,
                    varbinds=(
                        _vb(SYSUPTIME_OID, NullValue()),
                        _vb(SYSDESCR_OID, NullValue()),
                    ),
                )
            ).hex(),
        }
    )
    cases.append(
        {
            "name": "v1-getnext",
            "description": "SNMPv1 GETNEXT request, request-id 1002",
            "hex": _v1_message(
                Pdu(
                    pdu_type=PduType.GET_NEXT,
                    request_id=1002,
                    error_status=0,
                    error_index=0,
                    varbinds=(_vb((1, 3, 6, 1, 2, 1), NullValue()),),
                )
            ).hex(),
        }
    )
    cases.append(
        {
            "name": "v1-set",
            "description": "SNMPv1 SET request, request-id 1003",
            "hex": _v1_message(
                Pdu(
                    pdu_type=PduType.SET,
                    request_id=1003,
                    error_status=0,
                    error_index=0,
                    varbinds=(
                        _vb(SYSLOCATION_OID, OctetStringValue(b"server room")),
                        _vb(SYSNAME_OID, OctetStringValue(b"goldengate")),
                    ),
                )
            ).hex(),
        }
    )
    cases.append(
        {
            "name": "v1-response",
            "description": "SNMPv1 RESPONSE, no error, request-id 1004",
            "hex": _v1_message(
                Pdu(
                    pdu_type=PduType.RESPONSE,
                    request_id=1004,
                    error_status=0,
                    error_index=0,
                    varbinds=(
                        _vb(SYSDESCR_OID, OctetStringValue(b"golden v1 agent")),
                        _vb(SYSUPTIME_OID, TimeTicksValue(654321)),
                    ),
                )
            ).hex(),
        }
    )
    cases.append(
        {
            "name": "v1-trap",
            "description": (
                "SNMPv1 TRAP (RFC 1157 fields: enterprise 1.3.6.1.4.1.8072, "
                "agent-addr 127.0.0.1, generic 0 coldStart, specific 0, "
                "timestamp 123456), one sysUpTime varbind"
            ),
            "hex": _v1_message(
                build_trap_pdu(
                    enterprise=(1, 3, 6, 1, 4, 1, 8072),
                    agent_addr="127.0.0.1",
                    generic_trap=0,
                    specific_trap=0,
                    timestamp=123456,
                    varbinds=(_vb(SYSUPTIME_OID, TimeTicksValue(123456)),),
                )
            ).hex(),
        }
    )

    # ── v2c ───────────────────────────────────────────────────────────────
    cases.append(
        {
            "name": "v2c-get",
            "description": "SNMPv2c GET request, request-id 1101",
            "hex": _v2c_message(
                Pdu(
                    pdu_type=PduType.GET,
                    request_id=1101,
                    error_status=0,
                    error_index=0,
                    varbinds=(_vb(SYSUPTIME_OID, NullValue()),),
                )
            ).hex(),
        }
    )
    cases.append(
        {
            "name": "v2c-getnext",
            "description": "SNMPv2c GETNEXT request, request-id 1102",
            "hex": _v2c_message(
                Pdu(
                    pdu_type=PduType.GET_NEXT,
                    request_id=1102,
                    error_status=0,
                    error_index=0,
                    varbinds=(_vb((1, 3, 6, 1, 2, 1, 2), NullValue()),),
                )
            ).hex(),
        }
    )
    cases.append(
        {
            "name": "v2c-getbulk",
            "description": (
                "SNMPv2c GETBULK request, non-repeaters 1 (error_status field) "
                "and max-repetitions 2 (error_index field), request-id 1103"
            ),
            "hex": _v2c_message(
                Pdu(
                    pdu_type=PduType.GET_BULK,
                    request_id=1103,
                    error_status=1,
                    error_index=2,
                    varbinds=(
                        _vb(SYSDESCR_OID, NullValue()),
                        _vb((1, 3, 6, 1, 2, 1, 2, 1), NullValue()),
                    ),
                )
            ).hex(),
        }
    )
    cases.append(
        {
            "name": "v2c-response-error",
            "description": (
                "SNMPv2c RESPONSE with error-status 2 (noSuchName) and "
                "error-index 1, request-id 1104"
            ),
            "hex": _v2c_message(
                Pdu(
                    pdu_type=PduType.RESPONSE,
                    request_id=1104,
                    error_status=2,
                    error_index=1,
                    varbinds=(
                        _vb(SYSDESCR_OID, NullValue()),
                        _vb((1, 3, 6, 1, 2, 1, 99, 99), NoSuchInstanceValue()),
                    ),
                )
            ).hex(),
        }
    )
    cases.append(
        {
            "name": "v2c-inform",
            "description": (
                "SNMPv2c INFORM request (coldStart, sysUpTime + snmpTrapOID "
                "varbinds), request-id 1105"
            ),
            "hex": _v2c_message(
                Pdu(
                    pdu_type=PduType.INFORM_REQUEST,
                    request_id=1105,
                    error_status=0,
                    error_index=0,
                    varbinds=(
                        _vb((1, 3, 6, 1, 2, 1, 1, 3, 0), TimeTicksValue(42)),
                        _vb(
                            (1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0),
                            ObjectIdentifierValue((1, 3, 6, 1, 6, 3, 1, 1, 5, 1)),
                        ),
                    ),
                )
            ).hex(),
        }
    )
    cases.append(
        {
            "name": "v2c-snmpv2-trap",
            "description": (
                "SNMPv2c SNMPv2-TRAP (coldStart, sysUpTime + snmpTrapOID "
                "varbinds), no request-id semantics (id 0)"
            ),
            "hex": _v2c_message(
                Pdu(
                    pdu_type=PduType.SNMPV2_TRAP,
                    request_id=0,
                    error_status=0,
                    error_index=0,
                    varbinds=(
                        _vb((1, 3, 6, 1, 2, 1, 1, 3, 0), TimeTicksValue(42)),
                        _vb(
                            (1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0),
                            ObjectIdentifierValue((1, 3, 6, 1, 6, 3, 1, 1, 5, 1)),
                        ),
                    ),
                )
            ).hex(),
        }
    )
    cases.append(
        {
            "name": "v2c-report",
            "description": (
                "SNMPv2c REPORT (PDU tag 0xA8) carrying "
                "usmStatsUnknownUserNames.0 Counter32 1, request-id 1106 "
                "(assembled with the library BER primitives)"
            ),
            "hex": _report_message(
                1106,
                [_vb((1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0), Counter32Value(1))],
            ).hex(),
        }
    )

    # ── v3 ───────────────────────────────────────────────────────────────
    cases.append(
        {
            "name": "v3-noauthnopriv-get",
            "description": (
                "SNMPv3 noAuthNoPriv GET (flags 0x04), user 'golden', engineID "
                "000000000000000000000002, boots 1, time 500, msg-id 1, "
                "request-id 1201"
            ),
            "hex": _v3_get_request(UsmUser(username="golden"), 1201).hex(),
        }
    )
    cases.append(
        {
            "name": "v3-authnopriv-get-md5",
            "description": (
                "SNMPv3 authNoPriv GET (flags 0x05), HMAC-MD5 with the RFC 3414 "
                "A.2 localized key of 'maplesyrup' (16 octets), user 'golden', "
                "engineID 000000000000000000000002, boots 1, time 500, msg-id 1, "
                "request-id 1202"
            ),
            "hex": _v3_get_request(
                UsmUser(
                    username="golden",
                    auth_protocol=AuthProtocol.MD5,
                    auth_key=RFC3414_A2_LOCALIZED_MD5_KEY,
                    auth_key_localized=True,
                ),
                1202,
            ).hex(),
        }
    )

    return cases


def main() -> None:
    cases = build_cases()
    payload = {
        "meta": {
            "trishul_snmp_version": trishul_snmp.__version__,
            "cryptography_version": cryptography.__version__,
            "python_version": platform.python_version(),
        },
        "cases": cases,
    }
    OUTPUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT} with {len(cases)} cases")


if __name__ == "__main__":
    main()
