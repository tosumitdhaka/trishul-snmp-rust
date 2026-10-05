//! Typed-side hardening: trap ranges, tag agreement (← asn1.py, reduced — see §5.3a)
//!
//! Unsigned-minimality checks live in the manual `SnmpValue` Decode
//! (types/value.rs, §5.3a item 3); this module keeps only what post-decode
//! state can see. The v3 tag-vs-privParams agreement check (msgData tag must
//! match the PRIV flag, test_v3_wire.py:330/348) gates with the V3Message
//! codec in Phase 3.

use crate::error::ProtocolError;

/// Validates v1 Trap-PDU field ranges shared by encode and decode
/// (pdu.py:264–270): generic-trap must be 0..=6, specific-trap non-negative.
pub(crate) fn validate_trap_fields(
    generic_trap: i64,
    specific_trap: i64,
) -> Result<(u8, i32), ProtocolError> {
    if !(0..=6).contains(&generic_trap) {
        return Err(ProtocolError::new(format!(
            "generic-trap {generic_trap} must be between 0 and 6"
        )));
    }
    if specific_trap < 0 {
        return Err(ProtocolError::new(format!(
            "specific-trap {specific_trap} cannot be negative"
        )));
    }
    Ok((generic_trap as u8, specific_trap as i32))
}
