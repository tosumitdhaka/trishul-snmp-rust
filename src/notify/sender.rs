//! Notifier (v1/v2c trap/inform) (← notify/client.py)

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use crate::codec::message::SnmpVersion;
use crate::codec::pdu::{Pdu, PduKind, V1TrapFields};
use crate::error::{Error, ProtocolError};
use crate::manager::response_from_pdu;
use crate::security::SecurityModel;
use crate::security::community::CommunityModel;
use crate::session::{SessionConfig, SnmpSession};
use crate::target::{Target, normalize_target};
use crate::time::{Clock, Rng, SystemClock, SystemRng};
use crate::types::oid::Oid;
use crate::types::value::SnmpValue;
use crate::types::varbind::{Response, VarBind};

/// The sysUpTime.0 instance OID.
pub const SYS_UPTIME_OID: [u32; 9] = [1, 3, 6, 1, 2, 1, 1, 3, 0];
/// The snmpTrapOID.0 instance OID.
pub const SNMP_TRAP_OID: [u32; 11] = [1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0];

/// v1 notifier configuration (← notify/client.py:V1NotifierConfig).
#[derive(Clone)]
pub struct V1NotifierConfig {
    /// Target host.
    pub host: String,
    /// Target UDP port.
    pub port: u16,
    /// Community string.
    pub community: String,
    /// Per-attempt response timeout (default 2s).
    pub timeout: Duration,
    /// Retries after the initial attempt (default 1).
    pub retries: u32,
    /// Clock seam (default SystemClock).
    pub clock: Arc<dyn Clock>,
    /// Randomness seam (default SystemRng).
    pub rng: Arc<dyn Rng>,
}

impl Default for V1NotifierConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 162,
            community: "public".to_string(),
            timeout: Duration::from_secs(2),
            retries: 1,
            clock: Arc::new(SystemClock),
            rng: Arc::new(SystemRng),
        }
    }
}

/// v2c notifier configuration (← notify/client.py:V2cNotifierConfig).
#[derive(Clone)]
pub struct V2cNotifierConfig {
    /// Target host.
    pub host: String,
    /// Target UDP port.
    pub port: u16,
    /// Community string.
    pub community: String,
    /// Per-attempt response timeout (default 2s).
    pub timeout: Duration,
    /// Retries after the initial attempt (default 1).
    pub retries: u32,
    /// Clock seam (default SystemClock).
    pub clock: Arc<dyn Clock>,
    /// Randomness seam (default SystemRng).
    pub rng: Arc<dyn Rng>,
}

impl Default for V2cNotifierConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 162,
            community: "public".to_string(),
            timeout: Duration::from_secs(2),
            retries: 1,
            clock: Arc::new(SystemClock),
            rng: Arc::new(SystemRng),
        }
    }
}

/// v1 TRAP-PDU specification (← notify/client.py:V1TrapSpec).
#[derive(Clone)]
pub struct V1TrapSpec {
    /// Enterprise OID (default 1.3.6.1.4.1).
    pub enterprise: Target,
    /// Agent address (default 0.0.0.0).
    pub agent_addr: Ipv4Addr,
    /// Generic trap number (default 6 = enterpriseSpecific).
    pub generic_trap: u8,
    /// Specific trap number (default 0).
    pub specific_trap: i32,
    /// sysUpTime timestamp (default 0).
    pub timestamp: u32,
    /// Additional varbinds.
    pub varbinds: Vec<(Target, SnmpValue)>,
}

impl Default for V1TrapSpec {
    fn default() -> Self {
        Self {
            enterprise: Target::Numeric(Oid::from_arcs(&[1, 3, 6, 1, 4, 1]).expect("fixed OID")),
            agent_addr: Ipv4Addr::UNSPECIFIED,
            generic_trap: 6,
            specific_trap: 0,
            timestamp: 0,
            varbinds: Vec::new(),
        }
    }
}

/// SNMP notification sender for v1/v2c (v3 constructors land in Phase 3).
///
/// `send_trap`/`send_inform` are single-flight under the session's
/// `request_lock` (the trap path releases the reserved request id on every
/// exit, dispatcher.py discipline).
pub struct Notifier {
    /// The underlying session.
    pub session: SnmpSession,
    /// The wire version.
    pub version: SnmpVersion,
}

impl Notifier {
    /// Connects a v1 notifier.
    pub async fn connect_v1(config: V1NotifierConfig) -> Result<Self, Error> {
        let security = Arc::new(SecurityModel::Community(CommunityModel::new(
            config.community.clone().into_bytes(),
            SnmpVersion::V1,
        )?));
        let session = SnmpSession::connect(SessionConfig {
            host: config.host,
            port: config.port,
            security,
            timeout: config.timeout,
            retries: config.retries,
            rng: config.rng,
        })
        .await?;
        Ok(Self {
            session,
            version: SnmpVersion::V1,
        })
    }

    /// Connects a v2c notifier.
    pub async fn connect_v2c(config: V2cNotifierConfig) -> Result<Self, Error> {
        let security = Arc::new(SecurityModel::Community(CommunityModel::new(
            config.community.clone().into_bytes(),
            SnmpVersion::V2c,
        )?));
        let session = SnmpSession::connect(SessionConfig {
            host: config.host,
            port: config.port,
            security,
            timeout: config.timeout,
            retries: config.retries,
            rng: config.rng,
        })
        .await?;
        Ok(Self {
            session,
            version: SnmpVersion::V2c,
        })
    }

    /// Sends a v2c SNMPv2-TRAP and returns the request id
    /// (← notify/client.py:Notifier.send_trap).
    pub async fn send_trap(
        &self,
        notification: impl Into<Target>,
        varbinds: &[(Target, SnmpValue)],
        uptime: u32,
    ) -> Result<u32, Error> {
        if self.version == SnmpVersion::V1 {
            return Err(Error::Protocol(ProtocolError::new(
                "send_trap requires a v2c notifier",
            )));
        }
        let notification_oid = normalize_target(&notification.into())?;
        let built = build_notification_varbinds(&notification_oid, varbinds, uptime)?;

        let _guard = self.session.request_lock.lock().await;
        let request = self
            .session
            .dispatcher
            .prepare_request(PduKind::SnmpV2Trap, built, 0, 0)?;
        let request_id = request.request_id;
        let result = self.session.dispatcher.send_only(&request).await;
        self.session.dispatcher.release_request(request_id);
        result?;
        Ok(request_id)
    }

    /// Sends a v1 TRAP and returns the effective timestamp (used as the
    /// "request id" in the reference; ← notify/client.py:Notifier.send_v1_trap).
    pub async fn send_v1_trap(&self, spec: V1TrapSpec) -> Result<u32, Error> {
        if self.version != SnmpVersion::V1 {
            return Err(Error::Protocol(ProtocolError::new(
                "send_v1_trap requires a v1 notifier",
            )));
        }
        let enterprise = normalize_target(&spec.enterprise)?;
        let (varbinds, effective_timestamp) =
            build_v1_notification_varbinds(spec.timestamp, &spec.varbinds)?;
        let pdu = Pdu {
            kind: PduKind::Trap,
            request_id: 0,
            error_status: 0,
            error_index: 0,
            varbinds,
            v1_trap: Some(V1TrapFields {
                enterprise,
                agent_addr: spec.agent_addr,
                generic_trap: spec.generic_trap,
                specific_trap: spec.specific_trap,
                timestamp: effective_timestamp,
            }),
        };
        let encoded = self.session.security.wrap_pdu(&pdu)?;

        let _guard = self.session.request_lock.lock().await;
        let request = crate::transport::dispatcher::PreparedRequest {
            request_id: effective_timestamp,
            encoded_message: encoded,
        };
        self.session.dispatcher.send_only(&request).await?;
        Ok(effective_timestamp)
    }

    /// Sends an INFORM and waits for the response (v2c only;
    /// ← notify/client.py:Notifier.send_inform).
    pub async fn send_inform(
        &self,
        notification: impl Into<Target>,
        varbinds: &[(Target, SnmpValue)],
        uptime: u32,
    ) -> Result<Response, Error> {
        if self.version == SnmpVersion::V1 {
            return Err(Error::Protocol(ProtocolError::new(
                "SNMPv1 does not support informs",
            )));
        }
        let notification_oid = normalize_target(&notification.into())?;
        let built = build_notification_varbinds(&notification_oid, varbinds, uptime)?;

        let _guard = self.session.request_lock.lock().await;
        let request =
            self.session
                .dispatcher
                .prepare_request(PduKind::InformRequest, built, 0, 0)?;
        let pdu = self
            .session
            .dispatcher
            .send_prepared_request(request)
            .await?;
        response_from_pdu(pdu)
    }
}

/// Normalizes varbind targets to numeric OIDs (symbolic targets fail without
/// a bundle in Phase 2). Empty lists are valid — notification varbinds are
/// optional, unlike manager targets.
fn normalize_varbind_targets(
    varbinds: &[(Target, SnmpValue)],
) -> Result<Vec<(Oid, SnmpValue)>, Error> {
    let mut out = Vec::with_capacity(varbinds.len());
    for (target, value) in varbinds {
        let oid = normalize_target(target)?;
        out.push((oid, value.clone()));
    }
    Ok(out)
}

fn sys_uptime_oid() -> Oid {
    Oid::from_arcs(&SYS_UPTIME_OID).expect("fixed OID")
}

fn snmp_trap_oid() -> Oid {
    Oid::from_arcs(&SNMP_TRAP_OID).expect("fixed OID")
}

/// Builds the v2c/v3 notification varbind list: `sysUpTime.0`, then
/// `snmpTrapOID.0`, then any extras (← notify/client.py:349–377). Explicit
/// `sysUpTime.0 TimeTicks` / `snmpTrapOID.0 ObjectIdentifier` varbinds
/// override the auto values and are not duplicated in the extras.
pub fn build_notification_varbinds(
    notification_oid: &Oid,
    varbinds: &[(Target, SnmpValue)],
    uptime: u32,
) -> Result<Vec<VarBind>, Error> {
    let normalized = normalize_varbind_targets(varbinds)?;
    let mut sys_uptime = SnmpValue::TimeTicks(uptime);
    let mut trap_oid = SnmpValue::ObjectIdentifier(notification_oid.clone());
    let mut extras: Vec<VarBind> = Vec::new();
    for (oid, value) in normalized {
        if oid == sys_uptime_oid() && matches!(value, SnmpValue::TimeTicks(_)) {
            sys_uptime = value;
            continue;
        }
        if oid == snmp_trap_oid() && matches!(value, SnmpValue::ObjectIdentifier(_)) {
            trap_oid = value;
            continue;
        }
        extras.push(VarBind::new(oid, value));
    }
    let mut out = vec![
        VarBind::new(sys_uptime_oid(), sys_uptime),
        VarBind::new(snmp_trap_oid(), trap_oid),
    ];
    out.extend(extras);
    Ok(out)
}

/// Builds the v1 notification varbind list: `sysUpTime.0` then extras, and
/// returns the effective timestamp (← notify/client.py:_build_v1_raw_varbinds).
pub fn build_v1_notification_varbinds(
    timestamp: u32,
    varbinds: &[(Target, SnmpValue)],
) -> Result<(Vec<VarBind>, u32), Error> {
    let normalized = normalize_varbind_targets(varbinds)?;
    let mut sys_uptime = SnmpValue::TimeTicks(timestamp);
    let mut extras: Vec<VarBind> = Vec::new();
    for (oid, value) in normalized {
        if oid == sys_uptime_oid() && matches!(value, SnmpValue::TimeTicks(_)) {
            sys_uptime = value;
            continue;
        }
        extras.push(VarBind::new(oid, value));
    }
    let effective_timestamp = match &sys_uptime {
        SnmpValue::TimeTicks(value) => *value,
        _ => unreachable!("sys_uptime is always TimeTicks"),
    };
    let mut out = vec![VarBind::new(sys_uptime_oid(), sys_uptime)];
    out.extend(extras);
    Ok((out, effective_timestamp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::Target;
    use std::str::FromStr;

    fn oid(arcs: &[u32]) -> Oid {
        Oid::from_arcs(arcs).unwrap()
    }

    fn target(arcs: &[u32]) -> Target {
        Target::Numeric(oid(arcs))
    }

    #[test]
    fn build_notification_varbinds_adds_standard_bindings() {
        let notification = oid(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 1]);
        let varbinds = vec![
            (
                target(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 7]),
                SnmpValue::Integer(1),
            ),
            (
                target(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 8]),
                SnmpValue::Integer(1),
            ),
        ];
        let built = build_notification_varbinds(&notification, &varbinds, 123).unwrap();
        assert_eq!(built.len(), 4);
        assert_eq!(built[0].oid, sys_uptime_oid());
        assert_eq!(built[0].value, SnmpValue::TimeTicks(123));
        assert_eq!(built[1].oid, snmp_trap_oid());
        assert_eq!(built[1].value, SnmpValue::ObjectIdentifier(notification));
    }

    #[test]
    fn build_notification_varbinds_overrides_explicit_sys_uptime_and_trap_oid() {
        let notification = oid(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 2]);
        let explicit_trap = oid(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 3]);
        let varbinds = vec![
            (
                target(&[1, 3, 6, 1, 2, 1, 1, 3, 0]),
                SnmpValue::TimeTicks(999),
            ),
            (
                target(&[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0]),
                SnmpValue::ObjectIdentifier(explicit_trap.clone()),
            ),
        ];
        let built = build_notification_varbinds(&notification, &varbinds, 123).unwrap();
        assert_eq!(built[0].value, SnmpValue::TimeTicks(999));
        assert_eq!(built[1].value, SnmpValue::ObjectIdentifier(explicit_trap));
        assert_eq!(built.len(), 2);
    }

    #[test]
    fn build_notification_varbinds_rejects_symbolic_without_bundle() {
        let notification = oid(&[1, 3, 6, 1, 6, 3, 1, 1, 5, 1]);
        let symbolic = Target::from_str("IF-MIB::ifDescr.1").unwrap();
        let varbinds = vec![(symbolic, SnmpValue::Integer(1))];
        let err = build_notification_varbinds(&notification, &varbinds, 1).unwrap_err();
        assert!(err.to_string().contains("requires a loaded bundle"));
    }

    #[test]
    fn build_v1_notification_varbinds_uses_effective_timestamp() {
        let varbinds = vec![(
            target(&[1, 3, 6, 1, 2, 1, 1, 3, 0]),
            SnmpValue::TimeTicks(456),
        )];
        let (built, effective) = build_v1_notification_varbinds(123, &varbinds).unwrap();
        assert_eq!(effective, 456);
        assert_eq!(built.len(), 1);
        assert_eq!(built[0].value, SnmpValue::TimeTicks(456));
    }

    #[test]
    fn build_v1_notification_varbinds_defaults_to_input_timestamp() {
        let (built, effective) = build_v1_notification_varbinds(123, &[]).unwrap();
        assert_eq!(effective, 123);
        assert_eq!(built.len(), 1);
        assert_eq!(built[0].value, SnmpValue::TimeTicks(123));
    }
}
