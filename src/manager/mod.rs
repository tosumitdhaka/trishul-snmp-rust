//! Manager (v1/v2c constructors), get/… (← client.py)

pub mod v1_bulk;
pub mod walk;

use std::sync::Arc;
use std::time::Duration;

use crate::codec::message::SnmpVersion;
use crate::codec::pdu::{PduKind, response_error_status};
use crate::error::Error;
use crate::manager::walk::WalkOptions;
use crate::security::SecurityModel;
use crate::security::community::CommunityModel;
use crate::session::{SessionConfig, SnmpSession};
use crate::target::{Target, normalize_targets};
use crate::time::{Clock, Rng, SystemClock, SystemRng};
use crate::types::oid::Oid;
use crate::types::value::SnmpValue;
use crate::types::varbind::{Response, VarBind};

/// v1 manager configuration (← client.py:V1Config).
#[derive(Clone)]
pub struct V1Config {
    /// Remote host.
    pub host: String,
    /// Remote UDP port (default 161).
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

impl Default for V1Config {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 161,
            community: "public".to_string(),
            timeout: Duration::from_secs(2),
            retries: 1,
            clock: Arc::new(SystemClock),
            rng: Arc::new(SystemRng),
        }
    }
}

/// v2c manager configuration (← client.py:V2cConfig).
#[derive(Clone)]
pub struct V2cConfig {
    /// Remote host.
    pub host: String,
    /// Remote UDP port (default 161).
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

impl Default for V2cConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 161,
            community: "public".to_string(),
            timeout: Duration::from_secs(2),
            retries: 1,
            clock: Arc::new(SystemClock),
            rng: Arc::new(SystemRng),
        }
    }
}

/// SNMP manager for v1/v2c (connect_v3 is Phase 3).
///
/// # Lock discipline
///
/// `get`/`get_next`/`get_bulk` acquire the session's `request_lock` once for a
/// single exchange; `walk`/`bulkwalk` and the V1 GETBULK downgrade acquire it
/// per request (walk.py:19–27; §5.5).
pub struct Manager {
    /// The underlying session.
    pub session: SnmpSession,
    /// The wire version.
    pub version: SnmpVersion,
}

impl Manager {
    /// Connects a v1 manager.
    pub async fn connect_v1(config: V1Config) -> Result<Self, Error> {
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

    /// Connects a v2c manager.
    pub async fn connect_v2c(config: V2cConfig) -> Result<Self, Error> {
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

    /// Issues a GET request (← client.py:get).
    pub async fn get(
        &self,
        targets: impl IntoIterator<Item = impl Into<Target>>,
    ) -> Result<Response, Error> {
        self.request(PduKind::GetRequest, targets, 0, 0).await
    }

    /// Issues a GETNEXT request (← client.py:get_next).
    pub async fn get_next(
        &self,
        targets: impl IntoIterator<Item = impl Into<Target>>,
    ) -> Result<Response, Error> {
        self.request(PduKind::GetNextRequest, targets, 0, 0).await
    }

    /// Issues a GETBULK request. For v1 this transparently downgrades to a
    /// GETNEXT composite (← client.py:get_bulk, client.py:229–308).
    pub async fn get_bulk(
        &self,
        targets: impl IntoIterator<Item = impl Into<Target>>,
        non_repeaters: u32,
        max_repetitions: u32,
    ) -> Result<Response, Error> {
        if self.version == SnmpVersion::V1 {
            v1_bulk::v1_get_bulk(self, targets, non_repeaters, max_repetitions).await
        } else {
            self.request(
                PduKind::GetBulkRequest,
                targets,
                non_repeaters as i32,
                max_repetitions as i32,
            )
            .await
        }
    }

    /// Walks the subtree rooted at `root` (GETNEXT for v1, GETBULK for v2c
    /// unless `bulk` is disabled; ← client.py:walk).
    pub async fn walk(
        &self,
        root: impl Into<Target>,
        opts: WalkOptions,
    ) -> Result<Vec<VarBind>, Error> {
        let root = root.into();
        let root_oid = crate::target::normalize_target(&root)?;
        let bulk = self.version != SnmpVersion::V1 && opts.bulk;
        let request_fn = |current: &Oid, max_repetitions: Option<u32>| {
            let this = self;
            let current = current.clone();
            async move {
                match max_repetitions {
                    Some(count) => this.get_bulk_oid(&current, count).await,
                    None => this.get_next_oid(&current).await,
                }
            }
        };
        crate::manager::walk::walk_subtree(
            request_fn,
            &root_oid,
            bulk,
            opts.max_repetitions,
            self.version == SnmpVersion::V1,
        )
        .await
    }

    /// Bulk walk (v1 downgrades to GETNEXT walks; ← client.py:bulkwalk).
    pub async fn bulkwalk(
        &self,
        root: impl Into<Target>,
        opts: WalkOptions,
    ) -> Result<Vec<VarBind>, Error> {
        self.walk(root, opts).await
    }

    /// Single GETNEXT (used by the walk machinery).
    pub(crate) async fn get_next_oid(&self, oid: &Oid) -> Result<Response, Error> {
        let varbinds = vec![VarBind::new(oid.clone(), SnmpValue::Null)];
        let _guard = self.session.request_lock.lock().await;
        let pdu = self
            .session
            .dispatcher
            .send_pdu(PduKind::GetNextRequest, varbinds, 0, 0)
            .await?;
        response_from_pdu(pdu)
    }

    /// Single GETBULK (used by the bulk walk machinery).
    pub(crate) async fn get_bulk_oid(
        &self,
        oid: &Oid,
        max_repetitions: u32,
    ) -> Result<Response, Error> {
        let varbinds = vec![VarBind::new(oid.clone(), SnmpValue::Null)];
        let _guard = self.session.request_lock.lock().await;
        let pdu = self
            .session
            .dispatcher
            .send_pdu(PduKind::GetBulkRequest, varbinds, 0, max_repetitions as i32)
            .await?;
        response_from_pdu(pdu)
    }

    /// The shared single-exchange path: normalize targets, build null
    /// varbinds, exchange under one lock, retrying once on adopted engine
    /// recovery (← client.py:_request; §5.4).
    async fn request(
        &self,
        kind: PduKind,
        targets: impl IntoIterator<Item = impl Into<Target>>,
        error_status: i32,
        error_index: i32,
    ) -> Result<Response, Error> {
        let targets: Vec<Target> = targets.into_iter().map(Into::into).collect();
        let oids = normalize_targets(&targets)?;
        let varbinds: Vec<VarBind> = oids
            .iter()
            .map(|oid| VarBind::new(oid.clone(), SnmpValue::Null))
            .collect();
        let _guard = self.session.request_lock.lock().await;
        let pdu = match self
            .session
            .dispatcher
            .send_pdu(kind, varbinds.clone(), error_status, error_index)
            .await
        {
            Ok(pdu) => pdu,
            Err(Error::EngineRecovery(_)) => {
                // Adopt the recovery report and retry once.
                self.session
                    .dispatcher
                    .send_pdu(kind, varbinds, error_status, error_index)
                    .await?
            }
            Err(other) => return Err(other),
        };
        response_from_pdu(pdu)
    }
}

/// Converts a raw RESPONSE PDU into the public response model
/// (← client.py:response_from_pdu).
pub fn response_from_pdu(pdu: crate::codec::pdu::Pdu) -> Result<Response, Error> {
    let error_status = response_error_status(pdu.error_status)?;
    Ok(Response {
        request_id: pdu.request_id,
        error_status,
        error_index: pdu.error_index.max(0) as u32,
        varbinds: pdu.varbinds,
    })
}
