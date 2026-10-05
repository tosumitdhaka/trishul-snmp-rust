//! Manager (v1/v2c constructors), get/… (← client.py)

pub mod v1_bulk;
pub mod walk;

use std::sync::Arc;

use crate::codec::message::SnmpVersion;
use crate::codec::pdu::{Pdu, PduKind, response_error_status};
use crate::error::Error;
use crate::manager::walk::WalkOptions;
use crate::security::SecurityModel;
use crate::security::community::{CommunityConfig, CommunityModel};
use crate::session::{SessionConfig, SnmpSession};
use crate::target::{Target, normalize_targets};
use crate::types::oid::Oid;
use crate::types::value::SnmpValue;
use crate::types::varbind::{Response, VarBind};

/// v1 manager configuration (← client.py:V1Config): alias of
/// [`CommunityConfig`] keeping the architecture §5.5 name public.
pub type V1Config = CommunityConfig;

/// v2c manager configuration (← client.py:V2cConfig): alias of
/// [`CommunityConfig`] keeping the architecture §5.5 name public.
pub type V2cConfig = CommunityConfig;

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
    /// The shared community connect path: build the security model for
    /// `version` and open a session (← client.py:V1Manager/V2cManager).
    async fn connect_community(
        config: CommunityConfig,
        version: SnmpVersion,
    ) -> Result<Self, Error> {
        let security = Arc::new(SecurityModel::Community(CommunityModel::new(
            config.community.clone().into_bytes(),
            version,
        )?));
        let session = SnmpSession::connect(SessionConfig {
            host: config.host,
            port: config.port,
            security,
            timeout: config.timeout,
            retries: config.retries,
            rng: config.rng,
            skip_prepare: false,
        })
        .await?;
        Ok(Self { session, version })
    }

    /// Connects a v1 manager.
    pub async fn connect_v1(config: V1Config) -> Result<Self, Error> {
        Self::connect_community(config, SnmpVersion::V1).await
    }

    /// Connects a v2c manager.
    pub async fn connect_v2c(config: V2cConfig) -> Result<Self, Error> {
        Self::connect_community(config, SnmpVersion::V2c).await
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
            async move { this.get_oid(&current, max_repetitions).await }
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

    /// Single GETNEXT/GETBULK (used by the walk machinery; `None` = GETNEXT,
    /// `Some(n)` = GETBULK with `n` repetitions).
    pub(crate) async fn get_oid(
        &self,
        oid: &Oid,
        max_repetitions: Option<u32>,
    ) -> Result<Response, Error> {
        let varbinds = vec![VarBind::new(oid.clone(), SnmpValue::Null)];
        let _guard = self.session.request_lock.lock().await;
        let (kind, error_index) = match max_repetitions {
            Some(count) => (PduKind::GetBulkRequest, count as i32),
            None => (PduKind::GetNextRequest, 0),
        };
        // Same recovery-retry semantics as request(): a mid-walk
        // notInTimeWindows REPORT retries once and the walk continues
        // (client.py:118–169 — walk → get_next/get_bulk → _request).
        let pdu = self
            .exchange_with_recovery(kind, varbinds, 0, error_index)
            .await?;
        response_from_pdu(pdu)
    }

    /// Exchanges a single request, retrying exactly once on adopted engine
    /// recovery (client.py:150–169; §5.4). Shared by the single-exchange path
    /// (`request`) and the walk primitives (`get_oid`) so a mid-walk
    /// notInTimeWindows REPORT retries and the walk continues.
    async fn exchange_with_recovery(
        &self,
        kind: PduKind,
        varbinds: Vec<VarBind>,
        error_status: i32,
        error_index: i32,
    ) -> Result<Pdu, Error> {
        match self
            .session
            .dispatcher
            .send_pdu(kind, varbinds.clone(), error_status, error_index)
            .await
        {
            Ok(pdu) => Ok(pdu),
            Err(Error::EngineRecovery(_)) => {
                // The dispatcher already consumed the recovery report (it is
                // carried in the error); the model adopted the peer's state,
                // so retry exactly once. A second REPORT on the retry
                // propagates — one retry, no loop.
                match self
                    .session
                    .dispatcher
                    .send_pdu(kind, varbinds, error_status, error_index)
                    .await
                {
                    Ok(pdu) => Ok(pdu),
                    Err(Error::EngineRecovery(report)) => {
                        // Clear any residual flag so a later stray datagram
                        // cannot trigger a spurious recovery (client.py:165–169).
                        let _ = self.session.security.take_recovery();
                        Err(Error::EngineRecovery(report))
                    }
                    Err(other) => Err(other),
                }
            }
            Err(timeout @ Error::Timeout { .. }) => {
                // Risk #14: the reference catches RequestTimeoutError too and
                // consults the recovery flag before deciding whether to retry.
                // In the typed flow the dispatcher consumes recoveries
                // immediately, so this check is normally empty — but a REPORT
                // adopted just before the deadline expired must still retry
                // once rather than mis-report a timeout.
                if self.session.security.take_recovery().is_none() {
                    return Err(timeout);
                }
                match self
                    .session
                    .dispatcher
                    .send_pdu(kind, varbinds, error_status, error_index)
                    .await
                {
                    Ok(pdu) => Ok(pdu),
                    Err(other) => Err(other),
                }
            }
            Err(other) => Err(other),
        }
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
        let pdu = self
            .exchange_with_recovery(kind, varbinds, error_status, error_index)
            .await?;
        response_from_pdu(pdu)
    }

    /// Connects a v3 manager (RFC 3414 discovery runs during connect).
    pub async fn connect_v3(config: crate::security::usm::V3Config) -> Result<Self, Error> {
        let model = crate::security::usm::UsmModel::new(
            config.user,
            config.context_name,
            config.local_engine,
            Arc::clone(&config.clock),
            config.rng.clone(),
        );
        let security = Arc::new(SecurityModel::Usm(model));
        let session = SnmpSession::connect(SessionConfig {
            host: config.host,
            port: config.port,
            security,
            timeout: config.timeout,
            retries: config.retries,
            rng: config.rng,
            skip_prepare: false,
        })
        .await?;
        Ok(Self {
            session,
            version: SnmpVersion::V3,
        })
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
