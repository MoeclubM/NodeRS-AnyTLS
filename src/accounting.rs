use anyhow::{Context, bail};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::Notify;

use crate::limiter::SharedRateLimiter;
use crate::panel::PanelUser;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserEntry {
    pub id: i64,
    pub uuid: String,
    pub password_sha256: [u8; 32],
    pub speed_limit: i64,
    pub device_limit: i64,
}

#[derive(Debug, Default)]
pub struct UsageCounter {
    upload: AtomicU64,
    download: AtomicU64,
}

impl UsageCounter {
    pub fn record_upload(&self, bytes: u64) {
        if bytes > 0 {
            self.upload.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub fn record_download(&self, bytes: u64) {
        if bytes > 0 {
            self.download.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    fn snapshot_if_ready(&self, min_traffic_bytes: u64) -> Option<[u64; 2]> {
        let upload = self.upload.swap(0, Ordering::AcqRel);
        let download = self.download.swap(0, Ordering::AcqRel);
        let total = upload + download;
        if total == 0 {
            return None;
        }
        if total < min_traffic_bytes {
            if upload > 0 {
                self.upload.fetch_add(upload, Ordering::Release);
            }
            if download > 0 {
                self.download.fetch_add(download, Ordering::Release);
            }
            return None;
        }
        Some([upload, download])
    }

    fn restore(&self, upload: u64, download: u64) {
        if upload > 0 {
            self.upload.fetch_add(upload, Ordering::Release);
        }
        if download > 0 {
            self.download.fetch_add(download, Ordering::Release);
        }
    }
}

#[derive(Debug)]
pub struct SessionControl {
    cancelled: AtomicBool,
    notify: Notify,
}

impl SessionControl {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            cancelled: AtomicBool::new(false),
            notify: Notify::new(),
        })
    }

    pub fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::SeqCst) {
            self.notify.notify_waiters();
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        self.notify.notified().await;
    }
}

pub struct SessionLease {
    accounting: Arc<Accounting>,
    uid: i64,
    ip: String,
    session_id: u64,
    control: Arc<SessionControl>,
    limiter: Option<Arc<SharedRateLimiter>>,
}

impl SessionLease {
    pub fn control(&self) -> Arc<SessionControl> {
        self.control.clone()
    }

    pub fn limiter(&self) -> Option<Arc<SharedRateLimiter>> {
        self.limiter.clone()
    }
}

impl Drop for SessionLease {
    fn drop(&mut self) {
        self.accounting
            .close_session(self.uid, &self.ip, self.session_id);
    }
}

#[derive(Debug, Default)]
pub struct Accounting {
    users: RwLock<HashMap<[u8; 32], UserEntry>>,
    traffic: RwLock<HashMap<i64, Arc<UsageCounter>>>,
    online: Mutex<HashMap<i64, HashMap<String, usize>>>,
    external_alive: Mutex<HashMap<i64, usize>>,
    speed_limiters: Mutex<HashMap<i64, Arc<SharedRateLimiter>>>,
    sessions: Mutex<HashMap<i64, HashMap<u64, Arc<SessionControl>>>>,
    session_seq: AtomicU64,
}

impl Accounting {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn replace_users(self: &Arc<Self>, users: &[PanelUser]) {
        let previous_by_id = self
            .users
            .read()
            .expect("users lock poisoned")
            .values()
            .map(|entry| (entry.id, entry.clone()))
            .collect::<HashMap<_, _>>();

        let mapped = users
            .iter()
            .map(|user| {
                let entry = UserEntry {
                    id: user.id,
                    uuid: user.uuid.clone(),
                    password_sha256: sha256_bytes(user.uuid.as_bytes()),
                    speed_limit: user.speed_limit,
                    device_limit: user.device_limit,
                };
                (entry.password_sha256, entry)
            })
            .collect::<HashMap<_, _>>();

        let valid_ids = mapped
            .values()
            .map(|entry| entry.id)
            .collect::<HashSet<_>>();
        let rotated_ids = users
            .iter()
            .filter_map(|user| {
                previous_by_id.get(&user.id).and_then(|previous| {
                    if previous.uuid != user.uuid {
                        Some(user.id)
                    } else {
                        None
                    }
                })
            })
            .collect::<HashSet<_>>();

        *self.users.write().expect("users lock poisoned") = mapped;
        {
            let mut traffic = self.traffic.write().expect("traffic lock poisoned");
            for user in users {
                traffic
                    .entry(user.id)
                    .or_insert_with(|| Arc::new(UsageCounter::default()));
            }
            traffic.retain(|uid, _| valid_ids.contains(uid));
        }
        self.online
            .lock()
            .expect("online lock poisoned")
            .retain(|uid, _| valid_ids.contains(uid));
        self.external_alive
            .lock()
            .expect("external alive lock poisoned")
            .retain(|uid, _| valid_ids.contains(uid));

        {
            let mut limiters = self
                .speed_limiters
                .lock()
                .expect("speed limiter lock poisoned");
            for user in users {
                let rate = speed_limit_to_bytes_per_second(user.speed_limit);
                if let Some(existing) = limiters.get(&user.id) {
                    existing.set_rate(rate);
                } else {
                    limiters.insert(user.id, SharedRateLimiter::new(rate));
                }
            }
            limiters.retain(|uid, _| valid_ids.contains(uid));
        }

        let removed_ids = previous_by_id
            .keys()
            .filter(|uid| !valid_ids.contains(uid))
            .copied()
            .collect::<HashSet<_>>();
        self.cancel_sessions_for_ids(&removed_ids);
        self.cancel_sessions_for_ids(&rotated_ids);
    }

    pub fn set_external_alive_counts(&self, alive: &HashMap<String, i64>) {
        let mut parsed = HashMap::new();
        for (uid, count) in alive {
            if let (Ok(uid), Ok(count)) = (uid.parse::<i64>(), usize::try_from((*count).max(0))) {
                parsed.insert(uid, count);
            }
        }
        *self
            .external_alive
            .lock()
            .expect("external alive lock poisoned") = parsed;
    }

    pub fn find_user_by_hash(&self, hash: &[u8; 32]) -> Option<UserEntry> {
        self.users
            .read()
            .expect("users lock poisoned")
            .get(hash)
            .cloned()
    }

    pub fn open_session(
        self: &Arc<Self>,
        user: &UserEntry,
        source: std::net::SocketAddr,
    ) -> anyhow::Result<SessionLease> {
        let ip = normalize_ip(source.ip().to_string());
        self.enforce_device_limit(user, &ip)
            .with_context(|| format!("device limit reject for user {}", user.uuid))?;

        let session_id = self.session_seq.fetch_add(1, Ordering::SeqCst) + 1;
        let control = SessionControl::new();
        let limiter = self
            .speed_limiters
            .lock()
            .expect("speed limiter lock poisoned")
            .get(&user.id)
            .cloned();

        {
            let mut online = self.online.lock().expect("online lock poisoned");
            let ip_map = online.entry(user.id).or_default();
            *ip_map.entry(ip.clone()).or_default() += 1;
        }
        {
            let mut sessions = self.sessions.lock().expect("session lock poisoned");
            sessions
                .entry(user.id)
                .or_default()
                .insert(session_id, control.clone());
        }

        Ok(SessionLease {
            accounting: self.clone(),
            uid: user.id,
            ip,
            session_id,
            control,
            limiter,
        })
    }

    pub fn traffic_counter(&self, uid: i64) -> Arc<UsageCounter> {
        if let Some(counter) = self
            .traffic
            .read()
            .expect("traffic lock poisoned")
            .get(&uid)
            .cloned()
        {
            return counter;
        }
        let mut guard = self.traffic.write().expect("traffic lock poisoned");
        guard
            .entry(uid)
            .or_insert_with(|| Arc::new(UsageCounter::default()))
            .clone()
    }

    pub fn snapshot_traffic(&self, min_traffic_bytes: u64) -> HashMap<i64, [u64; 2]> {
        let counters = self
            .traffic
            .read()
            .expect("traffic lock poisoned")
            .iter()
            .map(|(uid, counter)| (*uid, counter.clone()))
            .collect::<Vec<_>>();
        let mut snapshot = HashMap::new();
        for (uid, counter) in counters {
            if let Some(usage) = counter.snapshot_if_ready(min_traffic_bytes) {
                snapshot.insert(uid, usage);
            }
        }
        snapshot
    }

    pub fn restore_traffic(&self, traffic: &HashMap<i64, [u64; 2]>) {
        if traffic.is_empty() {
            return;
        }
        for (uid, [upload, download]) in traffic {
            self.traffic_counter(*uid).restore(*upload, *download);
        }
    }

    pub fn snapshot_alive(&self) -> HashMap<i64, Vec<String>> {
        self.online
            .lock()
            .expect("online lock poisoned")
            .iter()
            .map(|(uid, ips)| (*uid, ips.keys().cloned().collect::<Vec<_>>()))
            .collect()
    }

    fn enforce_device_limit(&self, user: &UserEntry, ip: &str) -> anyhow::Result<()> {
        if user.device_limit <= 0 {
            return Ok(());
        }
        let local = self.online.lock().expect("online lock poisoned");
        let local_ips = local.get(&user.id).cloned().unwrap_or_default();
        if local_ips.contains_key(ip) {
            return Ok(());
        }
        let local_unique = local_ips.len();
        drop(local);

        let external = self
            .external_alive
            .lock()
            .expect("external alive lock poisoned")
            .get(&user.id)
            .copied()
            .unwrap_or(0);
        let adjusted_external = external.saturating_sub(local_unique);
        if adjusted_external + local_unique >= user.device_limit as usize {
            bail!(
                "device limit exceeded: uid={}, limit={}, local_unique={}, external_alive={}",
                user.id,
                user.device_limit,
                local_unique,
                external
            );
        }
        Ok(())
    }

    fn close_session(&self, uid: i64, ip: &str, session_id: u64) {
        {
            let mut sessions = self.sessions.lock().expect("session lock poisoned");
            if let Some(entries) = sessions.get_mut(&uid) {
                entries.remove(&session_id);
                if entries.is_empty() {
                    sessions.remove(&uid);
                }
            }
        }
        let mut online = self.online.lock().expect("online lock poisoned");
        if let Some(ip_map) = online.get_mut(&uid) {
            if let Some(count) = ip_map.get_mut(ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    ip_map.remove(ip);
                }
            }
            if ip_map.is_empty() {
                online.remove(&uid);
            }
        }
    }

    fn cancel_sessions_for_ids(&self, ids: &HashSet<i64>) {
        if ids.is_empty() {
            return;
        }
        let controls = {
            let sessions = self.sessions.lock().expect("session lock poisoned");
            ids.iter()
                .filter_map(|uid| sessions.get(uid))
                .flat_map(|entries| entries.values().cloned())
                .collect::<Vec<_>>()
        };
        for control in controls {
            control.cancel();
        }
    }
}

fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

fn speed_limit_to_bytes_per_second(limit_mbps: i64) -> u64 {
    if limit_mbps <= 0 {
        0
    } else {
        (limit_mbps as u64).saturating_mul(1_000_000) / 8
    }
}

fn normalize_ip(ip: String) -> String {
    ip.trim_start_matches("::ffff:").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_users_and_resolves_hash() {
        let accounting = Accounting::new();
        accounting.replace_users(&[PanelUser {
            id: 1,
            uuid: "abc".to_string(),
            speed_limit: 0,
            device_limit: 0,
        }]);
        let hash = sha256_bytes(b"abc");
        assert_eq!(accounting.find_user_by_hash(&hash).map(|it| it.id), Some(1));
    }

    #[test]
    fn device_limit_blocks_new_ip() {
        let accounting = Accounting::new();
        accounting.replace_users(&[PanelUser {
            id: 1,
            uuid: "abc".to_string(),
            speed_limit: 0,
            device_limit: 1,
        }]);
        let user = accounting
            .find_user_by_hash(&sha256_bytes(b"abc"))
            .expect("user exists");
        let _lease = accounting
            .open_session(&user, "1.1.1.1:1234".parse().expect("socket addr"))
            .expect("first session should pass");
        assert!(
            accounting
                .open_session(&user, "2.2.2.2:2345".parse().expect("socket addr"))
                .is_err()
        );
    }

    #[test]
    fn removing_user_cancels_active_session() {
        let accounting = Accounting::new();
        accounting.replace_users(&[PanelUser {
            id: 1,
            uuid: "abc".to_string(),
            speed_limit: 0,
            device_limit: 0,
        }]);
        let user = accounting
            .find_user_by_hash(&sha256_bytes(b"abc"))
            .expect("user exists");
        let lease = accounting
            .open_session(&user, "1.1.1.1:1234".parse().expect("socket addr"))
            .expect("session should open");
        let control = lease.control();
        accounting.replace_users(&[]);
        assert!(control.is_cancelled());
    }

    #[test]
    fn restores_traffic_after_failed_push() {
        let accounting = Accounting::new();
        let counter = accounting.traffic_counter(1);
        counter.record_upload(100);
        counter.record_download(40);

        let snapshot = accounting.snapshot_traffic(0);
        assert_eq!(snapshot.get(&1), Some(&[100, 40]));
        assert!(accounting.snapshot_traffic(0).is_empty());

        accounting.restore_traffic(&snapshot);
        assert_eq!(accounting.snapshot_traffic(0).get(&1), Some(&[100, 40]));
    }
}
