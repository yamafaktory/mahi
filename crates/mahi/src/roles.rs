use std::{
    collections::HashMap,
    fmt::Debug,
    path::{
        Path,
        PathBuf,
    },
    sync::Mutex,
    time::{
        Duration,
        Instant,
    },
};

use mahi_core::{
    ParticipantName,
    ThreadId,
};
use mahi_store::Store;
use mahi_thread::{
    ParticipantKey,
    Role,
    load_meta,
};

/// Tells which participants of a thread only watch.
pub(crate) trait Watchers: Debug + Send + Sync {
    /// Returns whether `participant` only watches the thread.
    fn is_watcher(&self, participant: &ParticipantName) -> bool;
}

/// The roles the owner signed in a thread's `meta`, read from the repository again at most
/// every `reread_every`, so a role changed while an agent runs counts within that time and a
/// teammate's prompts cannot make the host verify `meta` for each one.
#[derive(Debug)]
pub(crate) struct MetaRoles {
    git_dir: PathBuf,
    thread: ThreadId,
    owner: ParticipantKey,
    reread_every: Duration,
    read: Mutex<Option<(Instant, HashMap<ParticipantName, Role>)>>,
}

impl MetaRoles {
    /// Returns the roles in `thread`'s `meta`, signed by `owner`, in the repository whose
    /// git directory is `git_dir`, read again at most every `reread_every`.
    pub(crate) fn of(
        git_dir: &Path,
        thread: ThreadId,
        owner: ParticipantKey,
        reread_every: Duration,
    ) -> Self {
        Self {
            git_dir: git_dir.to_path_buf(),
            thread,
            owner,
            reread_every,
            read: Mutex::new(None),
        }
    }

    fn roles(&self) -> Option<HashMap<ParticipantName, Role>> {
        let store = Store::open(&self.git_dir).ok()?;
        let meta = load_meta(&store, self.thread, &self.owner, 0).ok()?;
        Some(
            meta.participants()
                .map(|listed| (listed.name().clone(), listed.role()))
                .collect(),
        )
    }
}

impl Watchers for MetaRoles {
    /// A participant whose role cannot be read, because `meta` cannot be or does not list
    /// them, counts as a watcher.
    fn is_watcher(&self, participant: &ParticipantName) -> bool {
        let Ok(mut read) = self.read.lock() else {
            return true;
        };
        let due = read
            .as_ref()
            .is_none_or(|(at, _)| at.elapsed() >= self.reread_every);
        if due {
            *read = Some((Instant::now(), self.roles().unwrap_or_default()));
        }
        read.as_ref()
            .and_then(|(_, roles)| roles.get(participant))
            .is_none_or(|role| *role == Role::Watcher)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace_live::tests::{
        add_bob,
        setup,
        sign_participant,
    };

    #[test]
    fn the_signed_role_decides_and_an_unlisted_or_unreadable_one_watches() {
        let setup = setup();
        let roles = |owner| {
            MetaRoles::of(
                setup.store.common_dir(),
                setup.thread,
                owner,
                Duration::ZERO,
            )
        };
        let (alice, bob) = (
            ParticipantName::new("alice").unwrap(),
            ParticipantName::new("bob").unwrap(),
        );
        let current = roles(setup.owner());
        assert!(!current.is_watcher(&alice));
        assert!(current.is_watcher(&bob));
        let listed = add_bob(&setup, Role::Watcher);
        assert!(current.is_watcher(&bob));
        sign_participant(&setup, listed.clone().with_role(Role::Collaborator));
        assert!(!current.is_watcher(&bob));
        sign_participant(&setup, listed.with_role(Role::Watcher));
        assert!(current.is_watcher(&bob));
        let stranger = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let other_owner = ParticipantKey::from_public_key(stranger.public_key()).unwrap();
        assert!(roles(other_owner).is_watcher(&alice));
        let elsewhere = MetaRoles::of(
            Path::new("/nonexistent"),
            setup.thread,
            setup.owner(),
            Duration::ZERO,
        );
        assert!(elsewhere.is_watcher(&alice));
    }

    #[test]
    fn a_role_is_read_again_only_once_its_reading_is_old_enough() {
        let setup = setup();
        let roles = MetaRoles::of(
            setup.store.common_dir(),
            setup.thread,
            setup.owner(),
            Duration::from_secs(3600),
        );
        let bob = ParticipantName::new("bob").unwrap();
        assert!(roles.is_watcher(&bob));
        add_bob(&setup, Role::Collaborator);
        assert!(roles.is_watcher(&bob));
        if let Ok(mut read) = roles.read.lock() {
            *read = None;
        }
        assert!(!roles.is_watcher(&bob));
    }
}
