use std::{
    env,
    fs,
    io,
    time::Duration,
};

use mahi_core::{
    ParticipantName,
    ThreadId,
};
use mahi_identity::{
    AgentError,
    AgentSigner,
    ConfigDir,
    ConfigError,
    IdentityError,
    LocalIdentity,
    NodeKey,
    SigningKey,
    SshAgent,
};
use mahi_live::{
    HostAddress,
    LiveError,
    LiveNode,
    Relays,
    Ticket,
    TicketError,
};
use mahi_store::{
    Store,
    StoreError,
};
use mahi_thread::{
    CardError,
    InvalidMeta,
    KeyError,
    MetaError,
    NodeId,
    ParticipantCard,
    ParticipantKey,
    SshSigner,
    ThreadError,
    VerifiedMeta,
    add_participant,
    load_meta,
};
use thiserror::Error;

use crate::{
    cli::InviteCommand,
    environment::{
        Environment,
        LiveMode,
    },
    live,
    prompt::{
        Prompt,
        TerminalPrompt,
    },
    thread_lock::{
        LockError,
        ThreadLock,
    },
};

const RELAY_WAIT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub(crate) enum InviteError {
    #[error("cannot find the current directory")]
    CurrentDirectory(#[source] io::Error),
    #[error("cannot find mahi's configuration directory")]
    Config(#[from] ConfigError),
    #[error("mahi is not set up; run mahi init first")]
    NotInitialised(#[source] IdentityError),
    #[error("SSH_AUTH_SOCK is not set; start ssh-agent and add your signing key (ssh-add)")]
    NoSshAgent,
    #[error("cannot sign with the SSH key")]
    Signer(#[from] AgentError),
    #[error("your signing key is not usable")]
    Key(#[from] KeyError),
    #[error("cannot read the repository")]
    Store(#[from] StoreError),
    #[error("{0}")]
    Card(#[from] CardError),
    #[error("thread {0}'s meta is not signed by your key; only the thread's owner can invite")]
    NotOwner(ThreadId, #[source] Box<ThreadError>),
    #[error("{0} is already in the thread with other keys, or shares keys with them")]
    Clash(ParticipantName),
    #[error("no relay answered within {} s; check the network and invite again", RELAY_WAIT.as_secs())]
    NoRelay,
    #[error("cannot read thread {0}")]
    Thread(ThreadId, #[source] Box<ThreadError>),
    #[error("cannot ask for your passphrase")]
    Terminal(#[source] io::Error),
    #[error("cannot unlock your mahi key")]
    Unlock(#[source] IdentityError),
    #[error("cannot add the participant to thread {0}")]
    Add(ThreadId, #[source] Box<ThreadError>),
    #[error("cannot find this machine's address on the live layer")]
    Live(#[from] LiveError),
    #[error("the live layer speaks as another node than your node key")]
    NodeMismatch,
    #[error("cannot write the ticket")]
    Ticket(#[from] TicketError),
    #[error("the thread is running, but its host has not published its address yet; try again")]
    NotPublished,
    #[error("cannot check whether the thread is running")]
    Lock(#[source] LockError),
    #[error(
        "an invitation needs the live layer: set MAHI_LIVE to local or public, or leave it unset"
    )]
    LiveSetting,
}

/// Who invites, with which keys, and how the ticket finds this machine.
pub(crate) struct Inviter<'a> {
    pub(crate) config: &'a ConfigDir,
    pub(crate) signer: &'a dyn SshSigner,
    pub(crate) node_key: &'a NodeKey,
    pub(crate) relays: Relays,
}

/// Adds the teammate whose card is in `command` to a thread the user owns and returns their
/// ticket, with a line ending.
pub(crate) fn invite(
    command: &InviteCommand,
    environment: &Environment,
) -> Result<String, InviteError> {
    let relays = relays_for(environment.live)?;
    let cwd = env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(InviteError::CurrentDirectory)?;
    let config = ConfigDir::resolve(
        environment.home.as_deref(),
        environment.xdg_config_home.as_deref(),
    )?;
    let signing =
        SigningKey::load(&config.signing_key_file()).map_err(InviteError::NotInitialised)?;
    let node_key = NodeKey::load(&config.node_key_file()).map_err(InviteError::NotInitialised)?;
    let socket = environment
        .ssh_auth_sock
        .as_deref()
        .ok_or(InviteError::NoSshAgent)?;
    let signer = AgentSigner::new(SshAgent::new(socket), signing.public_key().clone())?;
    let store = Store::discover(&cwd)?;
    let inviter = Inviter {
        config: &config,
        signer: &signer,
        node_key: &node_key,
        relays,
    };
    let card: ParticipantCard = command.card().parse()?;
    let ticket = invite_to(&store, command.thread, card, &inviter, &mut || {
        TerminalPrompt::open()
    })?;
    Ok(format!("{ticket}\n"))
}

/// Returns the relays the invite's host address uses, as `MAHI_LIVE` says.
fn relays_for(live: LiveMode) -> Result<Relays, InviteError> {
    match live {
        LiveMode::Public => Ok(Relays::Public),
        LiveMode::Local => Ok(Relays::Disabled),
        LiveMode::Off | LiveMode::Unknown => Err(InviteError::LiveSetting),
    }
}

/// Adds `card`'s participant to `thread` unless they are already in it, exactly as the card
/// says, and returns their ticket. The passphrase is asked only when they must be added.
pub(crate) fn invite_to<P: Prompt>(
    store: &Store,
    thread: ThreadId,
    card: ParticipantCard,
    inviter: &Inviter<'_>,
    open_prompt: &mut dyn FnMut() -> io::Result<P>,
) -> Result<Ticket, InviteError> {
    let owner = ParticipantKey::from_public_key(inviter.signer.public_key())?;
    let current = load_meta(store, thread, &owner, 0).map_err(|error| match error {
        ThreadError::Meta(
            MetaError::BadSignature | MetaError::Invalid(InvalidMeta::OwnerKeyUntrusted),
        ) => InviteError::NotOwner(thread, Box::new(error)),
        other => InviteError::Thread(thread, Box::new(other)),
    })?;
    let invitee_node = *card.participant().node();
    let new = card.participant();
    if let Some(clash) = current.participants().find(|listed| {
        *listed != new
            && (listed.name() == new.name()
                || listed.key() == new.key()
                || listed.recipient().to_string() == new.recipient().to_string()
                || listed.node() == new.node())
    }) {
        return Err(InviteError::Clash(clash.name().clone()));
    }
    let address = host_address(thread, inviter)?;
    if inviter.relays == Relays::Public && address.relay().is_none() {
        return Err(InviteError::NoRelay);
    }
    let own =
        NodeId::from_bytes(inviter.node_key.public()).map_err(|_| InviteError::NodeMismatch)?;
    if address.node() != &own {
        return Err(InviteError::NodeMismatch);
    }
    let meta = if current.participants().any(|listed| listed == new) {
        current
    } else {
        add(store, thread, &current, card, inviter, open_prompt)?
    };
    Ok(Ticket::new(
        thread,
        address,
        owner,
        meta.generation(),
        invitee_node,
    ))
}

/// Returns where the thread's host is: the address a running host published, since binding
/// a second endpoint with the same node key would take its relay connection over, or else this
/// machine's address, found by binding the endpoint while the thread's lock keeps a host from
/// starting.
fn host_address(thread: ThreadId, inviter: &Inviter<'_>) -> Result<HostAddress, InviteError> {
    match ThreadLock::acquire(inviter.config, thread) {
        Ok(_lock) => {
            let node = LiveNode::bind(inviter.node_key.secret(), inviter.relays)?;
            let address = node.address(RELAY_WAIT);
            node.close()?;
            Ok(address?)
        }
        Err(LockError::Busy(_)) => {
            live::published_address(inviter.config, thread).ok_or(InviteError::NotPublished)
        }
        Err(error) => Err(InviteError::Lock(error)),
    }
}

fn add<P: Prompt>(
    store: &Store,
    thread: ThreadId,
    current: &VerifiedMeta,
    card: ParticipantCard,
    inviter: &Inviter<'_>,
    open_prompt: &mut dyn FnMut() -> io::Result<P>,
) -> Result<VerifiedMeta, InviteError> {
    let passphrase = open_prompt()
        .and_then(|mut prompt| prompt.secret("Passphrase for your mahi key: "))
        .map_err(InviteError::Terminal)?;
    let identity = LocalIdentity::load(&inviter.config.identity_file(), &passphrase)
        .map_err(InviteError::Unlock)?;
    drop(passphrase);
    let thread_key = current
        .thread_key(current.owner(), identity.as_age())
        .map_err(|error| InviteError::Thread(thread, Box::new(error.into())))?;
    drop(identity);
    add_participant(
        store,
        thread,
        &thread_key,
        inviter.signer,
        card.into_participant(),
    )
    .map_err(|error| InviteError::Add(thread, Box::new(error)))
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::PermissionsExt,
        sync::atomic::AtomicBool,
    };

    use age::secrecy::SecretString;
    use mahi_core::ParticipantName;
    use mahi_identity::PublicIdentity;
    use mahi_store::GlobalPatterns;
    use mahi_thread::Participant;
    use ssh_key::{
        Algorithm,
        PrivateKey,
        rand_core::OsRng,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::{
        prompt::tests::Script,
        session::{
            self,
            NewThread,
            agent_from,
            tests::repository_on_main,
        },
    };

    const PASSPHRASE: &str = "correct horse";

    struct Owner {
        _config_dir: TempDir,
        config: ConfigDir,
        key: PrivateKey,
        node_key: NodeKey,
        thread: ThreadId,
    }

    fn owner_of_a_thread(store: &Store) -> Owner {
        let config_dir = TempDir::new().unwrap();
        let config = ConfigDir::resolve(Some(config_dir.path()), None).unwrap();
        fs::create_dir_all(config.path()).unwrap();
        fs::set_permissions(config.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let identity = LocalIdentity::generate();
        identity
            .save(
                &config.identity_file(),
                &SecretString::from(PASSPHRASE.to_owned()),
            )
            .unwrap();
        let node_key = NodeKey::generate().unwrap();
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let worktrees = TempDir::new().unwrap();
        let started = session::start(
            store,
            NewThread {
                public: &PublicIdentity::from(&identity),
                node: NodeId::from_bytes(node_key.public()).unwrap(),
                signer: &key,
                participant: ParticipantName::new("alice").unwrap(),
                agent: &agent_from(std::path::Path::new("claude")),
                worktrees: worktrees.path(),
            },
            &GlobalPatterns::default(),
            &AtomicBool::new(false),
        )
        .unwrap();
        Owner {
            _config_dir: config_dir,
            config,
            key,
            node_key,
            thread: started.thread,
        }
    }

    fn bob() -> ParticipantCard {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        ParticipantCard::new(
            Participant::new(
                ParticipantName::new("bob").unwrap(),
                ParticipantKey::from_public_key(key.public_key()).unwrap(),
                age::x25519::Identity::generate().to_public(),
                NodeId::from_bytes(NodeKey::generate().unwrap().public()).unwrap(),
            )
            .unwrap(),
        )
    }

    fn inviter<'a>(owner: &'a Owner, signer: &'a dyn SshSigner) -> Inviter<'a> {
        Inviter {
            config: &owner.config,
            signer,
            node_key: &owner.node_key,
            relays: Relays::Disabled,
        }
    }

    fn script(secrets: &[&'static str]) -> impl FnMut() -> io::Result<Script> {
        let secrets = secrets.to_vec();
        move || {
            Ok(Script {
                secrets: secrets.clone().into(),
                ..Script::default()
            })
        }
    }

    #[test]
    fn an_invitee_is_added_and_their_ticket_points_at_this_machine() {
        let (_repo, store) = repository_on_main();
        let owner = owner_of_a_thread(&store);
        let card = bob();
        let ticket = invite_to(
            &store,
            owner.thread,
            card.clone(),
            &inviter(&owner, &owner.key),
            &mut script(&[PASSPHRASE]),
        )
        .unwrap();
        let reparsed: Ticket = ticket.to_string().parse().unwrap();
        assert_eq!(reparsed, ticket);
        assert_eq!(ticket.thread(), owner.thread);
        assert_eq!(ticket.min_generation(), 1);
        assert_eq!(ticket.invitee(), card.participant().node());
        assert_eq!(ticket.host().node().as_bytes(), &owner.node_key.public());
        assert!(!ticket.host().direct().is_empty());
        assert_eq!(
            ticket.owner(),
            &ParticipantKey::from_public_key(owner.key.public_key()).unwrap()
        );
        let meta = load_meta(&store, owner.thread, ticket.owner(), 1).unwrap();
        assert!(
            meta.participants()
                .any(|listed| listed == card.participant())
        );

        let again = invite_to(
            &store,
            owner.thread,
            card,
            &inviter(&owner, &owner.key),
            &mut script(&[]),
        )
        .unwrap();
        assert_eq!(again.min_generation(), 1);
    }

    #[test]
    fn only_the_owner_invites_and_a_wrong_passphrase_adds_no_one() {
        let (_repo, store) = repository_on_main();
        let owner = owner_of_a_thread(&store);
        let stranger = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        assert!(matches!(
            invite_to(
                &store,
                owner.thread,
                bob(),
                &inviter(&owner, &stranger),
                &mut script(&[]),
            ),
            Err(InviteError::NotOwner(thread, _)) if thread == owner.thread
        ));
        assert!(matches!(
            invite_to(
                &store,
                owner.thread,
                bob(),
                &inviter(&owner, &owner.key),
                &mut script(&["wrong passphrase"]),
            ),
            Err(InviteError::Unlock(IdentityError::WrongPassphrase))
        ));
        let owner_key = ParticipantKey::from_public_key(owner.key.public_key()).unwrap();
        let meta = load_meta(&store, owner.thread, &owner_key, 0).unwrap();
        assert_eq!(meta.generation(), 0);
    }

    #[test]
    fn a_card_that_clashes_with_a_participant_is_refused_before_the_passphrase() {
        let (_repo, store) = repository_on_main();
        let owner = owner_of_a_thread(&store);
        let impostor = {
            let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
            ParticipantCard::new(
                Participant::new(
                    ParticipantName::new("alice").unwrap(),
                    ParticipantKey::from_public_key(key.public_key()).unwrap(),
                    age::x25519::Identity::generate().to_public(),
                    NodeId::from_bytes(NodeKey::generate().unwrap().public()).unwrap(),
                )
                .unwrap(),
            )
        };
        let same_node = {
            let card = bob();
            let bob = card.participant();
            ParticipantCard::new(
                Participant::new(
                    bob.name().clone(),
                    bob.key().clone(),
                    bob.recipient().clone(),
                    NodeId::from_bytes(owner.node_key.public()).unwrap(),
                )
                .unwrap(),
            )
        };
        for card in [impostor, same_node] {
            assert!(matches!(
                invite_to(
                    &store,
                    owner.thread,
                    card,
                    &inviter(&owner, &owner.key),
                    &mut script(&[]),
                ),
                Err(InviteError::Clash(name)) if name.as_str() == "alice"
            ));
        }
    }

    #[test]
    fn an_invitation_needs_the_live_layer_and_local_means_no_relays() {
        assert_eq!(relays_for(LiveMode::Public).unwrap(), Relays::Public);
        assert_eq!(relays_for(LiveMode::Local).unwrap(), Relays::Disabled);
        assert!(matches!(
            relays_for(LiveMode::Off),
            Err(InviteError::LiveSetting)
        ));
        assert!(matches!(
            relays_for(LiveMode::Unknown),
            Err(InviteError::LiveSetting)
        ));
    }

    #[test]
    fn a_thread_that_does_not_exist_is_reported_as_such() {
        let (_repo, store) = repository_on_main();
        let owner = owner_of_a_thread(&store);
        let missing = ThreadId::random().unwrap();
        assert!(matches!(
            invite_to(
                &store,
                missing,
                bob(),
                &inviter(&owner, &owner.key),
                &mut script(&[]),
            ),
            Err(InviteError::Thread(thread, error))
                if thread == missing && matches!(*error, ThreadError::NotFound(_))
        ));
    }

    #[test]
    fn a_running_threads_ticket_points_at_the_address_its_host_published() {
        let (_repo, store) = repository_on_main();
        let owner = owner_of_a_thread(&store);
        let running = crate::thread_lock::ThreadLock::acquire(&owner.config, owner.thread).unwrap();
        assert!(matches!(
            invite_to(
                &store,
                owner.thread,
                bob(),
                &inviter(&owner, &owner.key),
                &mut script(&[PASSPHRASE]),
            ),
            Err(InviteError::NotPublished)
        ));
        let owner_key = ParticipantKey::from_public_key(owner.key.public_key()).unwrap();
        assert_eq!(
            load_meta(&store, owner.thread, &owner_key, 0)
                .unwrap()
                .generation(),
            0
        );
        let published = HostAddress::new(
            NodeId::from_bytes(owner.node_key.public()).unwrap(),
            None,
            vec!["192.0.2.9:51000".parse().unwrap()],
        )
        .unwrap();
        let someone_else = HostAddress::new(
            NodeId::from_bytes(NodeKey::generate().unwrap().public()).unwrap(),
            None,
            vec!["192.0.2.9:51000".parse().unwrap()],
        )
        .unwrap();
        crate::live::publish_address(&owner.config, owner.thread, &someone_else).unwrap();
        assert!(matches!(
            invite_to(
                &store,
                owner.thread,
                bob(),
                &inviter(&owner, &owner.key),
                &mut script(&[]),
            ),
            Err(InviteError::NodeMismatch)
        ));
        crate::live::publish_address(&owner.config, owner.thread, &published).unwrap();
        let ticket = invite_to(
            &store,
            owner.thread,
            bob(),
            &inviter(&owner, &owner.key),
            &mut script(&[PASSPHRASE]),
        )
        .unwrap();
        assert_eq!(ticket.host(), &published);
        drop(running);
    }
}
