use std::{
    collections::{
        HashMap,
        HashSet,
    },
    io::{
        self,
        BufWriter,
        Write,
    },
    sync::atomic::{
        AtomicBool,
        Ordering,
    },
};

use gix::{
    ObjectId,
    features::parallel::InOrderIter,
    object::Kind,
    odb::pack::data::{
        Version,
        output::{
            bytes::FromEntriesIter,
            count::{
                self,
                objects::ObjectExpansion,
            },
            entry::iter_from_counts,
        },
    },
    protocol::transport::{
        Service,
        client::{
            MessageKind,
            WriteMode,
            blocking_io::Transport,
        },
    },
};
use mahi_core::{
    THREADS_PREFIX,
    ThreadRef,
};

use crate::store::{
    Store,
    StoreError,
};

const MAX_ADVERTISED_REFS: usize = 65536;
const MAX_REPORT_LINES: usize = 65536;
const MAX_REASON_CHARS: usize = 200;
const PACK_BUFFER_BYTES: usize = 64 << 10;
const AGENT: &str = "agent=mahi";

/// What pushing one thread ref did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pushed {
    /// The remote ref was created or moved forward to the local commit.
    Updated,
    /// The remote ref already pointed at the local commit.
    UpToDate,
    /// The remote ref points at a commit the local ref does not descend from, or that is not
    /// here; fetch first.
    Behind,
    /// The local history could not be checked against the remote ref, for the reason given.
    Unchecked(String),
    /// The remote refused the update, for the reason it gave, escaped.
    Refused(String),
}

struct Advertisement {
    wanted: HashMap<String, ObjectId>,
    tips: HashSet<ObjectId>,
    atomic: bool,
}

type Command = (ThreadRef, Option<ObjectId>, ObjectId);
type Plan = (Vec<(ThreadRef, Pushed)>, Vec<Command>);

impl Store {
    /// Pushes `refs` to the remote `transport` reaches, each to where it points here, and only
    /// as a fast-forward of what the remote has: a ref whose remote commit the local one does
    /// not descend from is left alone and reported [`Pushed::Behind`]. The updates are atomic
    /// when the remote supports it.
    ///
    /// Returns what happened to each ref, in the order given and once each; refs that do not
    /// exist here are left out.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::PushFailed`] if the remote does not speak the protocol mahi needs
    /// or cannot unpack what was sent, [`StoreError::Interrupted`] if `interrupt` is set, or
    /// [`StoreError::Git`] if the transport or building the pack fails.
    pub fn push_refs<T: Transport>(
        &self,
        mut transport: T,
        refs: &[ThreadRef],
        interrupt: &AtomicBool,
    ) -> Result<Vec<(ThreadRef, Pushed)>, StoreError> {
        let mut unique = Vec::new();
        for thread_ref in refs {
            if !unique.contains(thread_ref) {
                unique.push(thread_ref.clone());
            }
        }
        let advertised = advertisement(&mut transport, &unique)?;
        let (mut outcomes, commands) = self.plan(&unique, &advertised)?;
        let mut writer = transport
            .request(
                WriteMode::OneLfTerminatedLinePerWriteCall,
                MessageKind::Flush,
                false,
            )
            .map_err(gix::Error::from_error)?;
        if commands.is_empty() {
            writer.into_read()?;
            return Ok(outcomes);
        }
        let objects = self.objects_to_send(&commands, &advertised.tips, interrupt)?;
        for (index, (thread_ref, old, new)) in commands.iter().enumerate() {
            let old = old.unwrap_or_else(|| ObjectId::null(gix::hash::Kind::Sha1));
            let mut line = format!("{old} {new} {thread_ref}");
            if index == 0 {
                line.push('\0');
                line.push_str("report-status ");
                if advertised.atomic {
                    line.push_str("atomic ");
                }
                line.push_str(AGENT);
            }
            writer.write_all(line.as_bytes())?;
        }
        writer.write_message(MessageKind::Flush)?;
        let (raw, mut reader) = writer.into_parts();
        let mut raw = BufWriter::with_capacity(PACK_BUFFER_BYTES, raw);
        self.write_pack(&objects, &mut raw, interrupt)?;
        raw.flush()?;
        drop(raw);
        let sent: HashSet<String> = commands
            .iter()
            .map(|(thread_ref, _, _)| thread_ref.to_string())
            .collect();
        let report = read_report(&mut |line| reader.readline_str(line), &sent)?;
        for (thread_ref, outcome) in &mut outcomes {
            if *outcome != Pushed::Updated {
                continue;
            }
            match report.get(&thread_ref.to_string()) {
                Some(None) => {}
                Some(Some(reason)) => *outcome = Pushed::Refused(reason.clone()),
                None => *outcome = Pushed::Refused("no report".to_owned()),
            }
        }
        Ok(outcomes)
    }

    fn plan(&self, refs: &[ThreadRef], advertised: &Advertisement) -> Result<Plan, StoreError> {
        let mut outcomes = Vec::new();
        let mut commands = Vec::new();
        for thread_ref in refs {
            let Some(local) = self.head(thread_ref)? else {
                continue;
            };
            let remote = advertised.wanted.get(&thread_ref.to_string()).copied();
            let outcome = match remote {
                Some(remote) if remote == local => Pushed::UpToDate,
                Some(remote) if !self.has_commit(remote) => Pushed::Behind,
                Some(remote) => match self.descends_from(local, remote) {
                    Ok(true) => {
                        commands.push((thread_ref.clone(), Some(remote), local));
                        Pushed::Updated
                    }
                    Ok(false) => Pushed::Behind,
                    Err(error) => Pushed::Unchecked(error.to_string()),
                },
                None => {
                    commands.push((thread_ref.clone(), None, local));
                    Pushed::Updated
                }
            };
            outcomes.push((thread_ref.clone(), outcome));
        }
        Ok((outcomes, commands))
    }

    fn has_commit(&self, id: ObjectId) -> bool {
        self.require_kind(id, Kind::Commit).is_ok()
    }

    fn objects_to_send(
        &self,
        commands: &[Command],
        remote_tips: &HashSet<ObjectId>,
        interrupt: &AtomicBool,
    ) -> Result<Vec<ObjectId>, StoreError> {
        let mut known = HashSet::new();
        let mut remote_commits = HashSet::new();
        for tip in remote_tips {
            if self.has_commit(*tip) {
                remote_commits.insert(*tip);
                self.mark_known(self.commit_tree(*tip)?, &mut known, interrupt)?;
            }
        }
        let mut objects = Vec::new();
        for (_, _, new) in commands {
            let mut commits = Vec::new();
            let mut current = Some(*new);
            while let Some(commit) = current {
                if remote_commits.contains(&commit) || known.contains(&commit) {
                    break;
                }
                check(interrupt)?;
                commits.push(commit);
                current = self.parent(commit)?;
            }
            for commit in commits.into_iter().rev() {
                known.insert(commit);
                objects.push(commit);
                self.collect_new(
                    self.commit_tree(commit)?,
                    &mut known,
                    &mut objects,
                    interrupt,
                )?;
            }
        }
        Ok(objects)
    }

    fn mark_known(
        &self,
        tree: ObjectId,
        known: &mut HashSet<ObjectId>,
        interrupt: &AtomicBool,
    ) -> Result<(), StoreError> {
        let mut pending = vec![tree];
        while let Some(tree) = pending.pop() {
            if !known.insert(tree) {
                continue;
            }
            check(interrupt)?;
            for entry in self.repo.find_tree(tree)?.iter() {
                let entry = entry.map_err(gix::Error::from)?;
                let mode = entry.mode();
                if mode.is_tree() {
                    pending.push(entry.object_id());
                } else if !mode.is_commit() {
                    known.insert(entry.object_id());
                }
            }
        }
        Ok(())
    }

    fn collect_new(
        &self,
        tree: ObjectId,
        known: &mut HashSet<ObjectId>,
        objects: &mut Vec<ObjectId>,
        interrupt: &AtomicBool,
    ) -> Result<(), StoreError> {
        let mut pending = vec![tree];
        while let Some(tree) = pending.pop() {
            if !known.insert(tree) {
                continue;
            }
            check(interrupt)?;
            objects.push(tree);
            for entry in self.repo.find_tree(tree)?.iter() {
                let entry = entry.map_err(gix::Error::from)?;
                let mode = entry.mode();
                let id = entry.object_id();
                if mode.is_tree() {
                    pending.push(id);
                } else if !mode.is_commit() && known.insert(id) {
                    objects.push(id);
                }
            }
        }
        Ok(())
    }

    fn write_pack(
        &self,
        objects: &[ObjectId],
        out: &mut dyn Write,
        interrupt: &AtomicBool,
    ) -> Result<(), StoreError> {
        let mut db = self.repo.objects.clone().into_inner();
        db.prevent_pack_unload();
        let ids: Vec<_> = objects.iter().copied().map(Ok).collect();
        let (counts, _) = count::objects(
            db.clone(),
            Box::new(ids.into_iter()),
            &gix::progress::Discard,
            interrupt,
            count::objects::Options {
                thread_limit: Some(1),
                input_object_expansion: ObjectExpansion::AsIs,
                ..count::objects::Options::default()
            },
        )
        .map_err(gix::Error::from)?;
        let count = u32::try_from(counts.len())
            .map_err(|_| StoreError::PushFailed("too many objects to send".to_owned()))?;
        let entries = InOrderIter::from(iter_from_counts(
            counts,
            db,
            Box::new(gix::progress::Discard),
            gix::odb::pack::data::output::entry::iter_from_counts::Options {
                thread_limit: Some(1),
                ..Default::default()
            },
        ));
        let writer = FromEntriesIter::new(entries, out, count, Version::V2, gix::hash::Kind::Sha1);
        for written in writer {
            check(interrupt)?;
            written.map_err(gix::Error::from)?;
        }
        Ok(())
    }
}

fn check(interrupt: &AtomicBool) -> Result<(), StoreError> {
    if interrupt.load(Ordering::SeqCst) {
        Err(StoreError::Interrupted)
    } else {
        Ok(())
    }
}

fn advertisement<T: Transport>(
    transport: &mut T,
    refs: &[ThreadRef],
) -> Result<Advertisement, StoreError> {
    let response = transport
        .handshake(Service::ReceivePack, &[])
        .map_err(gix::Error::from_error)?;
    for needed in ["report-status", "ofs-delta"] {
        if !response.capabilities.contains(needed) {
            return Err(StoreError::PushFailed(format!(
                "the remote does not offer {needed}"
            )));
        }
    }
    let atomic = response.capabilities.contains("atomic");
    let Some(mut lines) = response.refs else {
        return Ok(Advertisement {
            wanted: HashMap::new(),
            tips: HashSet::new(),
            atomic,
        });
    };
    let (wanted, tips) = parse_advertisement(&mut |line| lines.readline_str(line), refs)?;
    Ok(Advertisement {
        wanted,
        tips,
        atomic,
    })
}

pub(crate) fn parse_advertisement(
    next_line: &mut dyn FnMut(&mut String) -> io::Result<usize>,
    refs: &[ThreadRef],
) -> Result<(HashMap<String, ObjectId>, HashSet<ObjectId>), StoreError> {
    let names: HashSet<String> = refs.iter().map(ToString::to_string).collect();
    let threads: HashSet<String> = refs
        .iter()
        .map(|thread_ref| format!("{THREADS_PREFIX}{}/", thread_ref.thread()))
        .collect();
    let mut wanted = HashMap::new();
    let mut tips = HashSet::new();
    let mut line = String::new();
    for _ in 0..MAX_ADVERTISED_REFS {
        line.clear();
        if next_line(&mut line)? == 0 {
            return Ok((wanted, tips));
        }
        let text = line.trim_end();
        let unexpected = || StoreError::PushFailed(format!("unexpected ref line {text:?}"));
        let (id, name) = text.split_once(' ').ok_or_else(unexpected)?;
        let name = name.split_once('\0').map_or(name, |(name, _)| name);
        if name == "capabilities^{}" {
            continue;
        }
        let id = ObjectId::from_hex(id.as_bytes()).map_err(|_| unexpected())?;
        if names.contains(name) {
            wanted.insert(name.to_owned(), id);
            tips.insert(id);
        } else if name == "HEAD"
            || threads
                .iter()
                .any(|prefix| name.starts_with(prefix.as_str()))
        {
            tips.insert(id);
        }
    }
    Err(StoreError::PushFailed(
        "the remote advertises too many refs".to_owned(),
    ))
}

pub(crate) fn read_report(
    next_line: &mut dyn FnMut(&mut String) -> io::Result<usize>,
    sent: &HashSet<String>,
) -> Result<HashMap<String, Option<String>>, StoreError> {
    let mut line = String::new();
    if next_line(&mut line)? == 0 {
        return Err(StoreError::PushFailed(
            "the remote sent no report".to_owned(),
        ));
    }
    match line.trim_end().strip_prefix("unpack ") {
        Some("ok") => {}
        Some(error) => {
            return Err(StoreError::PushFailed(format!(
                "the remote could not unpack: {}",
                escaped(error)
            )));
        }
        None => {
            return Err(StoreError::PushFailed(format!(
                "unexpected report {:?}",
                line.trim_end()
            )));
        }
    }
    let mut report = HashMap::new();
    for _ in 0..MAX_REPORT_LINES {
        line.clear();
        if next_line(&mut line)? == 0 {
            return Ok(report);
        }
        let text = line.trim_end();
        let (name, result) = if let Some(name) = text.strip_prefix("ok ") {
            (name, None)
        } else if let Some(rest) = text.strip_prefix("ng ") {
            let (name, reason) = rest.split_once(' ').unwrap_or((rest, "refused"));
            (name, Some(escaped(reason)))
        } else {
            return Err(StoreError::PushFailed(format!(
                "unexpected report {text:?}"
            )));
        };
        if sent.contains(name) {
            report.insert(name.to_owned(), result);
        }
    }
    Err(StoreError::PushFailed("the report is too long".to_owned()))
}

fn escaped(text: &str) -> String {
    text.chars()
        .take(MAX_REASON_CHARS)
        .flat_map(char::escape_debug)
        .collect()
}

#[cfg(test)]
mod tests {
    use mahi_core::{
        RefKind,
        ThreadId,
    };

    use super::*;

    fn lines(lines: &[&str]) -> impl FnMut(&mut String) -> io::Result<usize> + use<> {
        let mut lines: Vec<String> = lines.iter().rev().map(|line| (*line).to_owned()).collect();
        move |line: &mut String| {
            Ok(lines.pop().map_or(0, |next| {
                line.push_str(&next);
                next.len()
            }))
        }
    }

    const ONE: &str = "1111111111111111111111111111111111111111";
    const TWO: &str = "2222222222222222222222222222222222222222";

    #[test]
    fn only_the_pushed_refs_their_threads_and_head_are_kept_from_the_advertisement() {
        let thread = ThreadId::random().unwrap();
        let meta = ThreadRef::new(thread, RefKind::Meta);
        let (wanted, tips) = parse_advertisement(
            &mut lines(&[
                &format!("{ONE} {meta}\0report-status"),
                &format!("{TWO} refs/threads/{thread}/agents/alice.claude/snapshots\n"),
                &format!("{TWO} refs/heads/main"),
                &format!("{ONE} HEAD"),
                &format!("{TWO} refs/threads/{}/meta", ThreadId::random().unwrap()),
            ]),
            std::slice::from_ref(&meta),
        )
        .unwrap();
        assert_eq!(
            wanted,
            HashMap::from([(
                meta.to_string(),
                ObjectId::from_hex(ONE.as_bytes()).unwrap()
            )])
        );
        assert_eq!(tips.len(), 2);
        assert!(matches!(
            parse_advertisement(&mut lines(&["not a ref line"]), std::slice::from_ref(&meta)),
            Err(StoreError::PushFailed(_))
        ));
        let many: Vec<String> = (0..=MAX_ADVERTISED_REFS)
            .map(|n| format!("{ONE} refs/tags/t{n}"))
            .collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(matches!(
            parse_advertisement(&mut lines(&many), &[meta]),
            Err(StoreError::PushFailed(reason)) if reason.contains("too many")
        ));
    }

    #[test]
    fn the_report_keeps_only_sent_refs_and_escapes_what_the_remote_says() {
        let sent = HashSet::from(["refs/a".to_owned(), "refs/b".to_owned()]);
        let report = read_report(
            &mut lines(&[
                "unpack ok\n",
                "ok refs/a\n",
                "ng refs/b hook \x1b[31mdeclined\n",
                "ok refs/unsent\n",
            ]),
            &sent,
        )
        .unwrap();
        assert_eq!(
            report,
            HashMap::from([
                ("refs/a".to_owned(), None),
                (
                    "refs/b".to_owned(),
                    Some("hook \\u{1b}[31mdeclined".to_owned())
                ),
            ])
        );
        for broken in [
            &[][..],
            &["unpack \x07index-pack failed"][..],
            &["unpack ok", "maybe refs/a"][..],
        ] {
            let failed = read_report(&mut lines(broken), &sent);
            assert!(
                matches!(failed, Err(StoreError::PushFailed(ref reason)) if !reason.contains('\x07')),
                "{failed:?}"
            );
        }
    }
}
