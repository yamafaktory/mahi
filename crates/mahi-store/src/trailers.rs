use std::{
    collections::{
        HashMap,
        HashSet,
    },
    sync::atomic::{
        AtomicBool,
        Ordering,
    },
};

use gix::{
    ObjectId,
    bstr::{
        BStr,
        BString,
        ByteSlice,
    },
    object::Kind,
    refs::{
        Target,
        transaction::{
            Change,
            LogChange,
            PreviousValue,
            RefEdit,
            RefLog,
        },
    },
};

use crate::{
    history::NewCommits,
    store::{
        Store,
        StoreError,
        branch_ref,
    },
};

const MAX_TRAILED_COMMITS: usize = 10_000;
const MAX_TRAILED_COMMIT_BYTES: u64 = 1 << 20;
const MAX_HIDDEN_REFS: usize = 65_536;
const SIGNATURE_HEADER: &[u8] = b"gpgsig";
const CHERRY_PICKED: &[u8] = b"(cherry picked from commit ";
const SIGNED_OFF_BY: &[u8] = b"Signed-off-by";

/// What [`Store::add_trailers`] did to a branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trailed {
    /// How many commits were rewritten.
    pub rewritten: usize,
    /// Where the branch points now.
    pub tip: ObjectId,
    /// The commits left without the trailers because they, or a commit after them, are
    /// signed, newest first.
    pub left_signed: Vec<ObjectId>,
}

struct Plan<'a> {
    marker: (&'a str, &'a str),
    trailers: &'a str,
    kept: HashSet<ObjectId>,
    rewritten: HashMap<ObjectId, ObjectId>,
}

impl Store {
    /// Adds `trailers`, lines of `Key: value` each ending in a newline, to the trailer block of
    /// every commit of the local branch `branch` that neither `base` nor a remote-tracking
    /// branch reaches and whose trailer block has no trailer with the key and value of
    /// `marker`, keys compared ignoring ASCII case, as git does. Those
    /// commits and the ones after them are rewritten with the same trees, authors and
    /// committers, and the branch is moved to the new tip if it still points where it did.
    /// Rewriting drops a signature, so a signed commit and every commit before it are kept
    /// as they are, and those still without the trailers are listed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NoBranch`] or [`StoreError::InvalidBranchName`] if `branch` is not
    /// a local branch, [`StoreError::TooManyCommits`] if more than 10 000 commits are not
    /// reached or more than a million are walked to find them, [`StoreError::TooLarge`] if
    /// one is larger than 1 MiB, [`StoreError::Conflict`] if the branch moved meanwhile,
    /// [`StoreError::Interrupted`] if `interrupt` is set, or [`StoreError::Git`] if reading or
    /// writing fails.
    pub fn add_trailers(
        &self,
        branch: &str,
        base: ObjectId,
        (marker, trailers): ((&str, &str), &str),
        interrupt: &AtomicBool,
    ) -> Result<Trailed, StoreError> {
        let tip = self
            .branch_tip(branch)?
            .ok_or_else(|| StoreError::NoBranch(branch.to_owned()))?;
        let commits = self.unpublished(tip, base, interrupt)?;
        let set: HashSet<ObjectId> = commits.iter().copied().collect();
        let mut plan = Plan {
            marker,
            trailers,
            kept: self.signed_and_before(&commits, &set, interrupt)?,
            rewritten: HashMap::with_capacity(commits.len()),
        };
        let mut rewritten = 0;
        let mut lacking = HashSet::new();
        for start in &commits {
            let mut stack = vec![(*start, false)];
            while let Some((id, expanded)) = stack.pop() {
                if plan.rewritten.contains_key(&id) {
                    continue;
                }
                check(interrupt)?;
                if expanded {
                    let new = if plan.kept.contains(&id) {
                        if self.lacks_trailers(id, &plan)? {
                            lacking.insert(id);
                        }
                        id
                    } else {
                        self.trailed(id, &plan)?
                    };
                    rewritten += usize::from(new != id);
                    plan.rewritten.insert(id, new);
                    continue;
                }
                stack.push((id, true));
                for parent in self.repo.find_commit(id)?.parent_ids() {
                    let parent = parent.detach();
                    if set.contains(&parent) && !plan.rewritten.contains_key(&parent) {
                        stack.push((parent, false));
                    }
                }
            }
        }
        let left_signed = commits
            .into_iter()
            .filter(|id| lacking.contains(id))
            .collect();
        let new_tip = plan.rewritten.get(&tip).copied().unwrap_or(tip);
        if new_tip != tip {
            self.move_branch(branch, tip, new_tip)?;
        }
        Ok(Trailed {
            rewritten,
            tip: new_tip,
            left_signed,
        })
    }

    fn unpublished(
        &self,
        tip: ObjectId,
        base: ObjectId,
        interrupt: &AtomicBool,
    ) -> Result<Vec<ObjectId>, StoreError> {
        let mut hidden = HashSet::from([base]);
        for (count, reference) in self
            .repo
            .references()
            .map_err(gix::Error::from_error)?
            .remote_branches()
            .map_err(gix::Error::from_error)?
            .enumerate()
        {
            if count >= MAX_HIDDEN_REFS {
                return Err(StoreError::TooManyRefs(count + 1));
            }
            let mut reference = reference.map_err(gix::Error::from_error)?;
            hidden.insert(reference.peel_to_id()?.detach());
        }
        let NewCommits { commits, .. } = self.new_commits(tip, &hidden, interrupt)?;
        if commits.len() > MAX_TRAILED_COMMITS {
            return Err(StoreError::TooManyCommits(MAX_TRAILED_COMMITS));
        }
        Ok(commits)
    }

    fn signed_and_before(
        &self,
        commits: &[ObjectId],
        set: &HashSet<ObjectId>,
        interrupt: &AtomicBool,
    ) -> Result<HashSet<ObjectId>, StoreError> {
        let mut kept = HashSet::new();
        let mut pending = Vec::new();
        for id in commits {
            check(interrupt)?;
            self.require_bounded(*id, Kind::Commit, MAX_TRAILED_COMMIT_BYTES)?;
            let object = self.repo.find_commit(*id)?;
            let commit = object.decode().map_err(gix::Error::from)?;
            if commit
                .extra_headers
                .iter()
                .any(|(name, _)| name.starts_with(SIGNATURE_HEADER))
            {
                pending.push(*id);
            }
        }
        while let Some(id) = pending.pop() {
            if !kept.insert(id) {
                continue;
            }
            check(interrupt)?;
            for parent in self.repo.find_commit(id)?.parent_ids() {
                let parent = parent.detach();
                if set.contains(&parent) {
                    pending.push(parent);
                }
            }
        }
        Ok(kept)
    }

    fn lacks_trailers(&self, id: ObjectId, plan: &Plan<'_>) -> Result<bool, StoreError> {
        self.require_bounded(id, Kind::Commit, MAX_TRAILED_COMMIT_BYTES)?;
        let object = self.repo.find_commit(id)?;
        let commit = object.decode().map_err(gix::Error::from)?;
        Ok(with_trailers(commit.message, plan.marker, plan.trailers).is_some())
    }

    fn trailed(&self, id: ObjectId, plan: &Plan<'_>) -> Result<ObjectId, StoreError> {
        self.require_bounded(id, Kind::Commit, MAX_TRAILED_COMMIT_BYTES)?;
        let object = self.repo.find_commit(id)?;
        let commit = object.decode().map_err(gix::Error::from)?;
        let message = with_trailers(commit.message, plan.marker, plan.trailers);
        let parents: Vec<ObjectId> = commit
            .parents()
            .map(|parent| plan.rewritten.get(&parent).copied().unwrap_or(parent))
            .collect();
        if message.is_none() && commit.parents().eq(parents.iter().copied()) {
            return Ok(id);
        }
        let mut owned = commit.into_owned().map_err(gix::Error::from)?;
        owned.parents = parents.into();
        if let Some(message) = message {
            owned.message = message;
        }
        Ok(self.repo.write_object(&owned)?.detach())
    }

    fn move_branch(&self, branch: &str, from: ObjectId, to: ObjectId) -> Result<(), StoreError> {
        let name = branch_ref(branch)?;
        let edited = self.repo.edit_references_as(
            Some(RefEdit::new(
                name.clone(),
                Change::Update {
                    log: LogChange {
                        mode: RefLog::AndReference,
                        force_create_reflog: false,
                        message: "mahi land: add trailers".into(),
                    },
                    expected: PreviousValue::MustExistAndMatch(Target::Object(from)),
                    new: Target::Object(to),
                },
            )),
            None,
        );
        match edited {
            Ok(_) => Ok(()),
            Err(error) => {
                let found = self.branch_tip(branch)?;
                if found == Some(from) {
                    Err(gix::Error::from_error(error).into())
                } else {
                    Err(StoreError::Conflict {
                        name: name.as_bstr().to_string(),
                        expected: Some(from),
                        found,
                    })
                }
            }
        }
    }
}

fn with_trailers(message: &BStr, (key, value): (&str, &str), trailers: &str) -> Option<BString> {
    let body = message.trim_end();
    let eol: &[u8] = if body.find(b"\r\n").is_some() {
        b"\r\n"
    } else {
        b"\n"
    };
    let block = last_paragraph(body).filter(|block| is_trailer_block(block));
    if block.is_some_and(|block| {
        block
            .lines()
            .filter_map(trailer_parts)
            .any(|(found, found_value)| {
                found.eq_ignore_ascii_case(key.as_bytes()) && found_value == value.as_bytes()
            })
    }) {
        return None;
    }
    let mut out = BString::from(Vec::with_capacity(
        body.len() + trailers.len() * 2 + 2 * eol.len(),
    ));
    out.extend_from_slice(body);
    out.extend_from_slice(eol);
    if block.is_none() {
        out.extend_from_slice(eol);
    }
    for line in trailers.as_bytes().lines() {
        out.extend_from_slice(line);
        out.extend_from_slice(eol);
    }
    Some(out)
}

fn last_paragraph(body: &[u8]) -> Option<&[u8]> {
    let mut start = None;
    let mut offset = 0;
    for line in body.lines_with_terminator() {
        offset += line.len();
        if line.trim().is_empty() {
            start = Some(offset);
        }
    }
    start.and_then(|at| body.get(at..))
}

fn is_trailer_block(block: &[u8]) -> bool {
    let mut trailers = 0_usize;
    let mut others = 0_usize;
    let mut generated = false;
    let mut after_trailer = false;
    for line in block.lines() {
        if after_trailer
            && line
                .first()
                .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
        {
            continue;
        }
        after_trailer = false;
        if line.starts_with(CHERRY_PICKED) {
            trailers += 1;
            generated = true;
        } else if let Some((key, _)) = trailer_parts(line) {
            trailers += 1;
            after_trailer = true;
            generated |= key.eq_ignore_ascii_case(SIGNED_OFF_BY);
        } else {
            others += 1;
        }
    }
    trailers > 0 && (others == 0 || (generated && trailers.saturating_mul(3) >= others))
}

fn trailer_parts(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let colon = line.find_byte(b':')?;
    let key = line.get(..colon)?.trim_end();
    let valid = !key.is_empty()
        && key
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-');
    if !valid {
        return None;
    }
    Some((key, line.get(colon + 1..)?.trim()))
}

fn check(interrupt: &AtomicBool) -> Result<(), StoreError> {
    if interrupt.load(Ordering::SeqCst) {
        Err(StoreError::Interrupted)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use gix::refs::transaction::PreviousValue;

    use super::*;

    const TRAILERS: &str = "Thread: t\nAgent: alice.claude\n";
    const MARKS: ((&str, &str), &str) = (("Thread", "t"), TRAILERS);

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        gix::init_bare(dir.path()).unwrap();
        let store = Store::open(dir.path()).unwrap();
        (dir, store)
    }

    fn commit(store: &Store, parents: &[ObjectId], message: &str, signed: bool) -> ObjectId {
        let blob = store.write_blob(message.as_bytes()).unwrap();
        let tree = store
            .write_tree(&[("f", gix::objs::tree::EntryKind::Blob, blob)])
            .unwrap();
        let signature = gix::actor::Signature {
            name: "a".into(),
            email: "a@example.com".into(),
            time: gix::date::Time::new(1_700_000_000, 3600),
        };
        let extra_headers = if signed {
            vec![(
                "gpgsig".into(),
                "-----BEGIN PGP SIGNATURE-----\n\nx\n".into(),
            )]
        } else {
            Vec::new()
        };
        store
            .repo
            .write_object(&gix::objs::Commit {
                tree,
                parents: parents.into(),
                author: signature.clone(),
                committer: signature,
                encoding: None,
                message: message.into(),
                extra_headers,
            })
            .unwrap()
            .detach()
    }

    fn set_ref(store: &Store, name: &str, id: ObjectId) {
        store
            .repo
            .reference(name, id, PreviousValue::Any, "test")
            .unwrap();
    }

    fn message(store: &Store, id: ObjectId) -> String {
        store
            .repo
            .find_commit(id)
            .unwrap()
            .message_raw()
            .unwrap()
            .to_string()
    }

    fn parents(store: &Store, id: ObjectId) -> Vec<ObjectId> {
        store
            .repo
            .find_commit(id)
            .unwrap()
            .parent_ids()
            .map(gix::Id::detach)
            .collect()
    }

    #[test]
    fn trailers_join_an_existing_block_or_start_one_and_are_not_added_twice() {
        let ours = "Thread: t\nAgent: alice.claude\n";
        let cases: [(&str, Option<&str>); 13] = [
            ("subject", Some("subject\n\n{}")),
            ("subject\n", Some("subject\n\n{}")),
            (
                "subject\n\nbody text\n\n",
                Some("subject\n\nbody text\n\n{}"),
            ),
            (
                "subject\n\nbody\n\nSigned-off-by: a <a@b>\n",
                Some("subject\n\nbody\n\nSigned-off-by: a <a@b>\n{}"),
            ),
            ("subject\n\nThread: t\n", None),
            ("subject\n\nthread :t\nAgent: x\n", None),
            (
                "subject\n\nThread: other\n",
                Some("subject\n\nThread: other\n{}"),
            ),
            ("Thread: t\n", Some("Thread: t\n\n{}")),
            (
                "s\n\nSigned-off-by: a <a@b>\n(cherry picked from commit abc)\n",
                Some("s\n\nSigned-off-by: a <a@b>\n(cherry picked from commit abc)\n{}"),
            ),
            (
                "s\n\nCo-authored-by: a\n  folded <a@b>\nReviewed-by:b\n",
                Some("s\n\nCo-authored-by: a\n  folded <a@b>\nReviewed-by:b\n{}"),
            ),
            (
                "s\n\nsome prose\nmore prose\nSigned-off-by: a <a@b>\n",
                Some("s\n\nsome prose\nmore prose\nSigned-off-by: a <a@b>\n{}"),
            ),
            (
                "s\n\nNote: this is prose\nthat goes on\n",
                Some("s\n\nNote: this is prose\nthat goes on\n\n{}"),
            ),
            (
                "s\r\n\r\nSigned-off-by: a <a@b>\r\n",
                Some("s\r\n\r\nSigned-off-by: a <a@b>\r\nThread: t\r\nAgent: alice.claude\r\n"),
            ),
        ];
        for (message, expected) in cases {
            assert_eq!(
                with_trailers(message.into(), ("Thread", "t"), TRAILERS),
                expected.map(|expected| BString::from(expected.replace("{}", ours))),
                "{message:?}"
            );
        }
    }

    #[test]
    fn unpushed_commits_and_merges_get_trailers_once_and_the_branch_moves() {
        let (_dir, store) = store();
        let none = AtomicBool::new(false);
        let base = commit(&store, &[], "base\n", false);
        let pushed = commit(&store, &[base], "pushed\n", false);
        set_ref(&store, "refs/remotes/origin/land", pushed);
        let left = commit(&store, &[pushed], "left\n", false);
        let right = commit(&store, &[base], "right\n\nthread :t\n", false);
        let merge = commit(&store, &[left, right], "merge\n", false);
        set_ref(&store, "refs/heads/land", merge);
        let trailed = store.add_trailers("land", base, MARKS, &none).unwrap();
        assert_eq!(trailed.rewritten, 2);
        assert!(trailed.left_signed.is_empty());
        assert_eq!(store.branch_tip("land").unwrap(), Some(trailed.tip));
        assert_eq!(message(&store, trailed.tip), format!("merge\n\n{TRAILERS}"));
        let [new_left, new_right] = parents(&store, trailed.tip)[..] else {
            panic!("a merge has two parents");
        };
        assert_eq!(new_right, right);
        assert_eq!(message(&store, new_left), format!("left\n\n{TRAILERS}"));
        assert_eq!(parents(&store, new_left), [pushed]);
        let again = store.add_trailers("land", base, MARKS, &none).unwrap();
        assert_eq!((again.rewritten, again.tip), (0, trailed.tip));
    }

    #[test]
    fn a_signed_commit_and_those_before_it_are_kept_and_listed() {
        let (_dir, store) = store();
        let none = AtomicBool::new(false);
        let base = commit(&store, &[], "base\n", false);
        let first = commit(&store, &[base], "first\n", false);
        let signed = commit(&store, &[first], "signed\n", true);
        let after = commit(&store, &[signed], "after\n", false);
        set_ref(&store, "refs/heads/land", after);
        let trailed = store.add_trailers("land", base, MARKS, &none).unwrap();
        assert_eq!(trailed.rewritten, 1);
        assert_eq!(trailed.left_signed, [signed, first]);
        assert_eq!(parents(&store, trailed.tip), [signed]);
        assert_eq!(message(&store, trailed.tip), format!("after\n\n{TRAILERS}"));
        let signed_trailed = commit(&store, &[base], &format!("s\n\n{TRAILERS}"), true);
        set_ref(&store, "refs/heads/land", signed_trailed);
        let kept = store.add_trailers("land", base, MARKS, &none).unwrap();
        assert_eq!((kept.rewritten, kept.tip), (0, signed_trailed));
        assert!(kept.left_signed.is_empty());
    }

    #[test]
    fn a_branch_that_moved_or_is_missing_is_refused_and_an_interrupt_stops() {
        let (_dir, store) = store();
        let base = commit(&store, &[], "base\n", false);
        let one = commit(&store, &[base], "one\n", false);
        let two = commit(&store, &[one], "two\n", false);
        set_ref(&store, "refs/heads/land", two);
        assert!(matches!(
            store.move_branch("land", one, base),
            Err(StoreError::Conflict { found: Some(found), .. }) if found == two
        ));
        assert!(matches!(
            store.add_trailers("missing", base, MARKS, &AtomicBool::new(false)),
            Err(StoreError::NoBranch(_))
        ));
        assert!(matches!(
            store.add_trailers("land", base, MARKS, &AtomicBool::new(true)),
            Err(StoreError::Interrupted)
        ));
        assert_eq!(store.branch_tip("land").unwrap(), Some(two));
    }

    #[test]
    fn an_unreadable_remote_tracking_branch_stops_the_rewrite() {
        let (dir, store) = store();
        let base = commit(&store, &[], "base\n", false);
        let one = commit(&store, &[base], "one\n", false);
        set_ref(&store, "refs/heads/land", one);
        let remotes = dir.path().join("refs/remotes/origin");
        std::fs::create_dir_all(&remotes).unwrap();
        std::fs::write(
            remotes.join("land"),
            "1111111111111111111111111111111111111111\n",
        )
        .unwrap();
        assert!(
            store
                .add_trailers("land", base, MARKS, &AtomicBool::new(false))
                .is_err()
        );
        assert_eq!(store.branch_tip("land").unwrap(), Some(one));
    }
}
