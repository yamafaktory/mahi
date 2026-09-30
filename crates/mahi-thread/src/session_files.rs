use std::{
    collections::{
        HashMap,
        HashSet,
    },
    fmt,
    io::{
        self,
        Read,
        Write,
    },
};

use mahi_core::{
    AgentSlot,
    RefKind,
    ThreadId,
    ThreadRef,
};
use mahi_crypto::{
    DERIVED_KEY_BYTES,
    DeriveError,
    OpenError,
    SealError,
    ThreadKey,
};
use mahi_store::{
    CommitSigner,
    EntryKind,
    ObjectId,
    Store,
    StoreError,
};
use serde::{
    Deserialize,
    Deserializer,
    Serialize,
    de::{
        self,
        SeqAccess,
        Visitor,
    },
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    ParticipantKey,
    commits::signed_by,
};

/// The size of the pieces session files are sealed in; only the last piece of a file is
/// shorter.
pub const SESSION_CHUNK_BYTES: usize = 64 * 1024;
/// The most files one session commit holds.
pub const MAX_SESSION_FILES: usize = 4096;
/// The most distinct pieces one session commit holds.
pub const MAX_SESSION_CHUNKS: usize = 8192;
/// The most bytes the files of one session commit hold together.
pub const MAX_SESSION_BYTES: u64 = 512 * 1024 * 1024;
/// The longest path of a session file, in bytes.
pub const MAX_SESSION_PATH_BYTES: usize = 1024;

const MAX_COMPONENT_BYTES: usize = 255;
const MAX_DEPTH: usize = 16;
const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_SEALED_CHUNK_BYTES: u64 = sealed_bound(SESSION_CHUNK_BYTES);
const MAX_SEALED_MANIFEST_BYTES: u64 = sealed_bound(MAX_MANIFEST_BYTES);
const MANIFEST_ENTRY: &str = "manifest";
const SESSION_MESSAGE: &str = "session";
const VERSION: u16 = 1;
const TAG_SALT: &[u8] = b"mahi session files";
const TAG_INFO: &[u8] = b"chunk tag v1";

const fn sealed_bound(plaintext: usize) -> u64 {
    (plaintext + plaintext / 255 + 64 * 1024) as u64
}

/// The path of a session file, relative to the directory the agent keeps its session in:
/// `/`-separated, with no empty, `.` or `..` component and no NUL byte.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SessionPath(String);

impl SessionPath {
    /// Checks `path`.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidPath`] if `path` is empty, longer than
    /// [`MAX_SESSION_PATH_BYTES`], deeper than 16 components, or has an empty, `.`, `..` or
    /// overlong component or a NUL byte.
    pub fn new(path: &str) -> Result<Self, SessionError> {
        if path.is_empty() || path.len() > MAX_SESSION_PATH_BYTES {
            return Err(SessionError::InvalidPath);
        }
        let components: Vec<&str> = path.split('/').collect();
        let valid = components.len() <= MAX_DEPTH
            && components.iter().all(|component| {
                !component.is_empty()
                    && *component != "."
                    && *component != ".."
                    && component.len() <= MAX_COMPONENT_BYTES
                    && !component.contains('\0')
            });
        if valid {
            Ok(Self(path.to_owned()))
        } else {
            Err(SessionError::InvalidPath)
        }
    }

    /// Returns the path's components, from the top.
    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }

    /// Returns the path as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SessionPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionPath")
    }
}

/// Recording or reading an agent's session files failed.
///
/// Neither messages nor `Debug` output include paths, which come from sealed content.
#[derive(Debug, Error)]
pub enum SessionError {
    /// A path is not a valid [`SessionPath`].
    #[error("a session file path is not valid")]
    InvalidPath,
    /// The same path was given twice.
    #[error("a session file is given twice")]
    DuplicatePath,
    /// There are more than [`MAX_SESSION_FILES`] files.
    #[error("the session has more than {MAX_SESSION_FILES} files")]
    TooManyFiles,
    /// The manifest would be larger than the files' limits allow.
    #[error("the session manifest is too large")]
    ManifestTooLarge,
    /// The previous session commit is not signed by the user's own key, so its pieces are not
    /// reused.
    #[error("session commit {0} is not signed by your key")]
    NotOwn(ObjectId),
    /// The session ref moved since the previous commit.
    #[error("the session ref moved while it was recorded")]
    Moved,
    /// There are more than [`MAX_SESSION_CHUNKS`] distinct pieces.
    #[error("the session has more than {MAX_SESSION_CHUNKS} pieces")]
    TooManyChunks,
    /// The files hold more than [`MAX_SESSION_BYTES`] bytes together.
    #[error("the session files hold more than {MAX_SESSION_BYTES} bytes")]
    TooLarge,
    /// A session commit has no manifest, or a manifest or piece that does not decode, is
    /// inconsistent, or does not match its tag.
    #[error("session commit {0} is malformed")]
    Malformed(ObjectId),
    /// The manifest uses a format version this build does not read.
    #[error("session format version {0} is not supported")]
    UnsupportedVersion(u16),
    /// Encoding the manifest failed.
    #[error("cannot encode the session manifest")]
    Encode(#[source] postcard::Error),
    /// Deriving the tag key failed.
    #[error("cannot derive the session key")]
    Derive(#[from] DeriveError),
    /// Sealing failed.
    #[error("cannot seal the session")]
    Seal(#[from] SealError),
    /// Opening failed: the content is not sealed to this thread's key, or was tampered with.
    #[error("cannot open the session")]
    Open(#[from] OpenError),
    /// Reading a file to record failed.
    #[error("cannot read a session file")]
    Read(#[source] io::Error),
    /// Writing a file back failed.
    #[error("cannot write a session file")]
    Write(#[source] io::Error),
    /// Reading or writing the repository failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

type Tag = [u8; 32];

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Manifest {
    version: u16,
    #[serde(deserialize_with = "bounded_files")]
    files: Vec<ManifestFile>,
}

fn bounded_files<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ManifestFile>, D::Error> {
    deserializer.deserialize_seq(BoundedFiles)
}

struct BoundedFiles;

impl<'de> Visitor<'de> for BoundedFiles {
    type Value = Vec<ManifestFile>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "at most {MAX_SESSION_FILES} files")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut files = Vec::new();
        while let Some(file) = seq.next_element()? {
            if files.len() >= MAX_SESSION_FILES {
                return Err(de::Error::custom("too many files"));
            }
            files.push(file);
        }
        Ok(files)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
struct ManifestFile {
    path: String,
    len: u64,
    chunks: Vec<Tag>,
}

struct Tagger(Zeroizing<[u8; DERIVED_KEY_BYTES]>);

impl Tagger {
    fn new(key: &ThreadKey) -> Result<Self, SessionError> {
        Ok(Self(key.derive(TAG_SALT, TAG_INFO)?))
    }

    fn tag(&self, chunk: &[u8]) -> Tag {
        *blake3::keyed_hash(&self.0, chunk).as_bytes()
    }
}

fn entry_name(tag: &Tag) -> String {
    let mut name = String::with_capacity(tag.len() * 2);
    for byte in tag {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    name
}

const HEX: [u8; 16] = *b"0123456789abcdef";

/// Returns the ref holding `slot`'s session files in `thread`.
#[must_use]
pub fn session_ref(thread: ThreadId, slot: &AgentSlot) -> ThreadRef {
    ThreadRef::new(thread, RefKind::Session(slot.clone()))
}

/// Records an agent's session files in a new commit on its session ref, sealed to the thread
/// key in pieces of [`SESSION_CHUNK_BYTES`].
///
/// Each piece is named in the commit's tree by its tag, a keyed BLAKE3 hash under a key
/// derived from the thread key, so a piece the previous commit already holds is reused rather
/// than sealed again: a file that only grew costs the pieces it gained. The paths, sizes and
/// tags are in a sealed manifest.
pub struct SessionWriter<'a> {
    store: &'a Store,
    key: &'a ThreadKey,
    tagger: Tagger,
    previous: Option<ObjectId>,
    previous_manifest: Option<Manifest>,
    known: HashMap<String, ObjectId>,
    used: HashMap<String, ObjectId>,
    paths: HashSet<SessionPath>,
    files: Vec<ManifestFile>,
    total: u64,
    buffer: Vec<u8>,
}

impl fmt::Debug for SessionWriter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionWriter")
            .field("previous", &self.previous)
            .field("files", &self.files.len())
            .finish_non_exhaustive()
    }
}

impl<'a> SessionWriter<'a> {
    /// Starts a commit on top of `previous`, the session ref's current commit, if any, whose
    /// pieces are reused only once it is found signed by `own`, the user's key.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::NotOwn`] if `previous` is not signed by `own`, or another
    /// [`SessionError`] if it cannot be read or opened.
    pub fn new(
        store: &'a Store,
        key: &'a ThreadKey,
        own: &ParticipantKey,
        previous: Option<ObjectId>,
    ) -> Result<Self, SessionError> {
        let tagger = Tagger::new(key)?;
        let (known, previous_manifest) = match previous {
            Some(commit) => {
                if !signed_by(store, commit, own)? {
                    return Err(SessionError::NotOwn(commit));
                }
                let mut blobs: HashMap<String, ObjectId> =
                    store.commit_blobs(commit)?.into_iter().collect();
                let manifest = blobs
                    .remove(MANIFEST_ENTRY)
                    .ok_or(SessionError::Malformed(commit))?;
                (blobs, Some(read_manifest(store, key, commit, manifest)?))
            }
            None => (HashMap::new(), None),
        };
        Ok(Self {
            store,
            key,
            tagger,
            previous,
            previous_manifest,
            known,
            used: HashMap::new(),
            paths: HashSet::new(),
            files: Vec::new(),
            total: 0,
            buffer: vec![0; SESSION_CHUNK_BYTES],
        })
    }

    /// Adds the file `path`, read from `reader` to its end.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::DuplicatePath`], [`SessionError::TooManyFiles`],
    /// [`SessionError::TooManyChunks`] or [`SessionError::TooLarge`] when a limit is passed,
    /// [`SessionError::Read`] if reading fails, or another [`SessionError`] if a piece cannot
    /// be sealed or written.
    pub fn add(&mut self, path: SessionPath, reader: &mut dyn Read) -> Result<(), SessionError> {
        if self.files.len() >= MAX_SESSION_FILES {
            return Err(SessionError::TooManyFiles);
        }
        if self.paths.contains(&path) {
            return Err(SessionError::DuplicatePath);
        }
        let total = self.total;
        let mut added = Vec::new();
        let read = self.read_file(&path, reader, &mut added);
        match read {
            Ok(file) => {
                self.paths.insert(path);
                self.files.push(file);
                Ok(())
            }
            Err(error) => {
                self.total = total;
                for name in added {
                    self.used.remove(&name);
                }
                Err(error)
            }
        }
    }

    fn read_file(
        &mut self,
        path: &SessionPath,
        reader: &mut dyn Read,
        added: &mut Vec<String>,
    ) -> Result<ManifestFile, SessionError> {
        let mut file = ManifestFile {
            path: path.0.clone(),
            len: 0,
            chunks: Vec::new(),
        };
        loop {
            let read = read_full(reader, &mut self.buffer).map_err(SessionError::Read)?;
            if read == 0 {
                break;
            }
            let chunk = self.buffer.get(..read).unwrap_or_default();
            self.total = self
                .total
                .checked_add(read as u64)
                .filter(|total| *total <= MAX_SESSION_BYTES)
                .ok_or(SessionError::TooLarge)?;
            let tag = self.tagger.tag(chunk);
            let name = entry_name(&tag);
            if !self.used.contains_key(&name) {
                if self.used.len() >= MAX_SESSION_CHUNKS {
                    return Err(SessionError::TooManyChunks);
                }
                let blob = match self.known.get(&name) {
                    Some(blob) => *blob,
                    None => self.store.write_sealed(self.key, chunk)?,
                };
                self.used.insert(name.clone(), blob);
                added.push(name);
            }
            file.len += read as u64;
            file.chunks.push(tag);
            if read < SESSION_CHUNK_BYTES {
                break;
            }
        }
        Ok(file)
    }

    /// Commits the files added so far on `slot`'s session ref in `thread`, signed by `signer`,
    /// and returns the commit; when they are exactly what the previous commit holds, nothing is
    /// written and the previous commit is returned. A writer whose [`SessionWriter::add`]
    /// failed commits the files added before, as if the failed one was never given.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Moved`] or [`SessionError::Store`] if the session ref moved
    /// since the previous commit, [`SessionError::ManifestTooLarge`] if the manifest passes its
    /// limit, or another [`SessionError`] if it cannot be sealed or the commit written.
    pub fn commit(
        mut self,
        thread: ThreadId,
        slot: &AgentSlot,
        signer: &dyn CommitSigner,
    ) -> Result<ObjectId, SessionError> {
        self.files.sort_by(|left, right| left.path.cmp(&right.path));
        let manifest = Manifest {
            version: VERSION,
            files: self.files,
        };
        let session = session_ref(thread, slot);
        if let Some(previous) = self.previous
            && self.previous_manifest.as_ref() == Some(&manifest)
        {
            if self.store.head(&session)? != Some(previous) {
                return Err(SessionError::Moved);
            }
            return Ok(previous);
        }
        let encoded = postcard::to_allocvec(&manifest).map_err(SessionError::Encode)?;
        if encoded.len() > MAX_MANIFEST_BYTES {
            return Err(SessionError::ManifestTooLarge);
        }
        let sealed = self.store.write_sealed(self.key, &encoded)?;
        let mut entries: Vec<(&str, EntryKind, ObjectId)> = self
            .used
            .iter()
            .map(|(name, blob)| (name.as_str(), EntryKind::Blob, *blob))
            .collect();
        entries.push((MANIFEST_ENTRY, EntryKind::Blob, sealed));
        let tree = self.store.write_tree(&entries)?;
        Ok(self
            .store
            .append_signed(&session, self.previous, tree, SESSION_MESSAGE, signer)?)
    }
}

fn read_full(reader: &mut dyn Read, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while let Some(rest) = buffer.get_mut(filled..).filter(|rest| !rest.is_empty()) {
        match reader.read(rest) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

fn read_manifest(
    store: &Store,
    key: &ThreadKey,
    commit: ObjectId,
    blob: ObjectId,
) -> Result<Manifest, SessionError> {
    let sealed = store.read_blob(blob, MAX_SEALED_MANIFEST_BYTES)?;
    let encoded = key.open(&sealed, MAX_MANIFEST_BYTES)?;
    decode_manifest(&encoded, commit)
}

/// Decodes a manifest's plaintext, refusing trailing bytes and other versions.
pub(crate) fn decode_manifest(encoded: &[u8], commit: ObjectId) -> Result<Manifest, SessionError> {
    let (manifest, rest): (Manifest, &[u8]) =
        postcard::take_from_bytes(encoded).map_err(|_| SessionError::Malformed(commit))?;
    if !rest.is_empty() {
        return Err(SessionError::Malformed(commit));
    }
    if manifest.version != VERSION {
        return Err(SessionError::UnsupportedVersion(manifest.version));
    }
    Ok(manifest)
}

/// A file of a recorded session: its path and size.
///
/// Neither appears in `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionFile {
    /// The file's path.
    pub path: SessionPath,
    /// The file's size in bytes.
    pub len: u64,
}

impl fmt::Debug for SessionFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionFile")
    }
}

/// Reads back the files a session commit recorded, checking each piece against its tag.
pub struct SessionReader<'a> {
    store: &'a Store,
    key: &'a ThreadKey,
    tagger: Tagger,
    commit: ObjectId,
    blobs: HashMap<String, ObjectId>,
    manifest: Manifest,
    files: Vec<SessionFile>,
}

impl fmt::Debug for SessionReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionReader")
            .field("commit", &self.commit)
            .field("files", &self.files.len())
            .finish_non_exhaustive()
    }
}

impl<'a> SessionReader<'a> {
    /// Opens the session commit `commit` and checks its manifest: valid paths in strictly
    /// ascending order, none of them a directory of another or the same as another but for
    /// ASCII case, sizes that match their pieces, every piece in the tree, and the limits of
    /// [`SessionWriter`].
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Malformed`] if the commit or its manifest does not check out,
    /// [`SessionError::TooManyFiles`] or [`SessionError::TooLarge`] if it passes a limit, or
    /// another [`SessionError`] if it cannot be read or opened.
    pub fn open(
        store: &'a Store,
        key: &'a ThreadKey,
        commit: ObjectId,
    ) -> Result<Self, SessionError> {
        let malformed = || SessionError::Malformed(commit);
        let mut blobs: HashMap<String, ObjectId> =
            store.commit_blobs(commit)?.into_iter().collect();
        let manifest_blob = blobs.remove(MANIFEST_ENTRY).ok_or_else(malformed)?;
        let manifest = read_manifest(store, key, commit, manifest_blob)?;
        if manifest.files.len() > MAX_SESSION_FILES {
            return Err(SessionError::TooManyFiles);
        }
        let mut total: u64 = 0;
        let mut folded = HashSet::new();
        let mut directories = HashSet::new();
        let mut files = Vec::with_capacity(manifest.files.len());
        let mut last: Option<&str> = None;
        for file in &manifest.files {
            let path = SessionPath::new(&file.path).map_err(|_| malformed())?;
            if last.is_some_and(|last| last >= file.path.as_str()) {
                return Err(malformed());
            }
            last = Some(&file.path);
            if !folded.insert(file.path.to_ascii_lowercase()) {
                return Err(malformed());
            }
            let mut prefix = String::new();
            let components: Vec<&str> = path.components().collect();
            for component in components.iter().take(components.len().saturating_sub(1)) {
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(&component.to_ascii_lowercase());
                directories.insert(prefix.clone());
            }
            files.push(SessionFile {
                path,
                len: file.len,
            });
            let pieces = file.len.div_ceil(SESSION_CHUNK_BYTES as u64);
            if pieces != file.chunks.len() as u64 {
                return Err(malformed());
            }
            if file
                .chunks
                .iter()
                .any(|tag| !blobs.contains_key(&entry_name(tag)))
            {
                return Err(malformed());
            }
            total = total
                .checked_add(file.len)
                .filter(|total| *total <= MAX_SESSION_BYTES)
                .ok_or(SessionError::TooLarge)?;
        }
        if folded.iter().any(|path| directories.contains(path)) {
            return Err(malformed());
        }
        Ok(Self {
            store,
            key,
            tagger: Tagger::new(key)?,
            commit,
            blobs,
            manifest,
            files,
        })
    }

    /// Returns the recorded files, sorted by path.
    #[must_use]
    pub fn files(&self) -> &[SessionFile] {
        &self.files
    }

    /// Writes the contents of the file at `index` in [`SessionReader::files`] to `out`, one
    /// piece at a time, each checked against its tag and size before it is written.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Malformed`] if `index` is out of range or a piece does not
    /// match, [`SessionError::Write`] if writing fails, or another [`SessionError`] if a piece
    /// cannot be read or opened.
    pub fn copy(&self, index: usize, out: &mut dyn Write) -> Result<(), SessionError> {
        let malformed = || SessionError::Malformed(self.commit);
        let file = self.manifest.files.get(index).ok_or_else(malformed)?;
        let mut left = file.len;
        for tag in &file.chunks {
            let expected = left.min(SESSION_CHUNK_BYTES as u64);
            let blob = self.blobs.get(&entry_name(tag)).ok_or_else(malformed)?;
            let sealed = self.store.read_blob(*blob, MAX_SEALED_CHUNK_BYTES)?;
            let chunk = self.key.open(&sealed, SESSION_CHUNK_BYTES)?;
            if chunk.len() as u64 != expected || self.tagger.tag(&chunk) != *tag {
                return Err(malformed());
            }
            out.write_all(&chunk).map_err(SessionError::Write)?;
            left -= expected;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use mahi_core::{
        AgentName,
        ParticipantName,
    };
    use ssh_key::{
        Algorithm,
        PrivateKey,
        rand_core::OsRng,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::GitSigner;

    struct Setup {
        _dir: TempDir,
        store: Store,
        key: ThreadKey,
        thread: ThreadId,
        slot: AgentSlot,
        signer: GitSigner<PrivateKey>,
        own: ParticipantKey,
    }

    fn setup() -> Setup {
        let dir = TempDir::new().unwrap();
        gix::init(dir.path()).unwrap();
        let signer = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        Setup {
            own: ParticipantKey::from_public_key(signer.public_key()).unwrap(),
            store: Store::open(dir.path()).unwrap(),
            _dir: dir,
            key: ThreadKey::generate(),
            thread: ThreadId::random().unwrap(),
            slot: AgentSlot::new(
                ParticipantName::new("alice").unwrap(),
                AgentName::new("claude").unwrap(),
            ),
            signer: GitSigner(signer),
        }
    }

    fn path(text: &str) -> SessionPath {
        SessionPath::new(text).unwrap()
    }

    fn record(setup: &Setup, files: &[(&str, &[u8])]) -> ObjectId {
        let previous = setup
            .store
            .head(&session_ref(setup.thread, &setup.slot))
            .unwrap();
        let mut writer =
            SessionWriter::new(&setup.store, &setup.key, &setup.own, previous).unwrap();
        for (name, content) in files {
            writer.add(path(name), &mut &content[..]).unwrap();
        }
        writer
            .commit(setup.thread, &setup.slot, &setup.signer)
            .unwrap()
    }

    fn read_back(setup: &Setup, commit: ObjectId) -> Vec<(String, Vec<u8>)> {
        let reader = SessionReader::open(&setup.store, &setup.key, commit).unwrap();
        (0..reader.files().len())
            .map(|index| {
                let mut out = Vec::new();
                reader.copy(index, &mut out).unwrap();
                let file = &reader.files()[index];
                assert_eq!(file.len, out.len() as u64);
                (file.path.as_str().to_owned(), out)
            })
            .collect()
    }

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|index| u8::try_from(index % 251).unwrap() ^ seed)
            .collect()
    }

    #[test]
    fn files_read_back_as_recorded_and_the_commit_is_signed() {
        let setup = setup();
        let big = pattern(SESSION_CHUNK_BYTES * 2 + 17, 1);
        let exact = pattern(SESSION_CHUNK_BYTES, 2);
        let commit = record(
            &setup,
            &[
                ("s/b.jsonl", &big),
                ("a.jsonl", b"one line\n"),
                ("empty", b""),
                ("s/exact", &exact),
            ],
        );
        assert_eq!(
            read_back(&setup, commit),
            [
                ("a.jsonl".to_owned(), b"one line\n".to_vec()),
                ("empty".to_owned(), Vec::new()),
                ("s/b.jsonl".to_owned(), big),
                ("s/exact".to_owned(), exact),
            ]
        );
        let key = ParticipantKey::from_public_key(setup.signer.0.public_key()).unwrap();
        assert!(signed_by(&setup.store, commit, &key).unwrap());
    }

    #[test]
    fn a_grown_file_reuses_its_earlier_pieces_and_no_change_writes_nothing() {
        let setup = setup();
        let start = pattern(SESSION_CHUNK_BYTES * 3, 3);
        let first = record(&setup, &[("log", &start)]);
        let mut grown = start.clone();
        grown.extend_from_slice(b"appended turn\n");
        let second = record(&setup, &[("log", &grown)]);
        assert_ne!(first, second);
        let before: HashSet<ObjectId> = setup
            .store
            .commit_blobs(first)
            .unwrap()
            .into_iter()
            .filter(|(name, _)| name != MANIFEST_ENTRY)
            .map(|(_, blob)| blob)
            .collect();
        let after: Vec<ObjectId> = setup
            .store
            .commit_blobs(second)
            .unwrap()
            .into_iter()
            .filter(|(name, _)| name != MANIFEST_ENTRY)
            .map(|(_, blob)| blob)
            .collect();
        assert_eq!(after.len(), 4);
        assert_eq!(
            after.iter().filter(|blob| before.contains(*blob)).count(),
            3
        );
        assert_eq!(
            read_back(&setup, second),
            [("log".to_owned(), grown.clone())]
        );
        let third = record(&setup, &[("log", &grown)]);
        assert_eq!(third, second);
        assert_eq!(setup.store.parent(second).unwrap(), Some(first));
    }

    #[test]
    fn bad_paths_duplicates_and_limits_are_refused() {
        for bad in [
            "",
            "/abs",
            "a//b",
            "a/./b",
            "../up",
            "a/..",
            "trailing/",
            "nul\0",
        ] {
            assert!(SessionPath::new(bad).is_err(), "{bad:?}");
        }
        assert!(SessionPath::new(&"a".repeat(256)).is_err());
        assert!(SessionPath::new(&["a"; 17].join("/")).is_err());
        assert!(SessionPath::new(&["a"; 16].join("/")).is_ok());
        let setup = setup();
        let mut writer = SessionWriter::new(&setup.store, &setup.key, &setup.own, None).unwrap();
        writer.add(path("x"), &mut &b"1"[..]).unwrap();
        assert!(matches!(
            writer.add(path("x"), &mut &b"2"[..]),
            Err(SessionError::DuplicatePath)
        ));
        for index in 1..MAX_SESSION_FILES {
            writer
                .add(path(&format!("f{index}")), &mut &b""[..])
                .unwrap();
        }
        assert!(matches!(
            writer.add(path("one-more"), &mut &b""[..]),
            Err(SessionError::TooManyFiles)
        ));
    }

    struct Failing(usize);

    impl Read for Failing {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.0 == 0 {
                return Err(io::Error::other("gone"));
            }
            self.0 -= 1;
            buffer.fill(9);
            Ok(buffer.len())
        }
    }

    #[test]
    fn a_file_that_fails_midway_is_left_out_whole_and_can_be_given_again() {
        let setup = setup();
        let mut writer = SessionWriter::new(&setup.store, &setup.key, &setup.own, None).unwrap();
        writer.add(path("kept"), &mut &b"kept"[..]).unwrap();
        assert!(matches!(
            writer.add(path("broken"), &mut Failing(2)),
            Err(SessionError::Read(_))
        ));
        writer.add(path("broken"), &mut &b"whole"[..]).unwrap();
        let commit = writer
            .commit(setup.thread, &setup.slot, &setup.signer)
            .unwrap();
        assert_eq!(
            read_back(&setup, commit),
            [
                ("broken".to_owned(), b"whole".to_vec()),
                ("kept".to_owned(), b"kept".to_vec()),
            ]
        );
        assert_eq!(setup.store.commit_blobs(commit).unwrap().len(), 3);
    }

    #[test]
    fn a_previous_commit_not_signed_by_the_user_is_not_built_on() {
        let setup = setup();
        let first = record(&setup, &[("f", b"one")]);
        let stranger = self::setup();
        assert!(matches!(
            SessionWriter::new(&setup.store, &setup.key, &stranger.own, Some(first)),
            Err(SessionError::NotOwn(commit)) if commit == first
        ));
        let writer = SessionWriter::new(&setup.store, &setup.key, &setup.own, Some(first)).unwrap();
        let session = session_ref(setup.thread, &setup.slot);
        let moved = record(&setup, &[("f", b"two")]);
        assert_eq!(setup.store.head(&session).unwrap(), Some(moved));
        let mut stale = writer;
        stale.add(path("f"), &mut &b"one"[..]).unwrap();
        assert!(matches!(
            stale.commit(setup.thread, &setup.slot, &setup.signer),
            Err(SessionError::Moved)
        ));
    }

    fn forged(setup: &Setup, manifest: &Manifest, pieces: &[&[u8]]) -> ObjectId {
        let encoded = postcard::to_allocvec(manifest).unwrap();
        let sealed = setup.store.write_sealed(&setup.key, &encoded).unwrap();
        let tagger = Tagger::new(&setup.key).unwrap();
        let names: Vec<(String, ObjectId)> = pieces
            .iter()
            .map(|piece| {
                (
                    entry_name(&tagger.tag(piece)),
                    setup.store.write_sealed(&setup.key, piece).unwrap(),
                )
            })
            .collect();
        let mut entries: Vec<(&str, EntryKind, ObjectId)> = names
            .iter()
            .map(|(name, blob)| (name.as_str(), EntryKind::Blob, *blob))
            .collect();
        entries.push((MANIFEST_ENTRY, EntryKind::Blob, sealed));
        let tree = setup.store.write_tree(&entries).unwrap();
        let scratch = ThreadRef::new(ThreadId::random().unwrap(), RefKind::Meta);
        setup.store.append(&scratch, None, tree, "x").unwrap()
    }

    #[test]
    fn manifests_past_the_file_limit_or_of_a_newer_version_are_refused() {
        let setup = setup();
        let many = forged(
            &setup,
            &Manifest {
                version: VERSION,
                files: (0..=MAX_SESSION_FILES)
                    .map(|index| ManifestFile {
                        path: format!("{index:05}"),
                        len: 0,
                        chunks: Vec::new(),
                    })
                    .collect(),
            },
            &[],
        );
        assert!(matches!(
            SessionReader::open(&setup.store, &setup.key, many),
            Err(SessionError::Malformed(_))
        ));
        let newer = forged(
            &setup,
            &Manifest {
                version: VERSION + 1,
                files: Vec::new(),
            },
            &[],
        );
        assert!(matches!(
            SessionReader::open(&setup.store, &setup.key, newer),
            Err(SessionError::UnsupportedVersion(version)) if version == VERSION + 1
        ));
    }

    #[test]
    fn a_manifest_that_does_not_match_its_pieces_is_refused() {
        let setup = setup();
        let tagger = Tagger::new(&setup.key).unwrap();
        let piece = b"piece".as_slice();
        let file = |path: &str, len: u64, chunks: Vec<Tag>| ManifestFile {
            path: path.to_owned(),
            len,
            chunks,
        };
        let one = || vec![tagger.tag(piece)];
        let cases = [
            vec![file("b", 5, one()), file("a", 5, one())],
            vec![file("a", 5, one()), file("a/b", 5, one())],
            vec![file("A/b", 5, one()), file("a", 5, one())],
            vec![file("Same", 5, one()), file("same", 5, one())],
            vec![file("../escape", 5, vec![tagger.tag(piece)])],
            vec![
                file("same", 5, vec![tagger.tag(piece)]),
                file("same", 5, vec![tagger.tag(piece)]),
            ],
            vec![file(
                "short",
                SESSION_CHUNK_BYTES as u64 + 1,
                vec![tagger.tag(piece)],
            )],
            vec![file("missing", 5, vec![tagger.tag(b"other")])],
        ];
        for files in cases {
            let commit = forged(
                &setup,
                &Manifest {
                    version: VERSION,
                    files,
                },
                &[piece],
            );
            assert!(matches!(
                SessionReader::open(&setup.store, &setup.key, commit),
                Err(SessionError::Malformed(found)) if found == commit
            ));
        }
        let zeros = vec![0; SESSION_CHUNK_BYTES];
        let repeated = vec![
            tagger.tag(&zeros);
            usize::try_from(MAX_SESSION_BYTES).unwrap() / SESSION_CHUNK_BYTES + 1
        ];
        let len = repeated.len() as u64 * SESSION_CHUNK_BYTES as u64;
        let bomb = forged(
            &setup,
            &Manifest {
                version: VERSION,
                files: vec![file("bomb", len, repeated)],
            },
            &[&zeros],
        );
        assert!(matches!(
            SessionReader::open(&setup.store, &setup.key, bomb),
            Err(SessionError::TooLarge)
        ));
        let lying = forged(
            &setup,
            &Manifest {
                version: VERSION,
                files: vec![file("lying", 5, vec![tagger.tag(piece)])],
            },
            &[piece],
        );
        let swapped_tree = setup
            .store
            .write_tree(&[
                (
                    entry_name(&tagger.tag(piece)).as_str(),
                    EntryKind::Blob,
                    setup.store.write_sealed(&setup.key, b"other").unwrap(),
                ),
                (
                    MANIFEST_ENTRY,
                    EntryKind::Blob,
                    setup
                        .store
                        .commit_blobs(lying)
                        .unwrap()
                        .into_iter()
                        .find(|(name, _)| name == MANIFEST_ENTRY)
                        .unwrap()
                        .1,
                ),
            ])
            .unwrap();
        let scratch = ThreadRef::new(ThreadId::random().unwrap(), RefKind::Meta);
        let swapped = setup
            .store
            .append(&scratch, None, swapped_tree, "x")
            .unwrap();
        let reader = SessionReader::open(&setup.store, &setup.key, swapped).unwrap();
        assert!(matches!(
            reader.copy(0, &mut Vec::new()),
            Err(SessionError::Malformed(_))
        ));
        let other_key = ThreadKey::generate();
        assert!(SessionReader::open(&setup.store, &other_key, lying).is_err());
    }
}
