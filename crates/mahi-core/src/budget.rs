use std::{
    fmt,
    io::{
        self,
        Read,
    },
    sync::{
        Arc,
        atomic::{
            AtomicBool,
            AtomicU64,
            Ordering,
        },
    },
};

/// How many bytes may be read from a remote, shared by every reader made from it, and whether
/// a read went past it.
#[derive(Debug, Clone)]
pub struct ReadBudget {
    limit: u64,
    read: Arc<AtomicU64>,
    exceeded: Arc<AtomicBool>,
}

/// A read went past its [`ReadBudget`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverBudget {
    /// The budget, in bytes.
    pub limit: u64,
}

impl fmt::Display for OverBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the remote sent more than {} bytes", self.limit)
    }
}

impl std::error::Error for OverBudget {}

/// A reader that takes what it reads from a [`ReadBudget`], and fails once the budget is
/// spent.
#[derive(Debug)]
pub struct BudgetedRead<R> {
    inner: R,
    budget: ReadBudget,
}

impl ReadBudget {
    /// A budget of `limit` bytes.
    #[must_use]
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            read: Arc::new(AtomicU64::new(0)),
            exceeded: Arc::new(AtomicBool::new(false)),
        }
    }

    /// A budget no read can spend.
    #[must_use]
    pub fn unlimited() -> Self {
        Self::new(u64::MAX)
    }

    /// The budget, in bytes.
    #[must_use]
    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// Whether a read went past the budget.
    #[must_use]
    pub fn exceeded(&self) -> bool {
        self.exceeded.load(Ordering::SeqCst)
    }

    /// Returns `inner`, reading from this budget.
    #[must_use]
    pub fn reader<R>(&self, inner: R) -> BudgetedRead<R> {
        BudgetedRead {
            inner,
            budget: self.clone(),
        }
    }

    /// Takes `bytes` read from the remote from the budget.
    ///
    /// # Errors
    ///
    /// Returns [`OverBudget`] once the bytes taken pass the budget; it is marked as exceeded.
    pub fn charge(&self, bytes: usize) -> Result<(), OverBudget> {
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        let before = self.read.fetch_add(bytes, Ordering::SeqCst);
        if before.saturating_add(bytes) > self.limit {
            self.exceeded.store(true, Ordering::SeqCst);
            return Err(OverBudget { limit: self.limit });
        }
        Ok(())
    }
}

impl<R: Read> Read for BudgetedRead<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.budget.exceeded() {
            return Err(io::Error::other(OverBudget {
                limit: self.budget.limit,
            }));
        }
        let read = self.inner.read(buffer)?;
        self.budget.charge(read).map_err(io::Error::other)?;
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readers_share_the_budget_and_fail_once_it_is_spent() {
        let budget = ReadBudget::new(10);
        let mut first = budget.reader(&b"123456"[..]);
        let mut second = budget.reader(&b"abcdef"[..]);
        let mut buffer = [0_u8; 6];
        assert_eq!(first.read(&mut buffer).unwrap(), 6);
        assert!(!budget.exceeded());
        let error = second.read(&mut buffer).unwrap_err();
        assert_eq!(
            error.get_ref().unwrap().downcast_ref::<OverBudget>(),
            Some(&OverBudget { limit: 10 })
        );
        assert!(budget.exceeded());
        assert!(first.read(&mut buffer).is_err());
        assert_eq!(
            OverBudget { limit: 10 }.to_string(),
            "the remote sent more than 10 bytes"
        );
    }

    #[test]
    fn an_unlimited_budget_and_one_spent_exactly_never_fail() {
        let budget = ReadBudget::new(6);
        let mut exact = budget.reader(&b"123456"[..]);
        let mut buffer = [0_u8; 8];
        assert_eq!(exact.read(&mut buffer).unwrap(), 6);
        assert_eq!(exact.read(&mut buffer).unwrap(), 0);
        assert!(!budget.exceeded());
        let unlimited = ReadBudget::unlimited();
        let mut reader = unlimited.reader(&[0_u8; 4096][..]);
        let mut sink = Vec::new();
        assert_eq!(reader.read_to_end(&mut sink).unwrap(), 4096);
        assert_eq!(unlimited.limit(), u64::MAX);
    }
}
