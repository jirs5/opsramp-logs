use crate::{enrichment, Expression};
use std::iter::IntoIterator;
use std::ops::Deref;

#[derive(Debug, Clone)]
pub struct Program {
    pub(crate) expressions: Vec<Box<dyn Expression>>,
    pub(crate) fallible: bool,
    pub(crate) abortable: bool,
    pub(crate) enrichment_tables: Option<Box<dyn enrichment::TableSearch + Send + Sync>>,
}

impl Program {
    /// Returns whether the compiled program can fail at runtime.
    ///
    /// A program can only fail at runtime if the fallible-function-call
    /// (`foo!()`) is used within the source.
    pub fn can_fail(&self) -> bool {
        self.fallible
    }

    /// Returns whether the compiled program can be aborted at runtime.
    ///
    /// A program can only abort at runtime if there's an explicit `abort`
    /// statement in the source.
    pub fn can_abort(&self) -> bool {
        self.abortable
    }

    pub fn enrichment_tables(&self) -> Option<&(dyn enrichment::TableSearch + Send + Sync)> {
        self.enrichment_tables
            .as_ref()
            .map(|tables| tables.as_ref())
    }
}

impl IntoIterator for Program {
    type Item = Box<dyn Expression>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.expressions.into_iter()
    }
}

impl Deref for Program {
    type Target = [Box<dyn Expression>];

    fn deref(&self) -> &Self::Target {
        &self.expressions
    }
}
