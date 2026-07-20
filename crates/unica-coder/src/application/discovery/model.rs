#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DiscoverRequest {
    pub(crate) task: String,
    pub(crate) concepts: Vec<String>,
    pub(crate) search_terms: Vec<String>,
    pub(crate) known_artifacts: Vec<ArtifactRef>,
    pub(crate) source_set: Option<String>,
    pub(crate) limits: DiscoveryLimits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArtifactRef {
    pub(crate) kind: ArtifactKind,
    pub(crate) reference: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArtifactKind {
    MetadataObject,
    Module,
    Method,
    Form,
    Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DiscoveryLimits {
    pub(crate) max_candidates: u16,
    pub(crate) max_graph_depth: u8,
    pub(crate) max_evidence: u16,
}

impl Default for DiscoveryLimits {
    fn default() -> Self {
        Self {
            max_candidates: 20,
            max_graph_depth: 4,
            max_evidence: 200,
        }
    }
}
