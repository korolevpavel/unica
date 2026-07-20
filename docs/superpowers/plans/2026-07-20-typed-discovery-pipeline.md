# Typed Discovery Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver `unica.project.discover` as a deterministic, evidence-backed read-only MCP use case.

**Architecture:** The first PR contains only the typed public `explore` contract, immutable-source evidence providers, graph, and report. Receipt issuance, stale-mutation rejection, storage leases, and enforcement are separate PRs because their design is not complete. PR #117 is research only; its code is not copied.

**Tech Stack:** Rust, serde, SHA-256, bounded contained filesystem reads, MCP JSON schemas, Python CI.

---

## Delivery boundaries

1. PR A: read-only discovery (`explore`), no receipt and no mutation integration.
2. PR B: proposal validation and durable receipts after the receipt/lease design is accepted.
3. PR C: one exact mutation resolver and guard rollout.

### Task 1: Freeze the first delivery contract

**Files:**
- Create: `spec/architecture/extension-point-discovery.md`
- Create: `spec/decisions/0010-project-discovery-and-discovery-receipts.md`
- Modify: `tests/ci/test_product_contracts.py`

- [ ] Write a failing test that requires the architecture to declare `unica.project.discover`, `mode=explore`, typed evidence provenance, and the explicit PR-A non-goals: receipts, mutation guards, display-text parsing, and domain-specific synonyms.
- [ ] Run `python3.12 -m unittest tests.ci.test_product_contracts -v`; expect failure because the active design is absent from `main`.
- [ ] Add architecture and ADR text: five provider outcomes (`complete`, `bounded`, `unavailable`, `failed`, `contract_violation`); structural facts never prove a runtime flow; all source reads are bounded and contained.
- [ ] Re-run the focused test; expect pass.
- [ ] Commit: `git commit -m "Зафиксировать первый срез typed discovery"`.

### Task 2: Add strict MCP and application model

**Files:**
- Create: `crates/unica-coder/src/application/discovery/{mod,model,contract}.rs`
- Modify: `crates/unica-coder/src/application/tool_contracts.rs`
- Test: `crates/unica-coder/src/application/discovery/contract.rs`

- [ ] Write failing tests for this accepted request and rejection of `proposals`, `discoveryReceipt`, and all unknown fields:

```rust
assert!(parse_discover_request(json!({
    "mode": "explore", "task": "Проверить обработчик", "concepts": ["обработчик"]
})).is_ok());
```

- [ ] Run `cargo test --package unica-coder discovery::contract --lib`; expect failure.
- [ ] Implement `DiscoverRequest`, `DiscoveryMode::Explore`, `DiscoveryLimits`, `ArtifactRef`, `DiscoveryReport`, and `OperationData::Discovery`; use strict serde objects, bounded strings, and no score/confidence scalar.
- [ ] Add read-only schema for `unica.project.discover`. It accepts only `cwd`, `mode`, `task`, `concepts`, `searchTerms`, `knownArtifacts`, `sourceSet`, and `limits`.
- [ ] Run `cargo test --package unica-coder discovery::contract --lib && cargo test --package unica-coder tool_contracts::tests --lib`; expect pass.
- [ ] Commit: `git commit -m "Добавить typed контракт project discovery"`.

### Task 3: Add evidence ports and graph

**Files:**
- Create: `crates/unica-coder/src/application/discovery/{ports,evidence_graph}.rs`
- Modify: `crates/unica-coder/src/application/ports.rs`
- Test: `crates/unica-coder/src/application/discovery/evidence_graph.rs`

- [ ] Write failing tests proving that `contains` and `defines` stay structural, while only compatible typed Platform XML/form bindings create runtime-flow edges.
- [ ] Run `cargo test --package unica-coder discovery::evidence_graph --lib`; expect failure.
- [ ] Implement `ProviderOutcome<T>`, `ProviderBatch<T>`, `EvidenceLocation`, `EvidenceProvenance`, `RelatedArtifact`, `RuntimeFlowEvidence`, and `ActionableExtensionPoint`. Every record carries canonical identity, source location, provider/version, coverage, and snapshot fingerprint.
- [ ] Reject incompatible binding/flow/provider combinations before graph promotion; no adapter parses another adapter's text.
- [ ] Re-run the focused test; expect pass.
- [ ] Commit: `git commit -m "Добавить evidence graph discovery"`.

### Task 4: Capture immutable source snapshots

**Files:**
- Create: `crates/unica-coder/src/domain/source_snapshot.rs`
- Create: `crates/unica-coder/src/infrastructure/{contained_fs,source_snapshot}.rs`
- Modify: `crates/unica-coder/src/infrastructure/mod.rs`
- Test: `crates/unica-coder/src/infrastructure/source_snapshot.rs`

- [ ] Write failing tests for sorted deterministic manifests, raw-byte (BOM/EOL) SHA-256 changes, escaping symlink rejection, and TOCTOU re-read detection.
- [ ] Run `cargo test --package unica-coder source_snapshot --lib`; expect failure.
- [ ] Implement contained canonical paths, fixed file/byte bounds, raw hashes, and verified re-read identity. Exclude platform `ConfigDumpInfo.xml`; never rely on workspace-service display output.
- [ ] Re-run the focused test; expect pass.
- [ ] Commit: `git commit -m "Добавить снимок исходников для discovery"`.

### Task 5: Implement snapshot-backed explore

**Files:**
- Create: `crates/unica-coder/src/application/discovery/use_case.rs`
- Create: `crates/unica-coder/src/infrastructure/{platform_xml,discovery}.rs`
- Modify: `crates/unica-coder/src/application/{mod,ports}.rs`
- Test: `crates/unica-coder/src/application/discovery/use_case.rs`

- [ ] Write a UT 11.5 fixture test: report `Document.ПриобретениеТоваровУслуг.TabularSection.Серии`, `DataProcessor.ПодборСерийВДокументы`, and a registered form binding; a query only for `Товары.Серия` must emit an insufficient-evidence warning.
- [ ] Run `cargo test --package unica-coder discovery::use_case --lib`; expect failure.
- [ ] Implement Platform XML/form providers and snapshot-only lexical BSL definition/search. Dynamic or ambiguous calls return bounded/unknown, never a guessed resolved flow.
- [ ] Wire `DiscoverExtensionPointsUseCase` as read-only dispatch. Serialize deterministic related artifacts, flow edges, candidates, checks, provider outcomes, and analysis snapshot under `data.discovery`; never invoke a handler or emit a receipt.
- [ ] Re-run `cargo test --package unica-coder discovery::use_case --lib`; expect pass.
- [ ] Commit: `git commit -m "Реализовать read-only project discovery"`.

### Task 6: Package and verify PR A

**Files:**
- Modify: `plugins/unica/skills/code-search/SKILL.md`
- Modify: `plugins/unica/references/use-cases/workspace-runtime.md`
- Modify: `tests/ci/{test_unica_mcp_smoke,test_product_contracts}.py`

- [ ] Add failing package tests for one public `unica.project.discover` tool and guidance that discovery is read-only and not mutation approval.
- [ ] Update public guidance and package metadata tests; keep one public MCP server and `unica.*` names.
- [ ] Run:

```sh
cargo fmt --all -- --check
cargo clippy --package unica-coder --all-targets --all-features -- -D warnings
cargo test --package unica-coder
python3.12 -m unittest discover -s tests/ci
python3.12 -m py_compile scripts/ci/*.py tests/ci/*.py
git diff --check
```

- [ ] Review new Rust APIs for exhaustive enums, `Result` propagation, borrowed arguments, no panics, and no boolean policy parameters.
- [ ] Commit: `git commit -m "Описать read-only project discovery"`.

## Plan self-review

- PR A covers the actionable product start without promising receipt or mutation safety that has no accepted implementation contract.
- Each task names files, a failing-test gate, implementation boundary, verification, and commit.
- `DiscoverRequest` feeds `DiscoverExtensionPointsUseCase`; all providers return `ProviderOutcome<T>`; only `DiscoveryReport` is serialized as `data.discovery`.
