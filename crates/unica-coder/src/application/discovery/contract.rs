use super::model::{ArtifactKind, ArtifactRef, DiscoverRequest, DiscoveryLimits};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

const ALLOWED_ARGUMENTS: &[&str] = &[
    "concepts",
    "cwd",
    "knownArtifacts",
    "limits",
    "mode",
    "searchTerms",
    "sourceSet",
    "task",
];
const MAX_TASK_BYTES: usize = 8192;
const MAX_CONCEPTS: usize = 64;
const MAX_TERM_BYTES: usize = 256;
const MAX_SEARCH_TERMS: usize = 128;
const MAX_KNOWN_ARTIFACTS: usize = 128;

pub(crate) fn parse_explore_request(args: &Map<String, Value>) -> Result<DiscoverRequest, String> {
    reject_unknown_arguments(args)?;
    require_mode_explore(args)?;

    Ok(DiscoverRequest {
        task: required_text(args, "task", MAX_TASK_BYTES)?,
        concepts: unique_text_list(args, "concepts", 1, MAX_CONCEPTS, MAX_TERM_BYTES)?,
        search_terms: optional_text_list(args, "searchTerms", MAX_SEARCH_TERMS, MAX_TERM_BYTES)?,
        known_artifacts: parse_known_artifacts(args)?,
        source_set: optional_text(args, "sourceSet", 1024)?,
        limits: parse_limits(args)?,
    })
}

fn reject_unknown_arguments(args: &Map<String, Value>) -> Result<(), String> {
    for key in args.keys() {
        if !ALLOWED_ARGUMENTS.contains(&key.as_str()) {
            return Err(format!(
                "unica.project.discover does not accept argument `{key}`"
            ));
        }
    }
    Ok(())
}

fn require_mode_explore(args: &Map<String, Value>) -> Result<(), String> {
    match args.get("mode").and_then(Value::as_str) {
        Some("explore") => Ok(()),
        Some(_) => Err("unica.project.discover currently supports only mode `explore`".to_string()),
        None => Err("unica.project.discover requires `mode` argument".to_string()),
    }
}

fn required_text(
    args: &Map<String, Value>,
    key: &str,
    maximum_bytes: usize,
) -> Result<String, String> {
    let value = args
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("unica.project.discover requires non-empty string `{key}`"))?;
    validate_text(value, key, maximum_bytes)?;
    Ok(value.to_string())
}

fn optional_text(
    args: &Map<String, Value>,
    key: &str,
    maximum_bytes: usize,
) -> Result<Option<String>, String> {
    args.get(key)
        .map(|value| {
            let value = value
                .as_str()
                .ok_or_else(|| format!("unica.project.discover argument `{key}` must be string"))?;
            validate_text(value, key, maximum_bytes)?;
            Ok(value.to_string())
        })
        .transpose()
}

fn unique_text_list(
    args: &Map<String, Value>,
    key: &str,
    minimum_items: usize,
    maximum_items: usize,
    maximum_bytes: usize,
) -> Result<Vec<String>, String> {
    let values = args
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("unica.project.discover requires array `{key}`"))?;
    parse_unique_text_values(values, key, minimum_items, maximum_items, maximum_bytes)
}

fn optional_text_list(
    args: &Map<String, Value>,
    key: &str,
    maximum_items: usize,
    maximum_bytes: usize,
) -> Result<Vec<String>, String> {
    match args.get(key) {
        Some(Value::Array(values)) => {
            parse_unique_text_values(values, key, 0, maximum_items, maximum_bytes)
        }
        Some(_) => Err(format!(
            "unica.project.discover argument `{key}` must be array"
        )),
        None => Ok(Vec::new()),
    }
}

fn parse_unique_text_values(
    values: &[Value],
    key: &str,
    minimum_items: usize,
    maximum_items: usize,
    maximum_bytes: usize,
) -> Result<Vec<String>, String> {
    if !(minimum_items..=maximum_items).contains(&values.len()) {
        return Err(format!("unica.project.discover argument `{key}` must contain {minimum_items}..={maximum_items} items"));
    }
    let mut unique = BTreeSet::new();
    for value in values {
        let value = value.as_str().ok_or_else(|| {
            format!("unica.project.discover argument `{key}` must contain strings")
        })?;
        validate_text(value, key, maximum_bytes)?;
        if !unique.insert(value.to_string()) {
            return Err(format!(
                "unica.project.discover argument `{key}` must not contain duplicates"
            ));
        }
    }
    Ok(unique.into_iter().collect())
}

fn parse_known_artifacts(args: &Map<String, Value>) -> Result<Vec<ArtifactRef>, String> {
    let Some(values) = args.get("knownArtifacts") else {
        return Ok(Vec::new());
    };
    let values = values.as_array().ok_or_else(|| {
        "unica.project.discover argument `knownArtifacts` must be array".to_string()
    })?;
    if values.len() > MAX_KNOWN_ARTIFACTS {
        return Err(format!("unica.project.discover argument `knownArtifacts` must contain at most {MAX_KNOWN_ARTIFACTS} items"));
    }
    values.iter().map(parse_artifact).collect()
}

fn parse_artifact(value: &Value) -> Result<ArtifactRef, String> {
    let object = value.as_object().ok_or_else(|| {
        "unica.project.discover knownArtifacts entries must be objects".to_string()
    })?;
    if object.len() != 2 || !object.contains_key("kind") || !object.contains_key("ref") {
        return Err(
            "unica.project.discover knownArtifacts entries require only `kind` and `ref`"
                .to_string(),
        );
    }
    let kind = match object.get("kind").and_then(Value::as_str) {
        Some("metadata_object") => ArtifactKind::MetadataObject,
        Some("module") => ArtifactKind::Module,
        Some("method") => ArtifactKind::Method,
        Some("form") => ArtifactKind::Form,
        Some("command") => ArtifactKind::Command,
        _ => {
            return Err("unica.project.discover knownArtifacts `kind` is not supported".to_string())
        }
    };
    let reference = object
        .get("ref")
        .and_then(Value::as_str)
        .ok_or_else(|| "unica.project.discover knownArtifacts `ref` must be string".to_string())?;
    validate_text(reference, "knownArtifacts.ref", 1024)?;
    Ok(ArtifactRef {
        kind,
        reference: reference.to_string(),
    })
}

fn parse_limits(args: &Map<String, Value>) -> Result<DiscoveryLimits, String> {
    let Some(value) = args.get("limits") else {
        return Ok(DiscoveryLimits::default());
    };
    let object = value
        .as_object()
        .ok_or_else(|| "unica.project.discover argument `limits` must be object".to_string())?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "maxCandidates" | "maxGraphDepth" | "maxEvidence"
        ) {
            return Err(format!(
                "unica.project.discover limits does not accept `{key}`"
            ));
        }
    }
    Ok(DiscoveryLimits {
        max_candidates: bounded_u16(object, "maxCandidates", 20, 1, 100)?,
        max_graph_depth: bounded_u8(object, "maxGraphDepth", 4, 1, 12)?,
        max_evidence: bounded_u16(object, "maxEvidence", 200, 1, 2000)?,
    })
}

fn bounded_u16(
    object: &Map<String, Value>,
    key: &str,
    default: u16,
    minimum: u16,
    maximum: u16,
) -> Result<u16, String> {
    let Some(value) = object.get(key) else {
        return Ok(default);
    };
    let value = value
        .as_u64()
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| format!("unica.project.discover limits `{key}` must be integer"))?;
    if !(minimum..=maximum).contains(&value) {
        return Err(format!(
            "unica.project.discover limits `{key}` must be {minimum}..={maximum}"
        ));
    }
    Ok(value)
}

fn bounded_u8(
    object: &Map<String, Value>,
    key: &str,
    default: u8,
    minimum: u8,
    maximum: u8,
) -> Result<u8, String> {
    let Some(value) = object.get(key) else {
        return Ok(default);
    };
    let value = value
        .as_u64()
        .and_then(|value| u8::try_from(value).ok())
        .ok_or_else(|| format!("unica.project.discover limits `{key}` must be integer"))?;
    if !(minimum..=maximum).contains(&value) {
        return Err(format!(
            "unica.project.discover limits `{key}` must be {minimum}..={maximum}"
        ));
    }
    Ok(value)
}

fn validate_text(value: &str, key: &str, maximum_bytes: usize) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > maximum_bytes {
        return Err(format!("unica.project.discover argument `{key}` must be non-empty and at most {maximum_bytes} UTF-8 bytes"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_explore_request;
    use crate::application::tool_contracts::input_schema_for_tool;
    use crate::application::{ToolHandler, ToolSpec};
    use crate::domain::cache::CacheAccess;
    use serde_json::{json, Map, Value};

    fn args(value: Value) -> Map<String, Value> {
        value
            .as_object()
            .cloned()
            .expect("test input must be object")
    }

    #[test]
    fn parses_strict_explore_request() {
        let request = parse_explore_request(&args(json!({
            "mode": "explore",
            "task": "Проверить обработчик",
            "concepts": ["обработчик", "форма"],
            "searchTerms": ["ПриЗаписи"],
            "knownArtifacts": [{"kind": "method", "ref": "Document.Тест.ObjectModule.ПриЗаписи"}],
            "limits": {"maxCandidates": 10, "maxGraphDepth": 3, "maxEvidence": 50}
        })))
        .expect("valid request");

        assert_eq!(request.concepts, ["обработчик", "форма"]);
        assert_eq!(request.limits.max_evidence, 50);
        assert_eq!(request.known_artifacts.len(), 1);
    }

    #[test]
    fn rejects_receipts_proposals_and_unknown_fields() {
        for forbidden in ["proposals", "discoveryReceipt", "rawArgs"] {
            let mut request = args(json!({
                "mode": "explore", "task": "x", "concepts": ["x"]
            }));
            request.insert(forbidden.to_string(), Value::Null);
            assert!(parse_explore_request(&request).is_err(), "{forbidden}");
        }
    }

    #[test]
    fn rejects_empty_or_duplicate_concepts_and_non_explore_mode() {
        for request in [
            json!({"mode": "explore", "task": "x", "concepts": []}),
            json!({"mode": "explore", "task": "x", "concepts": ["x", "x"]}),
            json!({"mode": "validate", "task": "x", "concepts": ["x"]}),
        ] {
            assert!(parse_explore_request(&args(request)).is_err());
        }
    }

    #[test]
    fn schema_is_strict_and_does_not_offer_receipt_or_mutation_arguments() {
        let schema = input_schema_for_tool(&ToolSpec {
            name: "unica.project.discover",
            description: "test",
            mutating: false,
            cache_access: CacheAccess::default(),
            handler: ToolHandler::ProjectDiscover,
        });

        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"]["mode"]["enum"], json!(["explore"]));
        assert!(schema["properties"].get("discoveryReceipt").is_none());
        assert!(schema["properties"].get("dryRun").is_none());
    }
}
