//! YAML/JSON (Kubernetes) → normalized resource tree (spec 7.3). Multi-document
//! YAML is supported (K8s manifests routinely bundle several objects).

use std::collections::BTreeMap;

use crate::resource::{Resource, Value};

/// Parse a YAML (possibly multi-document) or JSON file into resources. Objects
/// without both `kind` and `apiVersion` are skipped (not K8s resources).
pub fn parse(text: &str, source_path: &str) -> Result<Vec<Resource>, String> {
    let mut resources = Vec::new();
    for document in serde_yaml_ng::Deserializer::from_str(text) {
        let value = serde_yaml_ng::Value::deserialize(document)
            .map_err(|e| format!("{source_path}: {e}"))?;
        if let Some(resource) = resource_from_yaml(&value, source_path) {
            resources.push(resource);
        }
    }
    Ok(resources)
}

use serde::Deserialize;

fn resource_from_yaml(value: &serde_yaml_ng::Value, source_path: &str) -> Option<Resource> {
    let map = value.as_mapping()?;
    let kind = map.get("kind")?.as_str()?.to_string();
    // Require apiVersion so we don't treat arbitrary YAML as a K8s object.
    map.get("apiVersion")?;
    let name = map
        .get("metadata")
        .and_then(|m| m.as_mapping())
        .and_then(|m| m.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("unnamed")
        .to_string();

    let attributes = match convert(value) {
        Value::Map(m) => m,
        _ => BTreeMap::new(),
    };
    Some(Resource {
        address: format!("{kind}.{name}"),
        kind,
        name,
        attributes,
        source_path: source_path.to_string(),
    })
}

fn convert(value: &serde_yaml_ng::Value) -> Value {
    match value {
        serde_yaml_ng::Value::Null => Value::Null,
        serde_yaml_ng::Value::Bool(b) => Value::Bool(*b),
        serde_yaml_ng::Value::Number(n) => Value::Number(n.to_string()),
        serde_yaml_ng::Value::String(s) => Value::String(s.clone()),
        serde_yaml_ng::Value::Sequence(items) => Value::List(items.iter().map(convert).collect()),
        serde_yaml_ng::Value::Mapping(map) => {
            let mut out = BTreeMap::new();
            for (k, v) in map {
                if let Some(key) = k.as_str() {
                    out.insert(key.to_string(), convert(v));
                }
            }
            Value::Map(out)
        }
        // Tagged values are uncommon in K8s manifests; treat as unresolved.
        _ => Value::Unresolved,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_privileged_pod() {
        let yaml = r#"
apiVersion: v1
kind: Pod
metadata:
  name: web
spec:
  securityContext:
    privileged: true
"#;
        let resources = parse(yaml, "pod.yaml").unwrap();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].kind, "Pod");
        assert_eq!(
            resources[0]
                .get("spec.securityContext.privileged")
                .and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn multi_document_yaml() {
        let yaml = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: a\n---\napiVersion: v1\nkind: Service\nmetadata:\n  name: b\n";
        let resources = parse(yaml, "k.yaml").unwrap();
        assert_eq!(resources.len(), 2);
    }

    #[test]
    fn non_k8s_yaml_skipped() {
        let resources = parse("just: data\nno: kind\n", "x.yaml").unwrap();
        assert!(resources.is_empty());
    }
}
