//! HCL2 → normalized resource tree (spec 7.3). Only `resource` blocks are
//! extracted for v1; interpolations and unknown expressions become
//! `Value::Unresolved` so policies degrade to Heuristic (IAC-003).

use std::collections::BTreeMap;

use hcl::{Block, Body, Expression, Structure};

use crate::resource::{Resource, Value};

/// Parse Terraform HCL into resources. A parse error yields `Err(reason)` so
/// the engine can degrade to `Partial` (spec 7.1 discipline).
pub fn parse(text: &str, source_path: &str) -> Result<Vec<Resource>, String> {
    let body: Body = hcl::from_str(text).map_err(|e| format!("{source_path}: {e}"))?;
    let mut resources = Vec::new();
    for structure in body.into_iter() {
        if let Structure::Block(block) = structure {
            if block.identifier.as_str() == "resource" {
                if let Some(resource) = resource_from_block(&block, source_path) {
                    resources.push(resource);
                }
            }
        }
    }
    Ok(resources)
}

fn resource_from_block(block: &Block, source_path: &str) -> Option<Resource> {
    // `resource "type" "name" { ... }` — two string labels.
    let labels: Vec<String> = block
        .labels
        .iter()
        .map(|l| l.as_str().to_string())
        .collect();
    let (kind, name) = match labels.as_slice() {
        [kind, name] => (kind.clone(), name.clone()),
        _ => return None,
    };
    let attributes = body_to_map(&block.body);
    Some(Resource {
        address: format!("{kind}.{name}"),
        kind,
        name,
        attributes,
        source_path: source_path.to_string(),
    })
}

/// Fold an HCL body into a normalized map. Repeated nested blocks with the
/// same identifier (e.g. multiple `ingress` blocks) collapse into a list.
fn body_to_map(body: &Body) -> BTreeMap<String, Value> {
    let mut map: BTreeMap<String, Value> = BTreeMap::new();
    for structure in body.iter() {
        match structure {
            Structure::Attribute(attr) => {
                map.insert(attr.key.as_str().to_string(), expr_to_value(&attr.expr));
            }
            Structure::Block(block) => {
                let key = block.identifier.as_str().to_string();
                let nested = Value::Map(body_to_map(&block.body));
                match map.get_mut(&key) {
                    Some(Value::List(items)) => items.push(nested),
                    Some(existing) => {
                        let prev = std::mem::replace(existing, Value::Null);
                        *existing = Value::List(vec![prev, nested]);
                    }
                    None => {
                        map.insert(key, nested);
                    }
                }
            }
        }
    }
    map
}

fn expr_to_value(expr: &Expression) -> Value {
    match expr {
        Expression::Null => Value::Null,
        Expression::Bool(b) => Value::Bool(*b),
        Expression::Number(n) => Value::Number(n.to_string()),
        Expression::String(s) => Value::String(s.clone()),
        Expression::Array(items) => Value::List(items.iter().map(expr_to_value).collect()),
        Expression::Object(obj) => {
            let mut map = BTreeMap::new();
            for (k, v) in obj.iter() {
                let key = match k {
                    hcl::ObjectKey::Identifier(id) => id.as_str().to_string(),
                    other => other.to_string(),
                };
                map.insert(key, expr_to_value(v));
            }
            Value::Map(map)
        }
        // Traversals (var.*, aws_*.*), function calls, template strings, and
        // any other expression can't be resolved statically (IAC-003).
        _ => Value::Unresolved,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_s3_resource_with_acl() {
        let hcl = r#"
resource "aws_s3_bucket" "data" {
  bucket = "my-data"
  acl    = "public-read"
}
"#;
        let resources = parse(hcl, "main.tf").unwrap();
        assert_eq!(resources.len(), 1);
        let r = &resources[0];
        assert_eq!(r.kind, "aws_s3_bucket");
        assert_eq!(r.address, "aws_s3_bucket.data");
        assert_eq!(r.get("acl").and_then(|v| v.as_str()), Some("public-read"));
    }

    #[test]
    fn interpolation_is_unresolved() {
        let hcl = r#"
resource "aws_s3_bucket" "data" {
  acl = var.bucket_acl
}
"#;
        let resources = parse(hcl, "main.tf").unwrap();
        assert!(resources[0].get("acl").unwrap().has_unresolved());
    }

    #[test]
    fn repeated_blocks_collapse_to_list() {
        let hcl = r#"
resource "aws_security_group" "web" {
  ingress { cidr_blocks = ["0.0.0.0/0"] }
  ingress { cidr_blocks = ["10.0.0.0/8"] }
}
"#;
        let resources = parse(hcl, "main.tf").unwrap();
        match resources[0].get("ingress") {
            Some(Value::List(items)) => assert_eq!(items.len(), 2),
            other => panic!("expected list, got {other:?}"),
        }
    }
}
