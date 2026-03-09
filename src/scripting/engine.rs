use anyhow::Result;
use rhai::{Engine, Map, Dynamic, Scope};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScriptResult {
    pub script_name: String,
    pub output: Vec<String>,
    pub data: HashMap<String, Value>,
    pub category: String,
}

#[derive(Debug, Clone)]
pub struct ScriptContext {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub service_name: String,
    pub banner: String,
    pub version: Option<String>,
    pub is_tls: bool,
}

pub struct ScriptEngine {
    engine: Engine,
}

impl ScriptEngine {
    pub fn new() -> Self {
        let mut engine = Engine::new();
        engine.set_max_operations(100_000);
        engine.set_max_string_size(65536);
        engine.set_max_array_size(1000);
        engine.set_max_map_size(500);

        engine.register_fn("contains", |s: &str, pat: &str| -> bool {
            s.contains(pat)
        });
        engine.register_fn("starts_with", |s: &str, pat: &str| -> bool {
            s.starts_with(pat)
        });
        engine.register_fn("ends_with", |s: &str, pat: &str| -> bool {
            s.ends_with(pat)
        });
        engine.register_fn("to_lowercase", |s: &str| -> String {
            s.to_lowercase()
        });
        engine.register_fn("trim", |s: &str| -> String {
            s.trim().to_string()
        });
        engine.register_fn("split_first_line", |s: &str| -> String {
            s.lines().next().unwrap_or("").to_string()
        });

        Self { engine }
    }

    pub fn run_script_file(&self, path: &Path, ctx: &ScriptContext) -> Result<ScriptResult> {
        let source = std::fs::read_to_string(path)?;
        let name = path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        self.run_script_source(&source, &name, ctx)
    }

    pub fn run_script_source(&self, source: &str, name: &str, ctx: &ScriptContext) -> Result<ScriptResult> {
        let mut scope = Scope::new();

        scope.push("ip", ctx.ip.clone());
        scope.push("port", ctx.port as i64);
        scope.push("protocol", ctx.protocol.clone());
        scope.push("service", ctx.service_name.clone());
        scope.push("banner", ctx.banner.clone());
        scope.push("version", ctx.version.clone().unwrap_or_default());
        scope.push("is_tls", ctx.is_tls);
        scope.push_dynamic("output", Dynamic::from(rhai::Array::new()));
        scope.push_dynamic("data", Dynamic::from(Map::new()));

        self.engine.run_with_scope(&mut scope, source)
            .map_err(|e| anyhow::anyhow!("Script '{}' error: {}", name, e))?;

        let output: Vec<String> = scope.get_value::<rhai::Array>("output")
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| v.try_cast::<String>())
            .collect();

        let data_map: HashMap<String, Value> = scope.get_value::<Map>("data")
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| {
                let json_val = dynamic_to_json(v);
                (k.to_string(), json_val)
            })
            .collect();

        let category = source.lines()
            .find(|l| l.starts_with("// @category"))
            .and_then(|l| l.split_once(' ').map(|(_, v)| v.trim().to_string()))
            .unwrap_or_else(|| "discovery".to_string());

        Ok(ScriptResult {
            script_name: name.to_string(),
            output,
            data: data_map,
            category,
        })
    }

    pub fn run_builtin(&self, script_name: &str, ctx: &ScriptContext) -> Result<ScriptResult> {
        let source = crate::scripting::builtins::get_builtin(script_name)
            .ok_or_else(|| anyhow::anyhow!("Unknown builtin script: {}", script_name))?;
        self.run_script_source(source, script_name, ctx)
    }

    pub fn list_builtins() -> Vec<&'static str> {
        crate::scripting::builtins::BUILTIN_NAMES
    }
}

impl Default for ScriptEngine {
    fn default() -> Self {
        Self::new()
    }
}

fn dynamic_to_json(d: Dynamic) -> Value {
    if let Some(s) = d.clone().try_cast::<String>() {
        Value::String(s)
    } else if let Some(i) = d.clone().try_cast::<i64>() {
        Value::Number(i.into())
    } else if let Some(b) = d.clone().try_cast::<bool>() {
        Value::Bool(b)
    } else if let Some(arr) = d.clone().try_cast::<rhai::Array>() {
        Value::Array(arr.into_iter().map(dynamic_to_json).collect())
    } else {
        Value::Null
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ctx(service: &str, banner: &str, port: u16) -> ScriptContext {
        ScriptContext {
            ip: "127.0.0.1".to_string(),
            port,
            protocol: "tcp".to_string(),
            service_name: service.to_string(),
            banner: banner.to_string(),
            version: None,
            is_tls: false,
        }
    }

    #[test]
    fn test_engine_basic_script() {
        let engine = ScriptEngine::new();
        let ctx = test_ctx("http", "HTTP/1.1 200 OK\r\nServer: nginx/1.18\r\n", 80);
        let result = engine.run_script_source(
            r#"output += "hello from script";"#,
            "test",
            &ctx,
        ).unwrap();
        assert_eq!(result.output, vec!["hello from script"]);
    }

    #[test]
    fn test_engine_accesses_banner() {
        let engine = ScriptEngine::new();
        let ctx = test_ctx("http", "Server: Apache", 80);
        let result = engine.run_script_source(
            r#"
            if contains(banner, "Apache") {
                output += "Apache detected";
            }
            "#,
            "test",
            &ctx,
        ).unwrap();
        assert!(result.output.contains(&"Apache detected".to_string()));
    }

    #[test]
    fn test_engine_data_map() {
        let engine = ScriptEngine::new();
        let ctx = test_ctx("ssh", "SSH-2.0-OpenSSH_8.9", 22);
        let result = engine.run_script_source(
            r#"
            data["server"] = "OpenSSH";
            data["version"] = "8.9";
            "#,
            "test",
            &ctx,
        ).unwrap();
        assert_eq!(result.data.get("server"), Some(&Value::String("OpenSSH".to_string())));
    }

    #[test]
    fn test_engine_max_ops_enforced() {
        let engine = ScriptEngine::new();
        let ctx = test_ctx("http", "", 80);
        let result = engine.run_script_source(
            r#"let i = 0; loop { i += 1; }"#,
            "infinite",
            &ctx,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_list_builtins_not_empty() {
        let names = ScriptEngine::list_builtins();
        assert!(!names.is_empty());
        assert!(names.contains(&"http-title"));
        assert!(names.contains(&"ssh-hostkey"));
        assert!(names.contains(&"banner"));
    }
}
