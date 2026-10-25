//! Zero-config project stack detection.
//!
//! Detection is advisory: `envy init` uses it to print a short summary and a
//! run hint. It never mutates the project and never executes a detected tool.

use std::fs;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

/// A detected language/runtime stack.
#[derive(Clone, Debug, Serialize)]
pub struct StackInfo {
    pub language: String,
    pub framework: Option<String>,
    pub package_manager: Option<String>,
    pub evidence: Vec<String>,
    pub run_hint: Option<String>,
}

impl StackInfo {
    fn new(language: &str) -> Self {
        Self {
            language: language.to_owned(),
            framework: None,
            package_manager: None,
            evidence: Vec::new(),
            run_hint: None,
        }
    }

    /// One-line human summary, e.g. `Node.js (Next.js, pnpm)`.
    pub fn summary(&self) -> String {
        let mut summary = self.language.clone();
        let mut details = Vec::new();
        if let Some(framework) = &self.framework {
            details.push(framework.clone());
        }
        if let Some(manager) = &self.package_manager {
            details.push(manager.clone());
        }
        if !details.is_empty() {
            summary.push_str(" (");
            summary.push_str(&details.join(", "));
            summary.push(')');
        }
        summary
    }
}

/// Detect every recognizable stack in `directory`, primary first.
pub fn detect(directory: &Path) -> Vec<StackInfo> {
    let mut stacks = Vec::new();

    if let Some(stack) = detect_node(directory) {
        stacks.push(stack);
    }
    if let Some(stack) = detect_rust(directory) {
        stacks.push(stack);
    }
    if let Some(stack) = detect_python(directory) {
        stacks.push(stack);
    }
    if let Some(stack) = detect_go(directory) {
        stacks.push(stack);
    }
    if let Some(stack) = detect_deno(directory) {
        stacks.push(stack);
    }
    if let Some(stack) = detect_ruby(directory) {
        stacks.push(stack);
    }
    if directory.join("Dockerfile").is_file()
        || directory.join("docker-compose.yml").is_file()
        || directory.join("compose.yaml").is_file()
    {
        let mut docker = StackInfo::new("Docker");
        docker.evidence.push("Dockerfile or compose file".to_owned());
        docker.run_hint = Some("docker compose up".to_owned());
        stacks.push(docker);
    }

    stacks
}

fn exists(directory: &Path, name: &str) -> bool {
    directory.join(name).is_file()
}

fn read_limited(path: &Path, limit: usize) -> Option<String> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return None;
    }
    fs::read_to_string(path).ok()
}

fn detect_node(directory: &Path) -> Option<StackInfo> {
    let package_json = directory.join("package.json");
    let lockfiles = [
        ("bun.lock", "bun"),
        ("bun.lockb", "bun"),
        ("pnpm-lock.yaml", "pnpm"),
        ("yarn.lock", "yarn"),
        ("package-lock.json", "npm"),
    ];
    let manager = lockfiles
        .iter()
        .find(|(name, _)| exists(directory, name))
        .map(|(_, manager)| (*manager).to_owned());

    if !package_json.is_file() && manager.is_none() {
        return None;
    }

    let mut stack = StackInfo::new("Node.js");
    stack.package_manager = manager.or_else(|| Some("npm".to_owned()));
    stack.evidence.push("package.json".to_owned());

    if let Some(contents) = read_limited(&package_json, 512 * 1024) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&contents) {
            let dependency_names: Vec<String> = ["dependencies", "devDependencies"]
                .iter()
                .filter_map(|section| json.get(*section).and_then(|value| value.as_object()))
                .flat_map(|object| object.keys().cloned())
                .collect();
            let has = |name: &str| dependency_names.iter().any(|candidate| candidate == name);
            stack.framework = if has("next") {
                Some("Next.js".to_owned())
            } else if has("astro") {
                Some("Astro".to_owned())
            } else if has("nuxt") || has("nuxt3") {
                Some("Nuxt".to_owned())
            } else if has("@remix-run/react") {
                Some("Remix".to_owned())
            } else if has("@sveltejs/kit") {
                Some("SvelteKit".to_owned())
            } else if has("svelte") {
                Some("Svelte".to_owned())
            } else if has("@nestjs/core") {
                Some("NestJS".to_owned())
            } else if has("express") {
                Some("Express".to_owned())
            } else if has("vite") {
                Some("Vite".to_owned())
            } else if has("react") {
                Some("React".to_owned())
            } else if has("vue") {
                Some("Vue".to_owned())
            } else {
                None
            };

            let script = json
                .get("scripts")
                .and_then(|scripts| scripts.get("dev"))
                .and_then(|value| value.as_str());
            let manager = stack.package_manager.as_deref().unwrap_or("npm");
            let runner = match manager {
                "bun" => "bun run",
                "pnpm" => "pnpm",
                "yarn" => "yarn",
                _ => "npm run",
            };
            stack.run_hint = Some(if script.is_some() {
                format!("envy run -- {runner} dev")
            } else {
                format!("envy run -- {runner} start")
            });
        }
    }

    if stack.run_hint.is_none() {
        stack.run_hint = Some("envy run -- npm start".to_owned());
    }
    Some(stack)
}

fn detect_rust(directory: &Path) -> Option<StackInfo> {
    if !exists(directory, "Cargo.toml") {
        return None;
    }
    let mut stack = StackInfo::new("Rust");
    stack.package_manager = Some("cargo".to_owned());
    stack.evidence.push("Cargo.toml".to_owned());
    let mut run_hint = "envy run -- cargo run".to_owned();
    if let Some(contents) = read_limited(&directory.join("Cargo.toml"), 512 * 1024) {
        let has = |needle: &str| contents.contains(needle);
        stack.framework = if has("axum") {
            Some("Axum".to_owned())
        } else if has("actix-web") {
            Some("Actix Web".to_owned())
        } else if has("rocket") {
            Some("Rocket".to_owned())
        } else if has("clap") {
            Some("CLI".to_owned())
        } else {
            None
        };
        if contents.contains("[[bin]]") {
            run_hint = "envy run -- cargo run --release".to_owned();
        }
    }
    stack.run_hint = Some(run_hint);
    Some(stack)
}

fn detect_python(directory: &Path) -> Option<StackInfo> {
    static FRAMEWORK: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
        [
            (r"(?i)\b(django|djangorestframework)\b", "Django"),
            (r"(?i)\bfastapi\b", "FastAPI"),
            (r"(?i)\bflask\b", "Flask"),
            (r"(?i)\bstarlette\b", "Starlette"),
            (r"(?i)\bcelery\b", "Celery"),
        ]
        .iter()
        .filter_map(|(pattern, name)| Regex::new(pattern).ok().map(|regex| (regex, *name)))
        .collect()
    });

    let candidates = [
        "pyproject.toml",
        "requirements.txt",
        "Pipfile",
        "setup.py",
        "poetry.lock",
        "uv.lock",
    ];
    let present: Vec<&str> = candidates
        .iter()
        .copied()
        .filter(|name| exists(directory, name))
        .collect();
    if present.is_empty() {
        return None;
    }

    let mut stack = StackInfo::new("Python");
    stack.evidence.extend(present.iter().map(|name| (*name).to_owned()));
    stack.package_manager = if exists(directory, "uv.lock") {
        Some("uv".to_owned())
    } else if exists(directory, "poetry.lock") {
        Some("poetry".to_owned())
    } else if exists(directory, "Pipfile") {
        Some("pipenv".to_owned())
    } else {
        Some("pip".to_owned())
    };

    let mut combined = String::new();
    for name in ["pyproject.toml", "requirements.txt", "Pipfile", "setup.py"] {
        if let Some(contents) = read_limited(&directory.join(name), 512 * 1024) {
            combined.push_str(&contents);
            combined.push('\n');
            if combined.len() > 1024 * 1024 {
                break;
            }
        }
    }
    stack.framework = FRAMEWORK
        .iter()
        .find(|(regex, _)| regex.is_match(&combined))
        .map(|(_, name)| (*name).to_owned());

    stack.run_hint = Some(match stack.framework.as_deref() {
        Some("Django") => "envy run -- python manage.py runserver".to_owned(),
        Some("FastAPI") => "envy run -- uvicorn app.main:app --reload".to_owned(),
        Some("Flask") => "envy run -- flask --app app run --debug".to_owned(),
        _ => "envy run -- python main.py".to_owned(),
    });
    Some(stack)
}

fn detect_go(directory: &Path) -> Option<StackInfo> {
    if !exists(directory, "go.mod") {
        return None;
    }
    let mut stack = StackInfo::new("Go");
    stack.package_manager = Some("go".to_owned());
    stack.evidence.push("go.mod".to_owned());
    if let Some(contents) = read_limited(&directory.join("go.mod"), 256 * 1024) {
        stack.framework = if contents.contains("github.com/gin-gonic/gin") {
            Some("Gin".to_owned())
        } else if contents.contains("github.com/labstack/echo") {
            Some("Echo".to_owned())
        } else if contents.contains("github.com/gofiber/fiber") {
            Some("Fiber".to_owned())
        } else {
            None
        };
    }
    stack.run_hint = Some("envy run -- go run .".to_owned());
    Some(stack)
}

fn detect_deno(directory: &Path) -> Option<StackInfo> {
    if !exists(directory, "deno.json") && !exists(directory, "deno.jsonc") {
        return None;
    }
    let mut stack = StackInfo::new("Deno");
    stack.package_manager = Some("deno".to_owned());
    stack.evidence.push("deno.json".to_owned());
    stack.run_hint = Some("envy run -- deno task dev".to_owned());
    Some(stack)
}

fn detect_ruby(directory: &Path) -> Option<StackInfo> {
    if !exists(directory, "Gemfile") {
        return None;
    }
    let mut stack = StackInfo::new("Ruby");
    stack.package_manager = Some("bundler".to_owned());
    stack.evidence.push("Gemfile".to_owned());
    if let Some(contents) = read_limited(&directory.join("Gemfile"), 256 * 1024) {
        stack.framework = if contents.contains("rails") {
            Some("Ruby on Rails".to_owned())
        } else {
            None
        };
    }
    stack.run_hint = Some("envy run -- bundle exec rails server".to_owned());
    Some(stack)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn detects_nextjs() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"next":"15"},"scripts":{"dev":"next dev"}}"#,
        )
        .unwrap();
        fs::write(dir.path().join("pnpm-lock.yaml"), "").unwrap();
        let stacks = detect(dir.path());
        assert_eq!(stacks.len(), 1);
        assert_eq!(stacks[0].language, "Node.js");
        assert_eq!(stacks[0].framework.as_deref(), Some("Next.js"));
        assert_eq!(stacks[0].package_manager.as_deref(), Some("pnpm"));
        assert!(stacks[0].run_hint.as_deref().unwrap().contains("pnpm dev"));
    }

    #[test]
    fn detects_fastapi() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("requirements.txt"),
            "fastapi==0.115\nuvicorn\n",
        )
        .unwrap();
        let stacks = detect(dir.path());
        assert_eq!(stacks[0].language, "Python");
        assert_eq!(stacks[0].framework.as_deref(), Some("FastAPI"));
        assert!(stacks[0].run_hint.as_deref().unwrap().contains("uvicorn"));
    }

    #[test]
    fn detects_rust_axum() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("Cargo.toml"), "[dependencies]\naxum = \"0.8\"\n").unwrap();
        let stacks = detect(dir.path());
        assert_eq!(stacks[0].language, "Rust");
        assert_eq!(stacks[0].framework.as_deref(), Some("Axum"));
    }

    #[test]
    fn detects_go_gin() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("go.mod"),
            "module example.com/app\nrequire github.com/gin-gonic/gin v1.10.0\n",
        )
        .unwrap();
        let stacks = detect(dir.path());
        assert_eq!(stacks[0].language, "Go");
        assert_eq!(stacks[0].framework.as_deref(), Some("Gin"));
    }

    #[test]
    fn empty_directory_detects_nothing() {
        let dir = TempDir::new().unwrap();
        assert!(detect(dir.path()).is_empty());
    }
}
