use oxc_allocator::Allocator;
use oxc_codegen::Codegen;
use oxc_parser::Parser;
use oxc_semantic::SemanticBuilder;
use oxc_span::SourceType;
use oxc_transformer::{TransformOptions, Transformer};
use nu_protocol::{ShellError, Span};
use std::path::Path;

/// Transpiles TypeScript to JavaScript using the pure-Rust OXC 0.144 engine.
/// Runs natively across Windows, Linux, macOS, Android, and iOS with zero Node.js dependency.
pub fn transform_ts_to_js(source: &str, span: Span) -> Result<String, ShellError> {
    let allocator = Allocator::default();
    let path = Path::new("input.ts");
    let source_type = SourceType::from_path(path).map_err(|_| {
        crate::shell_err(
            "Transformer Error",
            "Failed to determine source type",
            Some(span),
            None,
        )
    })?;

    let parser_return = Parser::new(&allocator, source, source_type).parse();

    if !parser_return.diagnostics.is_empty() {
        let err_msg = parser_return
            .diagnostics
            .into_iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        return Err(crate::shell_err(
            "TypeScript Syntax Error",
            err_msg,
            Some(span),
            Some("Ensure your TypeScript code is valid.".into()),
        ));
    }

    let mut program = parser_return.program;
    let scoping = SemanticBuilder::new().build(&program).semantic.into_scoping();
    let options = TransformOptions::default();

    let ret = Transformer::new(&allocator, path, &options).build_with_scoping(scoping, &mut program);
    if !ret.diagnostics.is_empty() {
        let err_msg = ret
            .diagnostics
            .into_iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        return Err(crate::shell_err(
            "TypeScript Transform Error",
            err_msg,
            Some(span),
            None,
        ));
    }

    let result = Codegen::new().build(&program).code;
    Ok(result)
}

/// A heuristic to check if code might be TypeScript.
pub fn is_likely_ts(code: &str) -> bool {
    code.contains(": ")
        || (code.contains('<') && code.contains('>'))
        || code.contains("interface ")
        || code.contains("type ")
        || code.contains("enum ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transpiles_typescript_to_javascript() {
        let ts = r#"
            interface User { name: string; age: number; }
            const greet = (u: User): string => `${u.name}:${u.age}`;
            greet({ name: "nexus", age: 1 });
        "#;
        let js = transform_ts_to_js(ts, Span::unknown()).unwrap();
        assert!(!js.contains("interface User"));
        assert!(js.contains("greet"));
    }
}
