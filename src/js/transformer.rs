use anyhow::Result;
#[cfg(feature = "ts-compiler")]
use anyhow::anyhow;

/// Transpiles TypeScript to JavaScript using the optional pure-Rust OXC engine (`ts-compiler` feature).
/// When `ts-compiler` is disabled (lean microkernel `profile-core`), returns source unmodified
/// (TypeScript can be pre-transpiled or stripped by a Wasm transpiler guest).
#[cfg(feature = "ts-compiler")]
pub fn transform_ts_to_js(source: &str) -> Result<String> {
    use oxc_allocator::Allocator;
    use oxc_codegen::Codegen;
    use oxc_parser::Parser;
    use oxc_semantic::SemanticBuilder;
    use oxc_span::SourceType;
    use oxc_transformer::{TransformOptions, Transformer};
    use std::path::Path;

    let allocator = Allocator::default();
    let path = Path::new("input.ts");
    let source_type = SourceType::from_path(path)
        .map_err(|_| anyhow!("Transformer Error: failed to determine source type"))?;

    let parser_return = Parser::new(&allocator, source, source_type).parse();

    if !parser_return.diagnostics.is_empty() {
        let err_msg = parser_return
            .diagnostics
            .into_iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        return Err(anyhow!("TypeScript Syntax Error:\n{}", err_msg));
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
        return Err(anyhow!("TypeScript Transform Error:\n{}", err_msg));
    }

    let result = Codegen::new().build(&program).code;
    Ok(result)
}

#[cfg(not(feature = "ts-compiler"))]
pub fn transform_ts_to_js(source: &str) -> Result<String> {
    if is_likely_ts(source) {
        anyhow::bail!(
            "TypeScript transpilation requires the `ts-compiler` feature (OXC) or pre-transpiled JavaScript in `profile-core`"
        );
    }
    Ok(source.to_string())
}

/// A heuristic to check if code might be TypeScript.
pub fn is_likely_ts(code: &str) -> bool {
    code.contains(": ")
        || (code.contains('<') && code.contains('>'))
        || code.contains("interface ")
        || code.contains("type ")
        || code.contains("enum ")
}

#[cfg(all(test, feature = "ts-compiler"))]
mod tests {
    use super::*;

    #[test]
    fn transpiles_typescript_to_javascript() {
        let ts = r#"
            interface User { name: string; age: number; }
            const greet = (u: User): string => `${u.name}:${u.age}`;
            greet({ name: "nexus", age: 1 });
        "#;
        let js = transform_ts_to_js(ts).unwrap();
        assert!(!js.contains("interface User"));
        assert!(js.contains("greet"));
    }
}
