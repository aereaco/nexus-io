use oxc_allocator::Allocator;
use oxc_codegen::{Codegen, CodegenOptions};
use oxc_parser::Parser;
use oxc_span::SourceType;
use oxc_transformer::{TransformOptions, Transformer};
use nu_protocol::{ShellError, Span};
use std::path::Path;

/// Transpiles TypeScript to JavaScript using the high-performance OXC engine.
/// This happens entirely in Rust, with no Node.js dependency.
pub fn transform_ts_to_js(source: &str, span: Span) -> Result<String, ShellError> {
    let allocator = Allocator::default();
    
    // We assume .ts for the purpose of the transformer
    let path = Path::new("input.ts");
    let source_type = SourceType::from_path(path).map_err(|_| crate::shell_err(
        "Transformer Error",
        "Failed to determine source type",
        Some(span),
        None,
    ))?;

    let parser_return = Parser::new(&allocator, source, source_type).parse();

    if !parser_return.errors.is_empty() {
        let err_msg = parser_return.errors
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

    let program = allocator.alloc(parser_return.program);
    
    // Configure transformer to only strip types (TypeScript support)
    let options = TransformOptions {
        ..Default::default()
    };
    
    let transformer = Transformer::new(
        &allocator,
        path,
        source_type,
        source,
        &parser_return.trivias,
        options
    );
    let _ = transformer.build(program);
    
    let result = Codegen::<false>::new(source, "input.ts", CodegenOptions::default(), None)
        .build(program)
        .source_text;
    Ok(result)
}

/// A heuristic to check if code might be TypeScript
pub fn is_likely_ts(code: &str) -> bool {
    // Simple check for common TS features if it doesn't look like pure JS
    code.contains(": ") || code.contains("<") && code.contains(">") || code.contains("interface ") || code.contains("type ") || code.contains("enum ")
}
