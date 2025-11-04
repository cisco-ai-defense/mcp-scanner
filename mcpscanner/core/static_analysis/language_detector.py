# Copyright 2025 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Language detection utilities."""

from enum import Enum
from pathlib import Path


class Language(Enum):
    """Supported programming languages."""
    
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    TSX = "tsx"
    JAVA = "java"
    KOTLIN = "kotlin"
    GO = "go"
    SWIFT = "swift"
    CSHARP = "csharp"
    RUBY = "ruby"
    RUST = "rust"
    UNKNOWN = "unknown"


def detect_language(file_path: Path) -> Language:
    """Detect programming language from file extension.
    
    Args:
        file_path: Path to source file
        
    Returns:
        Detected language
    """
    suffix = file_path.suffix.lower()
    
    if suffix == '.py':
        return Language.PYTHON
    elif suffix == '.js':
        return Language.JAVASCRIPT
    elif suffix == '.ts':
        return Language.TYPESCRIPT
    elif suffix == '.tsx':
        return Language.TSX
    elif suffix == '.java':
        return Language.JAVA
    elif suffix in ['.kt', '.kts']:
        return Language.KOTLIN
    elif suffix == '.go':
        return Language.GO
    elif suffix == '.swift':
        return Language.SWIFT
    elif suffix in ['.mjs', '.cjs']:
        return Language.JAVASCRIPT
    elif suffix == '.mts':
        return Language.TYPESCRIPT
    elif suffix == '.cs':
        return Language.CSHARP
    elif suffix == '.rb':
        return Language.RUBY
    elif suffix == '.rs':
        return Language.RUST
    else:
        return Language.UNKNOWN


def get_parser_for_language(language: Language, file_path: Path, source_code: str):
    """Get appropriate parser for a language.
    
    Args:
        language: Programming language
        file_path: Path to source file
        source_code: Source code content
        
    Returns:
        Parser instance
        
    Raises:
        ValueError: If language is not supported
    """
    if language == Language.PYTHON:
        from .parser.python_parser import PythonParser
        return PythonParser(file_path, source_code)
    
    elif language == Language.JAVASCRIPT:
        try:
            from .parser.javascript_parser import JavaScriptParser
            return JavaScriptParser(file_path, source_code)
        except ImportError:
            raise ValueError(
                "JavaScript support requires tree-sitter. "
                "Install with: pip install tree-sitter tree-sitter-javascript"
            )
    
    elif language in [Language.TYPESCRIPT, Language.TSX]:
        try:
            from .parser.typescript_parser import TypeScriptParser, TSXParser
            if language == Language.TSX:
                return TSXParser(file_path, source_code)
            else:
                return TypeScriptParser(file_path, source_code)
        except ImportError:
            raise ValueError(
                "TypeScript support requires tree-sitter. "
                "Install with: pip install tree-sitter tree-sitter-typescript"
            )
    
    elif language == Language.JAVA:
        try:
            from .parser.java_parser import JavaParser
            return JavaParser(file_path, source_code)
        except ImportError:
            raise ValueError(
                "Java support requires tree-sitter. "
                "Install with: pip install tree-sitter tree-sitter-java"
            )
    
    elif language == Language.KOTLIN:
        try:
            from .parser.kotlin_parser import KotlinParser
            return KotlinParser(file_path, source_code)
        except ImportError:
            raise ValueError(
                "Kotlin support requires tree-sitter. "
                "Install with: pip install tree-sitter tree-sitter-kotlin"
            )
    
    elif language == Language.GO:
        try:
            from .parser.go_parser import GoParser
            return GoParser(file_path, source_code)
        except ImportError:
            raise ValueError(
                "Go support requires tree-sitter. "
                "Install with: pip install tree-sitter tree-sitter-go"
            )
    
    elif language == Language.SWIFT:
        try:
            from .parser.swift_parser import SwiftParser
            return SwiftParser(file_path, source_code)
        except ImportError:
            raise ValueError(
                "Swift support requires tree-sitter. "
                "Install with: pip install tree-sitter tree-sitter-swift"
            )
    
    elif language == Language.CSHARP:
        try:
            from .parser.csharp_parser import CSharpParser
            return CSharpParser(file_path, source_code)
        except ImportError:
            raise ValueError(
                "C# support requires tree-sitter. "
                "Install with: pip install tree-sitter tree-sitter-c-sharp"
            )
    
    elif language == Language.RUBY:
        try:
            from .parser.ruby_parser import RubyParser
            return RubyParser(file_path, source_code)
        except ImportError:
            raise ValueError(
                "Ruby support requires tree-sitter. "
                "Install with: pip install tree-sitter tree-sitter-ruby"
            )
    
    elif language == Language.RUST:
        try:
            from .parser.rust_parser import RustParser
            return RustParser(file_path, source_code)
        except ImportError:
            raise ValueError(
                "Rust support requires tree-sitter. "
                "Install with: pip install tree-sitter tree-sitter-rust"
            )
    
    else:
        raise ValueError(f"Unsupported language: {language}")


def get_normalizer_for_language(language: Language, parser):
    """Get appropriate AST normalizer for a language.
    
    Args:
        language: Programming language
        parser: Parser instance
        
    Returns:
        Normalizer instance
        
    Raises:
        ValueError: If language is not supported
    """
    if language == Language.PYTHON:
        from .normalizers.python_normalizer import PythonASTNormalizer
        return PythonASTNormalizer()
    
    elif language == Language.JAVASCRIPT:
        try:
            from .normalizers.javascript_normalizer import JavaScriptASTNormalizer
            return JavaScriptASTNormalizer(parser)
        except ImportError:
            raise ValueError(
                "JavaScript support requires tree-sitter. "
                "Install with: pip install tree-sitter tree-sitter-javascript"
            )
    
    elif language in [Language.TYPESCRIPT, Language.TSX]:
        try:
            from .normalizers.typescript_normalizer import TypeScriptASTNormalizer
            return TypeScriptASTNormalizer(parser)
        except ImportError:
            raise ValueError(
                "TypeScript support requires tree-sitter. "
                "Install with: pip install tree-sitter tree-sitter-typescript"
            )
    
    elif language == Language.JAVA:
        try:
            from .normalizers.java_normalizer import JavaASTNormalizer
            return JavaASTNormalizer(parser)
        except ImportError:
            raise ValueError(
                "Java support requires tree-sitter. "
                "Install with: pip install tree-sitter tree-sitter-java"
            )
    
    elif language == Language.KOTLIN:
        try:
            from .normalizers.kotlin_normalizer import KotlinASTNormalizer
            return KotlinASTNormalizer(parser)
        except ImportError:
            raise ValueError(
                "Kotlin support requires tree-sitter. "
                "Install with: pip install tree-sitter tree-sitter-kotlin"
            )
    
    elif language == Language.GO:
        try:
            from .normalizers.go_normalizer import GoASTNormalizer
            return GoASTNormalizer(parser)
        except ImportError:
            raise ValueError(
                "Go support requires tree-sitter. "
                "Install with: pip install tree-sitter tree-sitter-go"
            )
    
    elif language == Language.SWIFT:
        try:
            from .normalizers.swift_normalizer import SwiftASTNormalizer
            return SwiftASTNormalizer(parser)
        except ImportError:
            raise ValueError(
                "Swift support requires tree-sitter. "
                "Install with: pip install tree-sitter tree-sitter-swift"
            )
    
    elif language == Language.CSHARP:
        try:
            from .normalizers.csharp_normalizer import CSharpASTNormalizer
            return CSharpASTNormalizer(parser)
        except ImportError:
            raise ValueError(
                "C# support requires tree-sitter. "
                "Install with: pip install tree-sitter tree-sitter-c-sharp"
            )
    
    elif language == Language.RUBY:
        try:
            from .normalizers.ruby_normalizer import RubyASTNormalizer
            return RubyASTNormalizer(parser)
        except ImportError:
            raise ValueError(
                "Ruby support requires tree-sitter. "
                "Install with: pip install tree-sitter tree-sitter-ruby"
            )
    
    elif language == Language.RUST:
        try:
            from .normalizers.rust_normalizer import RustASTNormalizer
            return RustASTNormalizer(parser)
        except ImportError:
            raise ValueError(
                "Rust support requires tree-sitter. "
                "Install with: pip install tree-sitter tree-sitter-rust"
            )
    
    else:
        raise ValueError(f"Unsupported language: {language}")


def get_mcp_functions(language: Language, parser, ast_root):
    """Find MCP-decorated functions for a language.
    
    Args:
        language: Programming language
        parser: Parser instance
        ast_root: Parsed AST root
        
    Returns:
        List of MCP function nodes
    """
    if language == Language.PYTHON:
        import ast
        mcp_functions = []
        for node in ast.walk(ast_root):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Check for @mcp.tool decorator
                for decorator in node.decorator_list:
                    try:
                        decorator_name = ast.unparse(decorator)
                        if 'mcp.tool' in decorator_name or '@tool' in decorator_name:
                            mcp_functions.append(node)
                            break
                    except:
                        pass
        return mcp_functions
    
    elif language in [Language.JAVASCRIPT, Language.TYPESCRIPT, Language.TSX]:
        # Use parser's find_mcp_decorated_functions method
        return parser.find_mcp_decorated_functions()
    
    elif language == Language.JAVA:
        # Use parser's find_mcp_decorated_functions method
        return parser.find_mcp_decorated_functions()
    
    elif language == Language.KOTLIN:
        # Use parser's find_mcp_decorated_functions method
        return parser.find_mcp_decorated_functions()
    
    elif language == Language.GO:
        # Use parser's find_mcp_decorated_functions method
        return parser.find_mcp_decorated_functions()
    
    elif language == Language.SWIFT:
        # Use parser's find_mcp_decorated_functions method
        return parser.find_mcp_decorated_functions()
    
    elif language == Language.CSHARP:
        # Use parser's find_mcp_decorated_functions method
        return parser.find_mcp_decorated_functions()
    
    elif language == Language.RUBY:
        # Use parser's find_mcp_decorated_functions method
        return parser.find_mcp_decorated_functions()
    
    elif language == Language.RUST:
        # Use parser's find_mcp_decorated_functions method
        return parser.find_mcp_decorated_functions()
    
    else:
        return []
