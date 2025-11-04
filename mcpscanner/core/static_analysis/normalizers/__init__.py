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

"""AST normalizers for different languages."""

from .python_normalizer import PythonASTNormalizer

try:
    from .javascript_normalizer import JavaScriptASTNormalizer
    from .typescript_normalizer import TypeScriptASTNormalizer
    from .go_normalizer import GoASTNormalizer
    from .java_normalizer import JavaASTNormalizer
    from .kotlin_normalizer import KotlinASTNormalizer
    from .ruby_normalizer import RubyASTNormalizer
    from .rust_normalizer import RustASTNormalizer
    from .swift_normalizer import SwiftASTNormalizer
    from .csharp_normalizer import CSharpASTNormalizer
    
    __all__ = [
        "PythonASTNormalizer",
        "JavaScriptASTNormalizer",
        "TypeScriptASTNormalizer",
        "GoASTNormalizer",
        "JavaASTNormalizer",
        "KotlinASTNormalizer",
        "RubyASTNormalizer",
        "RustASTNormalizer",
        "SwiftASTNormalizer",
        "CSharpASTNormalizer",
    ]
except ImportError:
    # tree-sitter not available
    __all__ = ["PythonASTNormalizer"]
