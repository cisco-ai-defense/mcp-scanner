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

"""Type analysis and inference with reversed approach.

REVERSED APPROACH: Track types of MCP parameters and parameter-influenced variables.

MULTI-LANGUAGE SUPPORT: Now supports all 10 languages through unified AST.
"""

import ast
from enum import Enum
from typing import Any, Optional

from ..parser.base import BaseParser
from ..parser.python_parser import PythonParser
from ..unified_ast import UnifiedASTNode, NodeType
from ..language_detector import Language


class TypeKind(Enum):
    """Type kinds."""
    UNKNOWN = "unknown"
    INT = "int"
    FLOAT = "float"
    STR = "str"
    BOOL = "bool"
    LIST = "list"
    DICT = "dict"
    TUPLE = "tuple"
    SET = "set"
    NONE = "none"
    FUNCTION = "function"
    CLASS = "class"
    ANY = "any"


class Type:
    """Represents a type."""

    def __init__(self, kind: TypeKind, params: list["Type"] | None = None) -> None:
        """Initialize type.

        Args:
            kind: Type kind
            params: Type parameters (for generics)
        """
        self.kind = kind
        self.params = params or []

    def __str__(self) -> str:
        """String representation."""
        if self.params:
            params_str = ", ".join(str(p) for p in self.params)
            return f"{self.kind.value}[{params_str}]"
        return self.kind.value

    def __eq__(self, other: object) -> bool:
        """Check equality."""
        if not isinstance(other, Type):
            return False
        return self.kind == other.kind and self.params == other.params


class TypeAnalyzer:
    """Performs type inference and analysis.
    
    REVERSED APPROACH: Specifically tracks types of MCP parameters and 
    parameter-influenced variables.
    """

    def __init__(self, analyzer: BaseParser, parameter_names: list[str] = None, language: Optional[Language] = None):
        """Initialize type analyzer.

        Args:
            analyzer: Language-specific analyzer
            parameter_names: MCP entry point parameter names
            language: Programming language (for unified analysis)
        """
        self.analyzer = analyzer
        self.parameter_names = set(parameter_names or [])
        self.language = language
        self.node_types: dict[Any, Type] = {}
        self.var_types: dict[str, Type] = {}
        self.param_var_types: dict[str, Type] = {}  # Types of parameter-influenced vars
        self.instance_to_class: dict[str, str] = {}  # variable_name -> ClassName for instances

    def analyze(self) -> None:
        """Perform type analysis on the AST."""
        ast_root = self.analyzer.get_ast()

        if isinstance(self.analyzer, PythonParser):
            self._analyze_python(ast_root)

    def analyze_unified(self, unified_nodes: list[UnifiedASTNode]) -> None:
        """Perform type analysis on unified AST nodes (supports all languages).

        Args:
            unified_nodes: List of UnifiedASTNode (typically functions)
        """
        for node in unified_nodes:
            self._analyze_unified_node(node)

    def _analyze_unified_node(self, node: UnifiedASTNode) -> None:
        """Analyze types in a unified AST node.

        Args:
            node: Unified AST node
        """
        # Track parameter types from function signatures
        if node.type in [NodeType.FUNCTION, NodeType.ASYNC_FUNCTION]:
            for param_name in node.parameters:
                if param_name in self.parameter_names:
                    # Try to get type from metadata
                    param_type = self._infer_unified_param_type(node, param_name)
                    self.var_types[param_name] = param_type
                    self.param_var_types[param_name] = param_type

        # Analyze assignments to track type propagation
        if node.metadata and 'assignments' in node.metadata:
            for assignment in node.metadata['assignments']:
                target = assignment.get('target')
                if target:
                    # Infer type from assignment context
                    inferred_type = self._infer_unified_assignment_type(assignment, node)
                    self.var_types[target] = inferred_type
                    
                    # Check if assignment uses parameters
                    if self._unified_uses_parameters(assignment, node):
                        self.param_var_types[target] = inferred_type

        # Recursively analyze children
        for child in node.children:
            self._analyze_unified_node(child)

    def _infer_unified_param_type(self, func_node: UnifiedASTNode, param_name: str) -> Type:
        """Infer parameter type from unified function node.

        Args:
            func_node: Unified function node
            param_name: Parameter name

        Returns:
            Inferred type
        """
        # Check for type annotations in metadata
        if func_node.metadata and 'params_with_types' in func_node.metadata:
            params_with_types = func_node.metadata['params_with_types']
            for param_info in params_with_types:
                if isinstance(param_info, dict) and param_info.get('name') == param_name:
                    type_str = param_info.get('type', '')
                    return self._string_to_type(type_str)
        
        # Default to ANY if no type info
        return Type(TypeKind.ANY)

    def _infer_unified_assignment_type(self, assignment: dict, context_node: UnifiedASTNode) -> Type:
        """Infer type from assignment in unified AST.

        Args:
            assignment: Assignment metadata dict
            context_node: Context node

        Returns:
            Inferred type
        """
        # Check if it's a string literal assignment
        if context_node.metadata and 'string_literals' in context_node.metadata:
            for lit in context_node.metadata['string_literals']:
                if isinstance(lit, dict) and lit.get('line') == assignment.get('line'):
                    return Type(TypeKind.STR)
        
        # Check if it's a function call result
        if context_node.metadata and 'all_calls' in context_node.metadata:
            for call in context_node.metadata['all_calls']:
                if isinstance(call, dict) and call.get('line') == assignment.get('line'):
                    # Function call result - type unknown
                    return Type(TypeKind.UNKNOWN)
        
        return Type(TypeKind.UNKNOWN)

    def _unified_uses_parameters(self, assignment: dict, context_node: UnifiedASTNode) -> bool:
        """Check if assignment uses tracked parameters.

        Args:
            assignment: Assignment metadata
            context_node: Context node

        Returns:
            True if uses parameters
        """
        # Check variable dependencies
        if context_node.metadata and 'variable_dependencies' in context_node.metadata:
            deps = context_node.metadata['variable_dependencies']
            target = assignment.get('target')
            if target in deps:
                dep_vars = deps[target]
                return any(var in self.parameter_names for var in dep_vars)
        
        return False

    def _string_to_type(self, type_str: str) -> Type:
        """Convert type string to Type object.

        Args:
            type_str: Type string (e.g., 'string', 'int', 'bool')

        Returns:
            Type object
        """
        type_str_lower = type_str.lower()
        
        if 'string' in type_str_lower or 'str' in type_str_lower:
            return Type(TypeKind.STR)
        elif 'int' in type_str_lower or 'integer' in type_str_lower or 'number' in type_str_lower:
            return Type(TypeKind.INT)
        elif 'float' in type_str_lower or 'double' in type_str_lower:
            return Type(TypeKind.FLOAT)
        elif 'bool' in type_str_lower:
            return Type(TypeKind.BOOL)
        elif 'list' in type_str_lower or 'array' in type_str_lower or '[]' in type_str:
            return Type(TypeKind.LIST)
        elif 'dict' in type_str_lower or 'map' in type_str_lower or 'object' in type_str_lower:
            return Type(TypeKind.DICT)
        else:
            return Type(TypeKind.ANY)

    def _analyze_python(self, node: ast.AST) -> None:
        """Analyze types in Python AST.

        Args:
            node: Python AST node
        """
        # First pass: infer types from annotations and literals
        for n in ast.walk(node):
            inferred_type = self._infer_python_type(n)
            if inferred_type:
                self.node_types[n] = inferred_type
            
            # Track parameter types
            if isinstance(n, ast.FunctionDef):
                for arg in n.args.args:
                    if arg.arg in self.parameter_names:
                        if arg.annotation:
                            param_type = self._annotation_to_type(arg.annotation)
                            self.var_types[arg.arg] = param_type
                            self.param_var_types[arg.arg] = param_type
                        else:
                            self.var_types[arg.arg] = Type(TypeKind.ANY)
                            self.param_var_types[arg.arg] = Type(TypeKind.ANY)
        
        # Second pass: propagate types through assignments and track class instances
        for n in ast.walk(node):
            if isinstance(n, ast.Assign):
                rhs_type = self.node_types.get(n.value, Type(TypeKind.UNKNOWN))
                
                for target in n.targets:
                    if isinstance(target, ast.Name):
                        self.var_types[target.id] = rhs_type
                        
                        # Track class instantiations: var = ClassName()
                        if isinstance(n.value, ast.Call):
                            if isinstance(n.value.func, ast.Name):
                                class_name = n.value.func.id
                                self.instance_to_class[target.id] = class_name
                        
                        # Check if RHS uses parameters
                        if self._uses_parameters(n.value):
                            self.param_var_types[target.id] = rhs_type

    def _infer_python_type(self, node: ast.AST) -> Type | None:
        """Infer type of a Python AST node.

        Args:
            node: Python AST node

        Returns:
            Inferred Type or None
        """
        if isinstance(node, ast.Constant):
            return self._infer_constant_type(node.value)
        elif isinstance(node, ast.List):
            return Type(TypeKind.LIST)
        elif isinstance(node, ast.Dict):
            return Type(TypeKind.DICT)
        elif isinstance(node, ast.Tuple):
            return Type(TypeKind.TUPLE)
        elif isinstance(node, ast.Set):
            return Type(TypeKind.SET)
        elif isinstance(node, ast.Compare):
            return Type(TypeKind.BOOL)
        elif isinstance(node, ast.BoolOp):
            return Type(TypeKind.BOOL)
        elif isinstance(node, ast.FunctionDef):
            return Type(TypeKind.FUNCTION)
        elif isinstance(node, ast.ClassDef):
            return Type(TypeKind.CLASS)

        return None

    def _infer_constant_type(self, value: Any) -> Type:
        """Infer type of a constant value.

        Args:
            value: Constant value

        Returns:
            Type
        """
        if isinstance(value, bool):
            return Type(TypeKind.BOOL)
        elif isinstance(value, int):
            return Type(TypeKind.INT)
        elif isinstance(value, float):
            return Type(TypeKind.FLOAT)
        elif isinstance(value, str):
            return Type(TypeKind.STR)
        elif value is None:
            return Type(TypeKind.NONE)
        else:
            return Type(TypeKind.UNKNOWN)

    def _annotation_to_type(self, annotation: ast.AST) -> Type:
        """Convert type annotation to Type.

        Args:
            annotation: Annotation node

        Returns:
            Type
        """
        if isinstance(annotation, ast.Name):
            type_name = annotation.id.lower()
            try:
                return Type(TypeKind(type_name))
            except ValueError:
                return Type(TypeKind.UNKNOWN)
        elif isinstance(annotation, ast.Constant):
            if isinstance(annotation.value, str):
                try:
                    return Type(TypeKind(annotation.value.lower()))
                except ValueError:
                    return Type(TypeKind.UNKNOWN)
        
        return Type(TypeKind.UNKNOWN)

    def _uses_parameters(self, node: ast.AST) -> bool:
        """Check if node uses MCP parameters.

        Args:
            node: AST node

        Returns:
            True if uses parameters
        """
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in self.parameter_names:
                return True
        return False

    def get_type(self, var_name: str) -> Type:
        """Get type of a variable.

        Args:
            var_name: Variable name

        Returns:
            Type
        """
        return self.var_types.get(var_name, Type(TypeKind.UNKNOWN))

    def get_parameter_types(self) -> dict[str, Type]:
        """Get types of all MCP parameters.

        Returns:
            Dictionary mapping parameter names to types
        """
        return {
            name: self.var_types.get(name, Type(TypeKind.ANY))
            for name in self.parameter_names
        }

    def get_param_influenced_types(self) -> dict[str, Type]:
        """Get types of all parameter-influenced variables.

        Returns:
            Dictionary mapping variable names to types
        """
        return self.param_var_types.copy()
    
    def resolve_method_call(self, call_name: str) -> str | None:
        """Resolve instance.method() to ClassName.method.
        
        Args:
            call_name: Call name like 'processor.process' or 'obj.method'
            
        Returns:
            Resolved name like 'DataProcessor.process' or None
        """
        if '.' not in call_name:
            return None
        
        parts = call_name.split('.', 1)
        if len(parts) != 2:
            return None
        
        instance_name, method_name = parts
        
        # Look up the class for this instance
        class_name = self.instance_to_class.get(instance_name)
        if class_name:
            return f"{class_name}.{method_name}"
        
        return None
    
    def get_instance_mappings(self) -> dict[str, str]:
        """Get all instance to class mappings.
        
        Returns:
            Dictionary mapping instance names to class names
        """
        return self.instance_to_class.copy()
