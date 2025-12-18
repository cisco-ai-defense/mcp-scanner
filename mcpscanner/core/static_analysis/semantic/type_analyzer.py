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
"""

import ast
from enum import Enum
from typing import Any

from ..parser.base import BaseParser
from ..parser.python_parser import PythonParser


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

    def __init__(self, analyzer: BaseParser, parameter_names: list[str] = None):
        """Initialize type analyzer.

        Args:
            analyzer: Language-specific analyzer
            parameter_names: MCP entry point parameter names
        """
        self.analyzer = analyzer
        self.parameter_names = set(parameter_names or [])
        self.node_types: dict[Any, Type] = {}
        self.var_types: dict[str, Type] = {}
        self.param_var_types: dict[str, Type] = {}  # Types of parameter-influenced vars
        self.instance_to_class: dict[str, str] = {}  # variable_name -> ClassName for instances

    def analyze(self) -> None:
        """Perform type analysis on the AST."""
        ast_root = self.analyzer.get_ast()

        if isinstance(self.analyzer, PythonParser):
            self._analyze_python(ast_root)

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
            
            # Track parameter types for both sync and async functions
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Process regular args
                for arg in n.args.args:
                    if arg.arg in self.parameter_names:
                        if arg.annotation:
                            param_type = self._annotation_to_type(arg.annotation)
                            self.var_types[arg.arg] = param_type
                            self.param_var_types[arg.arg] = param_type
                        else:
                            self.var_types[arg.arg] = Type(TypeKind.ANY)
                            self.param_var_types[arg.arg] = Type(TypeKind.ANY)
                
                # Process *args (vararg)
                if n.args.vararg and n.args.vararg.arg in self.parameter_names:
                    if n.args.vararg.annotation:
                        param_type = self._annotation_to_type(n.args.vararg.annotation)
                        self.var_types[n.args.vararg.arg] = param_type
                        self.param_var_types[n.args.vararg.arg] = param_type
                    else:
                        self.var_types[n.args.vararg.arg] = Type(TypeKind.ANY)
                        self.param_var_types[n.args.vararg.arg] = Type(TypeKind.ANY)
                
                # Process keyword-only args
                for arg in n.args.kwonlyargs:
                    if arg.arg in self.parameter_names:
                        if arg.annotation:
                            param_type = self._annotation_to_type(arg.annotation)
                            self.var_types[arg.arg] = param_type
                            self.param_var_types[arg.arg] = param_type
                        else:
                            self.var_types[arg.arg] = Type(TypeKind.ANY)
                            self.param_var_types[arg.arg] = Type(TypeKind.ANY)
                
                # Process **kwargs (kwarg)
                if n.args.kwarg and n.args.kwarg.arg in self.parameter_names:
                    if n.args.kwarg.annotation:
                        param_type = self._annotation_to_type(n.args.kwarg.annotation)
                        self.var_types[n.args.kwarg.arg] = param_type
                        self.param_var_types[n.args.kwarg.arg] = param_type
                    else:
                        self.var_types[n.args.kwarg.arg] = Type(TypeKind.ANY)
                        self.param_var_types[n.args.kwarg.arg] = Type(TypeKind.ANY)
        
        # Second pass: propagate types through assignments and track class instances
        for n in ast.walk(node):
            # Handle regular assignments (=)
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
            
            # Handle annotated assignments (a: int = 1)
            elif isinstance(n, ast.AnnAssign):
                if isinstance(n.target, ast.Name):
                    # Use annotation type if available, otherwise infer from value
                    if n.annotation:
                        ann_type = self._annotation_to_type(n.annotation)
                        self.var_types[n.target.id] = ann_type
                    elif n.value:
                        rhs_type = self.node_types.get(n.value, Type(TypeKind.UNKNOWN))
                        self.var_types[n.target.id] = rhs_type
                    
                    # Track class instantiations
                    if n.value and isinstance(n.value, ast.Call):
                        if isinstance(n.value.func, ast.Name):
                            class_name = n.value.func.id
                            self.instance_to_class[n.target.id] = class_name
                    
                    # Check if RHS uses parameters
                    if n.value and self._uses_parameters(n.value):
                        self.param_var_types[n.target.id] = self.var_types[n.target.id]
            
            # Handle augmented assignments (+=, -=, etc.)
            elif isinstance(n, ast.AugAssign):
                if isinstance(n.target, ast.Name):
                    # Keep existing type or infer from value
                    if n.target.id not in self.var_types:
                        rhs_type = self.node_types.get(n.value, Type(TypeKind.UNKNOWN))
                        self.var_types[n.target.id] = rhs_type
                    
                    # Check if RHS uses parameters
                    if self._uses_parameters(n.value):
                        self.param_var_types[n.target.id] = self.var_types[n.target.id]
            
            # Handle walrus operator (:=)
            elif isinstance(n, ast.NamedExpr):
                if isinstance(n.target, ast.Name):
                    rhs_type = self.node_types.get(n.value, Type(TypeKind.UNKNOWN))
                    self.var_types[n.target.id] = rhs_type
                    
                    # Track class instantiations
                    if isinstance(n.value, ast.Call):
                        if isinstance(n.value.func, ast.Name):
                            class_name = n.value.func.id
                            self.instance_to_class[n.target.id] = class_name
                    
                    # Check if RHS uses parameters
                    if self._uses_parameters(n.value):
                        self.param_var_types[n.target.id] = rhs_type

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
        """Check if node uses MCP parameters (directly or transitively).

        Args:
            node: AST node

        Returns:
            True if uses parameters (including parameter-influenced variables)
        """
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                # Check direct parameter usage
                if child.id in self.parameter_names:
                    return True
                # Check if variable is parameter-influenced (transitive)
                if child.id in self.param_var_types:
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
            name: self.var_types.get(name, Type(TypeKind.UNKNOWN))
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
