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

"""Semantic analysis for tree-sitter languages.

Provides name resolution and type inference for TypeScript, JavaScript, Go,
Java, Kotlin, C#, Ruby, Rust, and PHP.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from tree_sitter import Node


class TSTypeKind(Enum):
    """Type kinds for tree-sitter languages."""
    UNKNOWN = "unknown"
    INT = "int"
    FLOAT = "float"
    STRING = "string"
    BOOL = "bool"
    ARRAY = "array"
    OBJECT = "object"
    MAP = "map"
    FUNCTION = "function"
    CLASS = "class"
    VOID = "void"
    NULL = "null"
    ANY = "any"


@dataclass
class TSType:
    """Represents a type in tree-sitter languages."""
    kind: TSTypeKind
    name: str = ""  # For class/interface types
    params: List["TSType"] = field(default_factory=list)  # For generics
    
    def __str__(self) -> str:
        if self.name:
            if self.params:
                return f"{self.name}<{', '.join(str(p) for p in self.params)}>"
            return self.name
        return self.kind.value


@dataclass
class TSScope:
    """Represents a lexical scope."""
    parent: Optional["TSScope"] = None
    symbols: Dict[str, Any] = field(default_factory=dict)
    types: Dict[str, TSType] = field(default_factory=dict)
    is_param: Dict[str, bool] = field(default_factory=dict)
    children: List["TSScope"] = field(default_factory=list)
    
    def define(self, name: str, node: Any, type_info: TSType = None, is_param: bool = False) -> None:
        """Define a symbol in this scope."""
        self.symbols[name] = node
        if type_info:
            self.types[name] = type_info
        self.is_param[name] = is_param
    
    def lookup(self, name: str) -> Optional[Any]:
        """Look up a symbol in this scope or parent scopes."""
        if name in self.symbols:
            return self.symbols[name]
        if self.parent:
            return self.parent.lookup(name)
        return None
    
    def get_type(self, name: str) -> TSType:
        """Get type of a symbol."""
        if name in self.types:
            return self.types[name]
        if self.parent:
            return self.parent.get_type(name)
        return TSType(TSTypeKind.UNKNOWN)
    
    def is_param_influenced(self, name: str) -> bool:
        """Check if symbol is influenced by parameters."""
        if name in self.is_param:
            return self.is_param[name]
        if self.parent:
            return self.parent.is_param_influenced(name)
        return False


class TreeSitterSemanticAnalyzer:
    """Semantic analysis for tree-sitter languages.
    
    Provides:
    - Name resolution (symbol table)
    - Type inference
    - Parameter influence tracking
    """
    
    # Type annotation node types per language
    TYPE_ANNOTATION_TYPES = {
        "javascript": set(),  # JS has no type annotations
        "typescript": {"type_annotation", "type_identifier", "predefined_type"},
        "go": {"type_identifier", "pointer_type", "slice_type", "map_type"},
        "java": {"type_identifier", "generic_type", "array_type"},
        "kotlin": {"type_identifier", "nullable_type"},
        "c_sharp": {"type", "predefined_type", "nullable_type"},
        "ruby": set(),  # Ruby has no type annotations
        "rust": {"type_identifier", "reference_type", "generic_type"},
        "php": {"type_list", "named_type", "primitive_type"},
    }
    
    # Variable declaration types per language
    VAR_DECL_TYPES = {
        "javascript": {"variable_declarator", "lexical_declaration"},
        "typescript": {"variable_declarator", "lexical_declaration"},
        "go": {"short_var_declaration", "var_spec"},
        "java": {"variable_declarator", "local_variable_declaration"},
        "kotlin": {"property_declaration", "variable_declaration"},
        "c_sharp": {"variable_declarator", "local_declaration_statement"},
        "ruby": {"assignment", "lhs"},
        "rust": {"let_declaration"},
        "php": {"simple_variable", "variable_name"},
    }
    
    def __init__(self, language: str, root_node: Node, source_bytes: bytes, param_names: List[str] = None):
        """Initialize semantic analyzer."""
        self.language = language
        self.root = root_node
        self.source_bytes = source_bytes
        self.param_names = set(param_names or [])
        
        self.global_scope = TSScope()
        self.current_scope = self.global_scope
        
        self.param_influenced: Set[str] = set(param_names or [])
        self.instance_to_class: Dict[str, str] = {}
        self.var_types: Dict[str, TSType] = {}
    
    def analyze(self) -> None:
        """Perform semantic analysis."""
        self._visit(self.root)
    
    def _visit(self, node: Node) -> None:
        """Visit a node and its children."""
        # Handle scope-creating nodes
        if node.type in ("function_declaration", "function_expression", "arrow_function",
                        "method_definition", "method_declaration", "function_item"):
            self._visit_function(node)
        elif node.type in ("class_declaration", "class", "struct_item", "impl_item"):
            self._visit_class(node)
        elif node.type in ("variable_declarator", "short_var_declaration", "let_declaration",
                          "assignment", "property_declaration", "var_spec"):
            self._visit_assignment(node)
        else:
            for child in node.children:
                self._visit(child)
    
    def _visit_function(self, node: Node) -> None:
        """Visit function with scope management."""
        # Get function name
        name_node = node.child_by_field_name("name")
        if name_node:
            func_name = self._get_text(name_node)
            self.current_scope.define(func_name, node, TSType(TSTypeKind.FUNCTION))
        
        # Create new scope
        func_scope = TSScope(parent=self.current_scope)
        self.current_scope.children.append(func_scope)
        old_scope = self.current_scope
        self.current_scope = func_scope
        
        # Extract and define parameters
        params_node = node.child_by_field_name("parameters")
        if params_node:
            self._extract_parameters(params_node, func_scope)
        
        # Visit function body
        body = node.child_by_field_name("body")
        if body:
            for child in body.children:
                self._visit(child)
        
        # Exit scope
        self.current_scope = old_scope
    
    def _extract_parameters(self, params_node: Node, scope: TSScope) -> None:
        """Extract parameters and add to scope."""
        for child in params_node.children:
            if child.type in ("identifier", "formal_parameter", "required_parameter",
                             "parameter_declaration", "simple_parameter"):
                # Get parameter name
                name_node = child.child_by_field_name("name") or child
                if name_node.type == "identifier":
                    param_name = self._get_text(name_node)
                    
                    # Get type annotation if available
                    type_info = self._extract_type(child)
                    
                    # Check if this is a tracked parameter
                    is_tracked = param_name in self.param_names
                    
                    scope.define(param_name, child, type_info, is_param=is_tracked)
                    self.var_types[param_name] = type_info
                    
                    if is_tracked:
                        self.param_influenced.add(param_name)
    
    def _visit_class(self, node: Node) -> None:
        """Visit class with scope management."""
        name_node = node.child_by_field_name("name")
        if name_node:
            class_name = self._get_text(name_node)
            self.current_scope.define(class_name, node, TSType(TSTypeKind.CLASS, name=class_name))
        
        # Create class scope
        class_scope = TSScope(parent=self.current_scope)
        self.current_scope.children.append(class_scope)
        old_scope = self.current_scope
        self.current_scope = class_scope
        
        # Visit class body
        body = node.child_by_field_name("body")
        if body:
            for child in body.children:
                self._visit(child)
        
        self.current_scope = old_scope
    
    def _visit_assignment(self, node: Node) -> None:
        """Visit assignment and track taint."""
        # Get target
        target = node.child_by_field_name("left") or node.child_by_field_name("name")
        value = node.child_by_field_name("right") or node.child_by_field_name("value")
        
        if not target:
            # Try to find identifier in children
            for child in node.children:
                if child.type == "identifier":
                    target = child
                    break
        
        if target:
            target_name = self._get_text(target)
            
            # Infer type from value
            type_info = self._infer_type(value) if value else TSType(TSTypeKind.UNKNOWN)
            
            # Check if value uses parameters
            uses_params = self._uses_params(value) if value else False
            
            self.current_scope.define(target_name, node, type_info, is_param=uses_params)
            self.var_types[target_name] = type_info
            
            if uses_params:
                self.param_influenced.add(target_name)
            
            # Track class instantiation
            if value and value.type in ("call_expression", "new_expression", "object_creation_expression"):
                func = value.child_by_field_name("function") or value.child_by_field_name("type")
                if func:
                    class_name = self._get_text(func)
                    self.instance_to_class[target_name] = class_name
        
        # Continue visiting children
        for child in node.children:
            self._visit(child)
    
    def _extract_type(self, node: Node) -> TSType:
        """Extract type annotation from node."""
        type_node = node.child_by_field_name("type")
        if type_node:
            return self._parse_type(type_node)
        return TSType(TSTypeKind.UNKNOWN)
    
    def _parse_type(self, node: Node) -> TSType:
        """Parse a type annotation node."""
        type_text = self._get_text(node).lower()
        
        # Map common type names
        type_map = {
            "int": TSTypeKind.INT, "int32": TSTypeKind.INT, "int64": TSTypeKind.INT,
            "integer": TSTypeKind.INT, "number": TSTypeKind.INT,
            "float": TSTypeKind.FLOAT, "float32": TSTypeKind.FLOAT, "float64": TSTypeKind.FLOAT,
            "double": TSTypeKind.FLOAT,
            "string": TSTypeKind.STRING, "str": TSTypeKind.STRING,
            "bool": TSTypeKind.BOOL, "boolean": TSTypeKind.BOOL,
            "void": TSTypeKind.VOID, "unit": TSTypeKind.VOID,
            "null": TSTypeKind.NULL, "nil": TSTypeKind.NULL, "none": TSTypeKind.NULL,
            "any": TSTypeKind.ANY, "object": TSTypeKind.OBJECT,
            "array": TSTypeKind.ARRAY, "list": TSTypeKind.ARRAY,
            "map": TSTypeKind.MAP, "dict": TSTypeKind.MAP, "hash": TSTypeKind.MAP,
        }
        
        for key, kind in type_map.items():
            if key in type_text:
                return TSType(kind)
        
        # Assume it's a class/interface type
        return TSType(TSTypeKind.CLASS, name=self._get_text(node))
    
    def _infer_type(self, node: Node) -> TSType:
        """Infer type from expression."""
        if not node:
            return TSType(TSTypeKind.UNKNOWN)
        
        node_type = node.type
        
        # Literals
        if node_type in ("number", "integer_literal", "float_literal"):
            return TSType(TSTypeKind.INT if "." not in self._get_text(node) else TSTypeKind.FLOAT)
        elif node_type in ("string", "string_literal", "template_string"):
            return TSType(TSTypeKind.STRING)
        elif node_type in ("true", "false", "boolean"):
            return TSType(TSTypeKind.BOOL)
        elif node_type in ("null", "nil", "none"):
            return TSType(TSTypeKind.NULL)
        elif node_type in ("array", "array_creation_expression", "list_literal"):
            return TSType(TSTypeKind.ARRAY)
        elif node_type in ("object", "hash", "map_literal"):
            return TSType(TSTypeKind.OBJECT)
        
        # Identifier - look up in scope
        elif node_type == "identifier":
            var_name = self._get_text(node)
            return self.current_scope.get_type(var_name)
        
        return TSType(TSTypeKind.UNKNOWN)
    
    def _uses_params(self, node: Node) -> bool:
        """Check if expression uses parameter-influenced variables."""
        if not node:
            return False
        
        def check(n: Node) -> bool:
            if n.type == "identifier":
                name = self._get_text(n)
                if name in self.param_influenced:
                    return True
                if self.current_scope.is_param_influenced(name):
                    return True
            
            for child in n.children:
                if check(child):
                    return True
            return False
        
        return check(node)
    
    def _get_text(self, node: Node) -> str:
        """Get text content of a node."""
        return self.source_bytes[node.start_byte:node.end_byte].decode("utf-8")
    
    def get_param_influenced_vars(self) -> Set[str]:
        """Get all parameter-influenced variables."""
        return self.param_influenced.copy()
    
    def get_var_type(self, name: str) -> TSType:
        """Get type of a variable."""
        return self.var_types.get(name, TSType(TSTypeKind.UNKNOWN))
    
    def resolve_method_call(self, call_name: str) -> Optional[str]:
        """Resolve instance.method() to ClassName.method."""
        if "." not in call_name:
            return None
        
        parts = call_name.split(".", 1)
        if len(parts) != 2:
            return None
        
        instance_name, method_name = parts
        class_name = self.instance_to_class.get(instance_name)
        if class_name:
            return f"{class_name}.{method_name}"
        
        return None
    
    def get_instance_mappings(self) -> Dict[str, str]:
        """Get instance to class mappings."""
        return self.instance_to_class.copy()
