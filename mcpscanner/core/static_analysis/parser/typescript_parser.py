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

"""TypeScript parser using tree-sitter."""

from pathlib import Path
from typing import Any, List, Optional

try:
    from tree_sitter import Language, Parser, Node
    import tree_sitter_typescript
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    Node = Any

from .javascript_parser import JavaScriptParser


class TypeScriptParser(JavaScriptParser):
    """Parser for TypeScript using tree-sitter.
    
    Extends JavaScriptParser since TypeScript is a superset of JavaScript.
    """
    
    def __init__(self, file_path: Path, source_code: str):
        """Initialize TypeScript parser.
        
        Args:
            file_path: Path to source file
            source_code: TypeScript source code
            
        Raises:
            ImportError: If tree-sitter is not available
        """
        if not TREE_SITTER_AVAILABLE:
            raise ImportError(
                "tree-sitter and tree-sitter-typescript are required for TypeScript parsing. "
                "Install with: pip install tree-sitter tree-sitter-typescript"
            )
        
        # Don't call super().__init__ to avoid setting JS language
        self.file_path = file_path
        self.source_code = source_code
        self._ast = None
        
        # Set up TypeScript parser
        # tree-sitter 0.21+ wraps language in Language class
        ts_language = Language(tree_sitter_typescript.language_typescript())
        self.parser = Parser(ts_language)
        self._tree = None
    
    def find_functions(self, node: Node | None = None) -> List[Node]:
        """Find all function definitions including TS-specific ones.
        
        Args:
            node: Starting node (uses root if None)
            
        Returns:
            List of function nodes
        """
        if node is None:
            if self._tree is None:
                self.parse()
            node = self._tree.root_node
        
        functions = []
        for n in self.walk(node):
            if n.type in [
                'function_declaration',
                'function',
                'arrow_function',
                'method_definition',
                'generator_function_declaration',
                'function_signature',  # TS interface method
                'method_signature',    # TS interface method
            ]:
                functions.append(n)
        
        return functions
    
    def get_type_annotation(self, node: Node) -> Optional[str]:
        """Extract TypeScript type annotation from a node.
        
        Args:
            node: Node to extract type from
            
        Returns:
            Type annotation string or None
        """
        type_annotation = node.child_by_field_name('type')
        if type_annotation:
            return self.get_node_text(type_annotation)
        return None
    
    def get_function_return_type(self, node: Node) -> Optional[str]:
        """Extract return type annotation from a function.
        
        Args:
            node: Function node
            
        Returns:
            Return type string or None
        """
        return_type = node.child_by_field_name('return_type')
        if return_type:
            # Return type includes the colon, extract just the type
            type_node = return_type.named_children[0] if return_type.named_children else return_type
            return self.get_node_text(type_node)
        return None
    
    def get_function_parameters_with_types(self, node: Node) -> List[dict]:
        """Extract parameter names and types from a function node.
        
        Args:
            node: Function node
            
        Returns:
            List of dicts with 'name' and 'type' keys
        """
        params = []
        params_node = node.child_by_field_name('parameters')
        
        if params_node:
            for child in params_node.named_children:
                param_info = {}
                
                if child.type == 'required_parameter':
                    # TypeScript typed parameter
                    pattern = child.child_by_field_name('pattern')
                    
                    if pattern and pattern.type == 'identifier':
                        param_info['name'] = self.get_node_text(pattern)
                        type_annotation = child.child_by_field_name('type')
                        if type_annotation:
                            param_info['type'] = self.get_node_text(type_annotation)
                        params.append(param_info)
                    
                    elif pattern and pattern.type == 'object_pattern':
                        # Destructured parameter with type: { a, b }: { a: string, b: string }
                        for prop in pattern.named_children:
                            if prop.type == 'shorthand_property_identifier_pattern':
                                param_info = {'name': self.get_node_text(prop)}
                                params.append(param_info)
                            elif prop.type == 'pair_pattern':
                                value = prop.child_by_field_name('value')
                                if value and value.type == 'identifier':
                                    param_info = {'name': self.get_node_text(value)}
                                    params.append(param_info)
                
                elif child.type == 'optional_parameter':
                    # Optional parameter (param?)
                    pattern = child.child_by_field_name('pattern')
                    if pattern and pattern.type == 'identifier':
                        param_info['name'] = self.get_node_text(pattern) + '?'
                    
                    type_annotation = child.child_by_field_name('type')
                    if type_annotation:
                        param_info['type'] = self.get_node_text(type_annotation)
                    
                    params.append(param_info)
                
                elif child.type == 'identifier':
                    # Untyped parameter
                    param_info['name'] = self.get_node_text(child)
                    params.append(param_info)
                
                elif child.type == 'object_pattern':
                    # Destructured parameter: { a, b }
                    for prop in child.named_children:
                        if prop.type == 'shorthand_property_identifier_pattern':
                            param_info = {'name': self.get_node_text(prop)}
                            params.append(param_info)
                        elif prop.type == 'pair_pattern':
                            # { key: value } pattern
                            value = prop.child_by_field_name('value')
                            if value and value.type == 'identifier':
                                param_info = {'name': self.get_node_text(value)}
                                params.append(param_info)
                
                elif child.type == 'rest_pattern':
                    # Rest parameter (...args)
                    identifier = child.child(1)  # Skip the '...'
                    if identifier:
                        param_info['name'] = f"...{self.get_node_text(identifier)}"
                    
                    type_annotation = child.child_by_field_name('type')
                    if type_annotation:
                        param_info['type'] = self.get_node_text(type_annotation)
                    
                    params.append(param_info)
        
        return params
    
    def find_interfaces(self, node: Node | None = None) -> List[Node]:
        """Find all interface declarations.
        
        Args:
            node: Starting node (uses root if None)
            
        Returns:
            List of interface nodes
        """
        if node is None:
            if self._tree is None:
                self.parse()
            node = self._tree.root_node
        
        interfaces = []
        for n in self.walk(node):
            if n.type == 'interface_declaration':
                interfaces.append(n)
        
        return interfaces
    
    def find_type_aliases(self, node: Node | None = None) -> List[Node]:
        """Find all type alias declarations.
        
        Args:
            node: Starting node (uses root if None)
            
        Returns:
            List of type alias nodes
        """
        if node is None:
            if self._tree is None:
                self.parse()
            node = self._tree.root_node
        
        type_aliases = []
        for n in self.walk(node):
            if n.type == 'type_alias_declaration':
                type_aliases.append(n)
        
        return type_aliases
    
    def find_decorators(self, node: Node) -> List[Node]:
        """Find all decorators on a node.
        
        Args:
            node: Node to search for decorators
            
        Returns:
            List of decorator nodes
        """
        decorators = []
        for child in node.children:
            if child.type == 'decorator':
                decorators.append(child)
        return decorators
    
    def extract_tsdoc(self, node: Node) -> Optional[str]:
        """Extract TSDoc comment for a function.
        
        TSDoc is similar to JSDoc but with TypeScript-specific features.
        
        Args:
            node: Function node
            
        Returns:
            TSDoc text or None
        """
        # TSDoc uses same comment format as JSDoc
        return self.extract_jsdoc(node)


class TSXParser(TypeScriptParser):
    """Parser for TSX (TypeScript + JSX) files.
    
    Extends TypeScriptParser to handle JSX syntax.
    """
    
    def __init__(self, file_path: Path, source_code: str):
        """Initialize TSX parser.
        
        Args:
            file_path: Path to source file
            source_code: TSX source code
            
        Raises:
            ImportError: If tree-sitter is not available
        """
        if not TREE_SITTER_AVAILABLE:
            raise ImportError(
                "tree-sitter and tree-sitter-typescript are required for TSX parsing. "
                "Install with: pip install tree-sitter tree-sitter-typescript"
            )
        
        # Don't call super().__init__ to avoid setting TS language
        self.file_path = file_path
        self.source_code = source_code
        self._ast = None
        
        # Set up TSX parser
        # tree-sitter 0.21+ wraps language in Language class
        tsx_language = Language(tree_sitter_typescript.language_tsx())
        self.parser = Parser(tsx_language)
        self._tree = None
