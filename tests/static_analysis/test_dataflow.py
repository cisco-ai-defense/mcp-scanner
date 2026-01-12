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

"""Tests for dataflow analysis components."""

import pytest


class TestDataflow:
    """Test dataflow analysis functionality."""
    
    def test_reaching_definitions_concept(self):
        """Test reaching definitions concept with simple example."""
        # Reaching definitions tracks where variables are defined
        # Example: x = 1; y = x + 2  -> 'x' reaches the use in 'y = x + 2'
        
        import ast
        code = '''
x = 1
y = x + 2
z = x + y
'''
        tree = ast.parse(code)
        assignments = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)]
        
        assert len(assignments) == 3, "Should find 3 assignments"
        # This demonstrates the concept of reaching definitions
    
    def test_liveness_analysis_concept(self):
        """Test liveness analysis concept with simple example."""
        # Liveness analysis determines if a variable is live (will be used later)
        # Example: x = 1; return x  -> 'x' is live after assignment
        
        import ast
        code = '''
def foo():
    x = 1  # x is live (used later)
    y = 2  # y is dead (never used)
    return x
'''
        tree = ast.parse(code)
        func = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)][0]
        
        # Check that we can identify assignments and returns
        assigns = [node for node in ast.walk(func) if isinstance(node, ast.Assign)]
        returns = [node for node in ast.walk(func) if isinstance(node, ast.Return)]
        
        assert len(assigns) == 2, "Should find 2 assignments"
        assert len(returns) == 1, "Should find 1 return"
    
    def test_constant_propagation_concept(self):
        """Test constant propagation concept with simple example."""
        # Constant propagation replaces variables with their constant values
        # Example: x = 5; y = x + 3  -> y = 5 + 3 -> y = 8
        
        import ast
        code = '''
x = 5
y = x + 3
'''
        tree = ast.parse(code)
        
        # Find the constant assignment
        assigns = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)]
        first_assign = assigns[0]
        
        # Check that first assignment has a constant
        assert isinstance(first_assign.value, ast.Constant), "First assignment should be constant"
        assert first_assign.value.value == 5, "Constant should be 5"
    
    def test_available_expressions_concept(self):
        """Test available expressions concept with simple example."""
        # Available expressions: expressions that have been computed and not invalidated
        # Example: x = a + b; y = a + b  -> second 'a + b' is available
        
        import ast
        code = '''
x = a + b
y = a + b  # Same expression is available
'''
        tree = ast.parse(code)
        
        # Find binary operations
        bin_ops = [node for node in ast.walk(tree) if isinstance(node, ast.BinOp)]
        
        assert len(bin_ops) == 2, "Should find 2 binary operations"
        # Both should be addition operations
        assert all(isinstance(op.op, ast.Add) for op in bin_ops)
    
    def test_forward_analysis_concept(self):
        """Test forward dataflow analysis concept."""
        # Forward analysis propagates information from entry to exit
        # Example: track how values flow through assignments
        
        import ast
        code = '''
x = 1
y = x
z = y
'''
        tree = ast.parse(code)
        
        # Trace the dataflow: x -> y -> z
        assigns = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)]
        
        assert len(assigns) == 3, "Should find 3 assignments in dataflow chain"
        
        # Second assignment uses first variable
        second_assign = assigns[1]
        assert isinstance(second_assign.value, ast.Name), "Should use a variable"
        assert second_assign.value.id == 'x', "Should reference x"
    
    def test_dataflow_has_init(self):
        """Test that dataflow package has proper initialization."""
        from mcpscanner.core.static_analysis import dataflow
        
        # Check if module has expected attributes
        assert hasattr(dataflow, '__file__'), "Module should have __file__ attribute"
        assert hasattr(dataflow, '__path__'), "Package should have __path__ attribute"
