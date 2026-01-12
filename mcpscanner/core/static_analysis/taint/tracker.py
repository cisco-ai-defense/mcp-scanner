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

"""Shape-based taint tracking for objects and arrays."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TaintStatus(Enum):
    """Taint status.
    
    Note: UNKNOWN is currently unused but reserved for future use cases where
    taint status cannot be determined (e.g., external function calls, complex
    control flow). The current implementation uses a binary taint model
    (TAINTED/UNTAINTED) which is sufficient for MCP parameter tracking.
    """
    TAINTED = "tainted"
    UNTAINTED = "untainted"
    UNKNOWN = "unknown"  # Reserved for future use


@dataclass
class SourceTrace:
    """Trace of a taint source."""
    source_pattern: str
    call_site: Any
    labels: set[str] = field(default_factory=set)


@dataclass
class Taint:
    """Taint information with labels and sources."""
    status: TaintStatus = TaintStatus.UNTAINTED
    labels: set[str] = field(default_factory=set)
    sources: list[SourceTrace] = field(default_factory=list)
    
    def is_tainted(self) -> bool:
        """Check if tainted."""
        return self.status == TaintStatus.TAINTED
    
    def add_label(self, label: str) -> None:
        """Add a taint label."""
        self.labels.add(label)
    
    def remove_label(self, label: str) -> None:
        """Remove a taint label."""
        self.labels.discard(label)
    
    def has_label(self, label: str) -> bool:
        """Check if has a specific label."""
        return label in self.labels
    
    def merge(self, other: "Taint") -> "Taint":
        """Merge two taints."""
        if not self.is_tainted() and not other.is_tainted():
            return Taint(status=TaintStatus.UNTAINTED)
        
        return Taint(
            status=TaintStatus.TAINTED,
            labels=self.labels | other.labels,
            sources=self.sources + other.sources,
        )
    
    def copy(self) -> "Taint":
        """Create a copy."""
        return Taint(
            status=self.status,
            labels=self.labels.copy(),
            sources=self.sources.copy(),
        )


class TaintShape:
    """Represents the shape of tainted data structures with bounded depth."""
    
    MAX_DEPTH = 3  # Cap nesting depth to prevent explosion
    
    def __init__(self, taint: Taint | None = None, depth: int = 0):
        """Initialize taint shape.
        
        Args:
            taint: Base taint for scalar values
            depth: Current nesting depth (for bounding)
        """
        self.scalar_taint = taint or Taint()
        self.fields: dict[str, TaintShape] = {}
        self.element_shape: TaintShape | None = None
        self.is_object = False
        self.is_array = False
        self.depth = depth
        self.collapsed = depth >= self.MAX_DEPTH  # Collapse at max depth
    
    def get_taint(self) -> Taint:
        """Get the taint of this shape."""
        return self.scalar_taint
    
    def set_taint(self, taint: Taint) -> None:
        """Set the taint of this shape."""
        self.scalar_taint = taint
    
    def get_field(self, field: str) -> Taint:
        """Get taint of a specific field.
        
        Args:
            field: Field name
            
        Returns:
            Taint of the field
        """
        if self.scalar_taint.is_tainted():
            return self.scalar_taint
        
        if field in self.fields:
            return self.fields[field].get_taint()
        
        return Taint(status=TaintStatus.UNTAINTED)
    
    def set_field(self, field: str, taint: Taint) -> None:
        """Set taint of a specific field.
        
        Args:
            field: Field name
            taint: Taint to set
        """
        # If collapsed, just merge taint into scalar (summary node)
        if self.collapsed:
            self.scalar_taint = self.scalar_taint.merge(taint)
            return
        
        self.is_object = True
        
        if field not in self.fields:
            self.fields[field] = TaintShape(depth=self.depth + 1)
        
        self.fields[field].set_taint(taint)
    
    def get_element(self) -> Taint:
        """Get taint of array elements.
        
        Returns:
            Taint of elements
        """
        if self.scalar_taint.is_tainted():
            return self.scalar_taint
        
        if self.element_shape:
            return self.element_shape.get_taint()
        
        return Taint(status=TaintStatus.UNTAINTED)
    
    def set_element(self, taint: Taint) -> None:
        """Set taint of array elements.
        
        Args:
            taint: Taint to set
        """
        # If collapsed, just merge taint into scalar (summary node)
        if self.collapsed:
            self.scalar_taint = self.scalar_taint.merge(taint)
            return
        
        self.is_array = True
        
        if not self.element_shape:
            self.element_shape = TaintShape(depth=self.depth + 1)
        
        self.element_shape.set_taint(taint)
    
    def merge(self, other: "TaintShape") -> "TaintShape":
        """Merge two taint shapes.
        
        Args:
            other: Other shape to merge
            
        Returns:
            Merged shape
        """
        # Preserve the maximum depth and collapsed state from either input
        max_depth = max(self.depth, other.depth)
        result = TaintShape(depth=max_depth)
        result.collapsed = self.collapsed or other.collapsed
        
        result.scalar_taint = self.scalar_taint.merge(other.scalar_taint)
        
        all_fields = set(self.fields.keys()) | set(other.fields.keys())
        for field in all_fields:
            self_field = self.fields.get(field, TaintShape(depth=max_depth))
            other_field = other.fields.get(field, TaintShape(depth=max_depth))
            result.fields[field] = self_field.merge(other_field)
        
        if self.element_shape or other.element_shape:
            self_elem = self.element_shape or TaintShape(depth=max_depth)
            other_elem = other.element_shape or TaintShape(depth=max_depth)
            result.element_shape = self_elem.merge(other_elem)
        
        result.is_object = self.is_object or other.is_object
        result.is_array = self.is_array or other.is_array
        
        return result
    
    def copy(self) -> "TaintShape":
        """Create a deep copy."""
        result = TaintShape(self.scalar_taint.copy(), depth=self.depth)
        result.is_object = self.is_object
        result.is_array = self.is_array
        result.collapsed = self.collapsed
        
        for field, shape in self.fields.items():
            result.fields[field] = shape.copy()
        
        if self.element_shape:
            result.element_shape = self.element_shape.copy()
        
        return result
    
    def __eq__(self, other: object) -> bool:
        """Check equality including structural differences.
        
        Compares taint status, labels, structure (object/array), and per-field taints.
        """
        if not isinstance(other, TaintShape):
            return False
        
        # Check basic properties
        if (self.is_object != other.is_object or 
            self.is_array != other.is_array or
            self.collapsed != other.collapsed or
            self.depth != other.depth):
            return False
        
        # Check scalar taint (status and labels)
        if (self.scalar_taint.status != other.scalar_taint.status or
            self.scalar_taint.labels != other.scalar_taint.labels):
            return False
        
        # Check fields for objects
        if self.fields.keys() != other.fields.keys():
            return False
        
        for field in self.fields:
            if self.fields[field] != other.fields[field]:
                return False
        
        # Check element shape for arrays
        if (self.element_shape is None) != (other.element_shape is None):
            return False
        
        if self.element_shape and self.element_shape != other.element_shape:
            return False
        
        return True
    
    def __repr__(self) -> str:
        """String representation."""
        if self.is_object:
            fields_str = ", ".join(f"{k}: {v.get_taint().status.value}" 
                                  for k, v in self.fields.items())
            return f"Object({{{fields_str}}})"
        elif self.is_array:
            elem_taint = self.element_shape.get_taint() if self.element_shape else Taint()
            return f"Array({elem_taint.status.value})"
        else:
            return f"Scalar({self.scalar_taint.status.value})"


class ShapeEnvironment:
    """Environment mapping variables to their taint shapes."""
    
    def __init__(self):
        """Initialize empty environment."""
        self.shapes: dict[str, TaintShape] = {}
    
    def get(self, var: str) -> TaintShape:
        """Get shape for a variable.
        
        Args:
            var: Variable name
            
        Returns:
            Taint shape
        """
        return self.shapes.get(var, TaintShape())
    
    def set(self, var: str, shape: TaintShape) -> None:
        """Set shape for a variable.
        
        Args:
            var: Variable name
            shape: Taint shape
        """
        self.shapes[var] = shape
    
    def set_taint(self, var: str, taint: Taint) -> None:
        """Set taint for a variable (scalar).
        
        Args:
            var: Variable name
            taint: Taint
        """
        shape = TaintShape(taint)
        self.shapes[var] = shape
    
    def get_taint(self, var: str) -> Taint:
        """Get taint for a variable.
        
        Args:
            var: Variable name
            
        Returns:
            Taint
        """
        return self.get(var).get_taint()
    
    def merge(self, other: "ShapeEnvironment") -> "ShapeEnvironment":
        """Merge two environments.
        
        Args:
            other: Other environment
            
        Returns:
            Merged environment
        """
        result = ShapeEnvironment()
        
        all_vars = set(self.shapes.keys()) | set(other.shapes.keys())
        for var in all_vars:
            self_shape = self.get(var)
            other_shape = other.get(var)
            result.set(var, self_shape.merge(other_shape))
        
        return result
    
    def copy(self) -> "ShapeEnvironment":
        """Create a deep copy."""
        result = ShapeEnvironment()
        for var, shape in self.shapes.items():
            result.set(var, shape.copy())
        return result
    
    def __eq__(self, other: object) -> bool:
        """Check equality including structural differences.
        
        Uses TaintShape's __eq__ which checks labels and per-field taints.
        """
        if not isinstance(other, ShapeEnvironment):
            return False
        
        if set(self.shapes.keys()) != set(other.shapes.keys()):
            return False
        
        for var in self.shapes:
            # Use TaintShape's __eq__ for proper structural comparison
            if self.shapes[var] != other.shapes[var]:
                return False
        
        return True
