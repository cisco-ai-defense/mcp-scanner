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

"""Base parser interface for language-specific parsers.

This module defines the abstract base class for all language parsers
in the static analysis engine, following SAST tool conventions.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from ..types import Position, Range


class BaseParser(ABC):
    """Base class for language-specific source code parsers.
    
    This follows the parser abstraction pattern used in tools like
    Semgrep, where each language has its own parser implementation.
    """

    def __init__(self, file_path: Path, source_code: str) -> None:
        """Initialize parser.

        Args:
            file_path: Path to the source file
            source_code: Source code content
        """
        self.file_path = file_path
        self.source_code = source_code
        self.lines = source_code.split("\n")
        self._ast: Any = None

    @abstractmethod
    def parse(self) -> Any:
        """Parse source code and return AST.

        Returns:
            AST representation
        """
        pass

    @abstractmethod
    def get_node_range(self, node: Any) -> Range:
        """Get source range for an AST node.

        Args:
            node: AST node

        Returns:
            Source range
        """
        pass

    @abstractmethod
    def get_node_text(self, node: Any) -> str:
        """Get source text for an AST node.

        Args:
            node: AST node

        Returns:
            Source code text
        """
        pass

    @abstractmethod
    def walk(self, node: Any | None = None) -> list[Any]:
        """Walk AST and return all nodes.

        Args:
            node: Starting node (None for root)

        Returns:
            List of all nodes
        """
        pass

    def get_ast(self) -> Any:
        """Get parsed AST, parsing if necessary.

        Returns:
            AST representation
        """
        if self._ast is None:
            self._ast = self.parse()
        
        if hasattr(self._ast, 'root_node'):
            return self._ast.root_node
        
        return self._ast

    def offset_to_position(self, offset: int) -> Position:
        """Convert byte offset to line/column position.

        Args:
            offset: Byte offset

        Returns:
            Position object
        """
        line = 0
        col = 0
        current_offset = 0

        for line_num, line_text in enumerate(self.lines):
            line_len = len(line_text) + 1
            if current_offset + line_len > offset:
                col = offset - current_offset
                line = line_num + 1
                break
            current_offset += line_len
        else:
            line = len(self.lines)
            col = len(self.lines[-1]) if self.lines else 0

        return Position(line=line, column=col, offset=offset)
