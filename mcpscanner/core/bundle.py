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

"""
MCP Bundle (.mcpb) Support Module.

This module provides functionality to load, validate, and extract MCP server bundles
in the MCPB format - a ZIP-based package format for MCP servers using the DXT manifest schema.

Supports the official DXT manifest schema (manifest_version 0.3).

Bundle Structure:
    bundle.mcpb (ZIP file)
    ├── manifest.json         # Required: DXT manifest (schema v0.3)
    ├── server/               # Server files (based on entry_point)
    │   ├── main.py           # Main entry point
    │   └── utils.py          # Additional modules
    ├── lib/                  # Bundled Python packages
    └── icon.png              # Optional: Bundle icon
"""

import json
import os
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field


class ServerType(str, Enum):
    """Server runtime type."""
    PYTHON = "python"
    NODE = "node"
    BINARY = "binary"


class Platform(str, Enum):
    """Supported platforms."""
    DARWIN = "darwin"
    WIN32 = "win32"
    LINUX = "linux"


class UserConfigType(str, Enum):
    """User configuration field types."""
    STRING = "string"
    NUMBER = "number"
    BOOLEAN = "boolean"
    DIRECTORY = "directory"
    FILE = "file"


class Author(BaseModel):
    """Author information."""
    model_config = ConfigDict(extra="forbid")
    
    name: str
    email: Optional[str] = None
    url: Optional[str] = None


class Repository(BaseModel):
    """Repository information."""
    model_config = ConfigDict(extra="forbid")
    
    type: str
    url: str


class Icon(BaseModel):
    """Icon definition with size and optional theme."""
    model_config = ConfigDict(extra="forbid")
    
    src: str
    size: str = Field(..., pattern=r"^\d+x\d+$")
    theme: Optional[str] = None


class Localization(BaseModel):
    """Localization configuration."""
    model_config = ConfigDict(extra="forbid")
    
    resources: str = Field(..., pattern=r"\$\{locale\}")
    default_locale: str = Field(..., pattern=r"^[A-Za-z0-9]{2,8}(?:-[A-Za-z0-9]{1,8})*$")


class MCPConfig(BaseModel):
    """MCP server configuration for stdio execution."""
    model_config = ConfigDict(extra="forbid")
    
    command: str
    args: List[str] = Field(default_factory=list)
    env: Dict[str, str] = Field(default_factory=dict)
    platform_overrides: Optional[Dict[str, Any]] = None


class Server(BaseModel):
    """Server configuration."""
    model_config = ConfigDict(extra="forbid")
    
    type: ServerType
    entry_point: str
    mcp_config: MCPConfig


class Tool(BaseModel):
    """Tool definition."""
    model_config = ConfigDict(extra="forbid")
    
    name: str
    description: Optional[str] = None


class Prompt(BaseModel):
    """Prompt definition."""
    model_config = ConfigDict(extra="forbid")
    
    name: str
    text: str
    description: Optional[str] = None
    arguments: List[str] = Field(default_factory=list)


class Runtimes(BaseModel):
    """Runtime version requirements."""
    model_config = ConfigDict(extra="forbid")
    
    python: Optional[str] = None
    node: Optional[str] = None


class Compatibility(BaseModel):
    """Compatibility requirements."""
    model_config = ConfigDict(extra="forbid")
    
    claude_desktop: Optional[str] = None
    platforms: List[Platform] = Field(default_factory=list)
    runtimes: Optional[Runtimes] = None


class UserConfigField(BaseModel):
    """User configuration field definition."""
    model_config = ConfigDict(extra="forbid")
    
    type: UserConfigType
    title: str
    description: str
    required: Optional[bool] = None
    default: Optional[Union[str, int, float, bool, List[str]]] = None
    multiple: Optional[bool] = None
    sensitive: Optional[bool] = None
    min: Optional[float] = None
    max: Optional[float] = None


class BundleManifest(BaseModel):
    """
    DXT Manifest schema for MCP bundles (manifest_version 0.3).
    
    Based on the official Desktop Extension manifest format.
    """
    
    # Required fields
    name: str = Field(..., description="Extension identifier")
    version: str = Field(..., description="Extension version (semver)")
    description: str = Field(..., description="Short description")
    author: Author = Field(..., description="Author information")
    server: Server = Field(..., description="Server configuration")
    
    # Schema and version
    schema_: Optional[str] = Field(None, alias="$schema")
    dxt_version: Optional[str] = Field(None, description="Deprecated: Use manifest_version")
    manifest_version: Optional[Literal["0.3"]] = None
    
    # Display information
    display_name: Optional[str] = Field(None, description="Human-readable name")
    long_description: Optional[str] = Field(None, description="Detailed description")
    
    # Links
    repository: Optional[Repository] = None
    homepage: Optional[str] = None
    documentation: Optional[str] = None
    support: Optional[str] = None
    
    # Icons and media
    icon: Optional[str] = None
    icons: List[Icon] = Field(default_factory=list)
    screenshots: List[str] = Field(default_factory=list)
    
    # Localization
    localization: Optional[Localization] = None
    
    # MCP capabilities
    tools: List[Tool] = Field(default_factory=list)
    tools_generated: Optional[bool] = None
    prompts: List[Prompt] = Field(default_factory=list)
    prompts_generated: Optional[bool] = None
    
    # Metadata
    keywords: List[str] = Field(default_factory=list)
    license: Optional[str] = None
    privacy_policies: List[str] = Field(default_factory=list)
    
    # Compatibility
    compatibility: Optional[Compatibility] = None
    
    # User configuration
    user_config: Dict[str, UserConfigField] = Field(default_factory=dict)
    
    # Extension metadata
    _meta: Optional[Dict[str, Dict[str, Any]]] = Field(None, alias="_meta")

    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    
    @property
    def entry_point(self) -> str:
        """Get the server entry point."""
        return self.server.entry_point
    
    @property
    def server_type(self) -> ServerType:
        """Get the server type."""
        return self.server.type
    
    @property
    def tool_names(self) -> List[str]:
        """Get list of tool names."""
        return [t.name for t in self.tools]
    
    @property
    def prompt_names(self) -> List[str]:
        """Get list of prompt names."""
        return [p.name for p in self.prompts]


@dataclass
class BundleInfo:
    """Information about an extracted bundle."""
    
    manifest: BundleManifest
    bundle_path: Path
    extract_dir: Path
    server_dir: Path
    entry_point_path: Path
    lib_dir: Optional[Path] = None
    requirements_path: Optional[Path] = None
    icon_path: Optional[Path] = None
    python_files: List[Path] = field(default_factory=list)
    
    @property
    def name(self) -> str:
        return self.manifest.name
    
    @property
    def version(self) -> str:
        return self.manifest.version


class BundleError(Exception):
    """Base exception for bundle-related errors."""
    pass


class BundleValidationError(BundleError):
    """Raised when bundle validation fails."""
    pass


class BundleExtractionError(BundleError):
    """Raised when bundle extraction fails."""
    pass


class MCPBundleLoader:
    """
    Loader for MCP server bundles (.mcpb files).
    
    Handles extraction, validation, and provides access to bundle contents
    for security scanning.
    """
    
    MANIFEST_FILENAME = "manifest.json"
    SERVER_DIR = "server"
    LIB_DIR = "lib"
    REQUIREMENTS_FILE = "requirements.txt"
    ICON_FILE = "icon.png"
    
    def __init__(self, bundle_path: Union[str, Path]):
        """
        Initialize the bundle loader.
        
        Args:
            bundle_path: Path to the .mcpb bundle file
        """
        self.bundle_path = Path(bundle_path)
        self._temp_dir: Optional[tempfile.TemporaryDirectory] = None
        self._bundle_info: Optional[BundleInfo] = None
        
    def __enter__(self) -> 'MCPBundleLoader':
        """Context manager entry - extracts the bundle."""
        self.extract()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleans up temporary files."""
        self.cleanup()
        return False
    
    def validate_bundle_file(self) -> None:
        """
        Validate that the bundle file exists and is a valid ZIP.
        
        Raises:
            BundleValidationError: If validation fails
        """
        if not self.bundle_path.exists():
            raise BundleValidationError(f"Bundle file not found: {self.bundle_path}")
        
        if not self.bundle_path.is_file():
            raise BundleValidationError(f"Bundle path is not a file: {self.bundle_path}")
        
        if not zipfile.is_zipfile(self.bundle_path):
            raise BundleValidationError(
                f"Bundle is not a valid ZIP file: {self.bundle_path}"
            )
    
    def extract(self, target_dir: Optional[Union[str, Path]] = None) -> BundleInfo:
        """
        Extract the bundle to a temporary or specified directory.
        
        Args:
            target_dir: Optional target directory. If None, uses a temp directory.
            
        Returns:
            BundleInfo with details about the extracted bundle
            
        Raises:
            BundleValidationError: If bundle validation fails
            BundleExtractionError: If extraction fails
        """
        self.validate_bundle_file()
        
        if target_dir:
            extract_path = Path(target_dir)
            extract_path.mkdir(parents=True, exist_ok=True)
        else:
            self._temp_dir = tempfile.TemporaryDirectory(prefix="mcpb_")
            extract_path = Path(self._temp_dir.name)
        
        try:
            with zipfile.ZipFile(self.bundle_path, 'r') as zf:
                zf.extractall(extract_path)
        except zipfile.BadZipFile as e:
            raise BundleExtractionError(f"Failed to extract bundle: {e}")
        except Exception as e:
            raise BundleExtractionError(f"Extraction error: {e}")
        
        self._bundle_info = self._parse_extracted_bundle(extract_path)
        return self._bundle_info
    
    def _parse_extracted_bundle(self, extract_path: Path) -> BundleInfo:
        """
        Parse and validate the extracted bundle contents.
        
        Args:
            extract_path: Path to extracted bundle directory
            
        Returns:
            BundleInfo with parsed bundle details
            
        Raises:
            BundleValidationError: If required files are missing or invalid
        """
        manifest_path = extract_path / self.MANIFEST_FILENAME
        if not manifest_path.exists():
            raise BundleValidationError(
                f"Missing required {self.MANIFEST_FILENAME} in bundle"
            )
        
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                manifest_data = json.load(f)
        except json.JSONDecodeError as e:
            raise BundleValidationError(f"Invalid manifest JSON: {e}")
        
        try:
            manifest = BundleManifest(**manifest_data)
        except Exception as e:
            raise BundleValidationError(f"Invalid manifest schema: {e}")
        
        server_dir = extract_path / self.SERVER_DIR
        if not server_dir.exists():
            server_dir = extract_path
        
        entry_point_path = extract_path / manifest.entry_point
        if not entry_point_path.exists():
            alt_entry = server_dir / "main.py"
            if alt_entry.exists():
                entry_point_path = alt_entry
            else:
                raise BundleValidationError(
                    f"Entry point not found: {manifest.entry_point}"
                )
        
        lib_dir = extract_path / self.LIB_DIR
        lib_dir = lib_dir if lib_dir.exists() else None
        
        requirements_path = extract_path / self.REQUIREMENTS_FILE
        requirements_path = requirements_path if requirements_path.exists() else None
        
        icon_path = extract_path / self.ICON_FILE
        icon_path = icon_path if icon_path.exists() else None
        
        python_files = self._find_python_files(extract_path)
        
        return BundleInfo(
            manifest=manifest,
            bundle_path=self.bundle_path,
            extract_dir=extract_path,
            server_dir=server_dir,
            entry_point_path=entry_point_path,
            lib_dir=lib_dir,
            requirements_path=requirements_path,
            icon_path=icon_path,
            python_files=python_files,
        )
    
    def _find_python_files(self, root_dir: Path) -> List[Path]:
        """
        Find all Python files in the bundle.
        
        Args:
            root_dir: Root directory to search
            
        Returns:
            List of paths to Python files
        """
        python_files = []
        for path in root_dir.rglob("*.py"):
            if "__pycache__" not in str(path):
                python_files.append(path)
        return sorted(python_files)
    
    @property
    def info(self) -> Optional[BundleInfo]:
        """Get the bundle info if extracted."""
        return self._bundle_info
    
    def get_server_source_path(self) -> Path:
        """
        Get the path to the server source directory for scanning.
        
        Returns:
            Path to the server directory
            
        Raises:
            BundleError: If bundle hasn't been extracted
        """
        if not self._bundle_info:
            raise BundleError("Bundle not extracted. Call extract() first.")
        return self._bundle_info.server_dir
    
    def get_all_python_files(self) -> List[Path]:
        """
        Get all Python files in the bundle for scanning.
        
        Returns:
            List of paths to Python files
            
        Raises:
            BundleError: If bundle hasn't been extracted
        """
        if not self._bundle_info:
            raise BundleError("Bundle not extracted. Call extract() first.")
        return self._bundle_info.python_files
    
    def get_entry_point(self) -> Path:
        """
        Get the main entry point file.
        
        Returns:
            Path to the entry point Python file
            
        Raises:
            BundleError: If bundle hasn't been extracted
        """
        if not self._bundle_info:
            raise BundleError("Bundle not extracted. Call extract() first.")
        return self._bundle_info.entry_point_path
    
    def cleanup(self) -> None:
        """Clean up temporary extraction directory."""
        if self._temp_dir:
            try:
                self._temp_dir.cleanup()
            except Exception:
                pass
            self._temp_dir = None
        self._bundle_info = None


def load_bundle(bundle_path: Union[str, Path]) -> MCPBundleLoader:
    """
    Convenience function to create a bundle loader.
    
    Args:
        bundle_path: Path to the .mcpb bundle file
        
    Returns:
        MCPBundleLoader instance
        
    Example:
        with load_bundle("server.mcpb") as bundle:
            source_path = bundle.get_server_source_path()
            # Run behavioral analysis on source_path
    """
    return MCPBundleLoader(bundle_path)


def validate_bundle(bundle_path: Union[str, Path]) -> BundleInfo:
    """
    Validate a bundle without keeping it extracted.
    
    Args:
        bundle_path: Path to the .mcpb bundle file
        
    Returns:
        BundleInfo with bundle details
        
    Raises:
        BundleValidationError: If validation fails
    """
    with load_bundle(bundle_path) as loader:
        return loader.info
