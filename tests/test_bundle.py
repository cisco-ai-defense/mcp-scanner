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

"""Tests for MCP Bundle (.mcpb) support using DXT manifest schema."""

import json
import os
import tempfile
import zipfile
from pathlib import Path

import pytest


def create_valid_manifest(name="test-server", version="1.0.0", **overrides):
    """Helper to create a valid DXT manifest dict."""
    manifest = {
        "name": name,
        "version": version,
        "description": "Test MCP server",
        "author": {"name": "Test Author"},
        "server": {
            "type": "python",
            "entry_point": "server/main.py",
            "mcp_config": {
                "command": "python",
                "args": ["-m", "server"]
            }
        }
    }
    manifest.update(overrides)
    return manifest


class TestBundleManifest:
    """Test BundleManifest model with DXT schema."""
    
    def test_manifest_import(self):
        """Test that BundleManifest can be imported."""
        from mcpscanner.core.bundle import BundleManifest
        assert BundleManifest is not None
    
    def test_manifest_required_fields(self):
        """Test manifest with required fields only."""
        from mcpscanner.core.bundle import BundleManifest
        
        manifest = BundleManifest(**create_valid_manifest())
        
        assert manifest.name == "test-server"
        assert manifest.version == "1.0.0"
        assert manifest.entry_point == "server/main.py"
        assert manifest.author.name == "Test Author"
    
    def test_manifest_all_fields(self):
        """Test manifest with all fields."""
        from mcpscanner.core.bundle import BundleManifest, ServerType
        
        manifest_data = create_valid_manifest(
            name="full-server",
            version="2.1.0",
            description="A full-featured MCP server",
            display_name="Full Server",
            long_description="A comprehensive MCP server implementation",
            license="MIT",
            keywords=["mcp", "server"],
            tools=[{"name": "tool1", "description": "First tool"}, {"name": "tool2"}],
            compatibility={
                "platforms": ["darwin", "linux"],
                "runtimes": {"python": ">=3.10"}
            }
        )
        manifest_data["author"]["email"] = "test@example.com"
        manifest_data["author"]["url"] = "https://example.com"
        
        manifest = BundleManifest(**manifest_data)
        
        assert manifest.name == "full-server"
        assert manifest.version == "2.1.0"
        assert manifest.description == "A full-featured MCP server"
        assert manifest.display_name == "Full Server"
        assert manifest.author.name == "Test Author"
        assert manifest.author.email == "test@example.com"
        assert manifest.entry_point == "server/main.py"
        assert manifest.server_type == ServerType.PYTHON
        assert "tool1" in manifest.tool_names
        assert "tool2" in manifest.tool_names
    
    def test_manifest_version_validation(self):
        """Test that version is validated."""
        from mcpscanner.core.bundle import BundleManifest
        
        # Valid versions
        BundleManifest(**create_valid_manifest(version="1.0.0"))
        BundleManifest(**create_valid_manifest(version="0.1.0-beta"))
        BundleManifest(**create_valid_manifest(version="2.0.0+build123"))


class TestMCPBundleLoader:
    """Test MCPBundleLoader functionality."""
    
    def test_loader_import(self):
        """Test that MCPBundleLoader can be imported."""
        from mcpscanner.core.bundle import MCPBundleLoader
        assert MCPBundleLoader is not None
    
    def test_loader_nonexistent_file(self):
        """Test loader with non-existent file."""
        from mcpscanner.core.bundle import MCPBundleLoader, BundleValidationError
        
        loader = MCPBundleLoader("/nonexistent/path/bundle.mcpb")
        
        with pytest.raises(BundleValidationError, match="not found"):
            loader.validate_bundle_file()
    
    def test_loader_invalid_zip(self):
        """Test loader with invalid ZIP file."""
        from mcpscanner.core.bundle import MCPBundleLoader, BundleValidationError
        
        with tempfile.NamedTemporaryFile(suffix=".mcpb", delete=False) as f:
            f.write(b"not a zip file")
            temp_path = f.name
        
        try:
            loader = MCPBundleLoader(temp_path)
            with pytest.raises(BundleValidationError, match="not a valid ZIP"):
                loader.validate_bundle_file()
        finally:
            os.unlink(temp_path)
    
    def test_loader_missing_manifest(self):
        """Test loader with ZIP missing manifest.json."""
        from mcpscanner.core.bundle import MCPBundleLoader, BundleValidationError
        
        with tempfile.NamedTemporaryFile(suffix=".mcpb", delete=False) as f:
            temp_path = f.name
        
        try:
            with zipfile.ZipFile(temp_path, 'w') as zf:
                zf.writestr("server/main.py", "# empty")
            
            loader = MCPBundleLoader(temp_path)
            with pytest.raises(BundleValidationError, match="Missing required manifest.json"):
                loader.extract()
        finally:
            os.unlink(temp_path)
    
    def test_loader_valid_bundle(self):
        """Test loader with valid bundle."""
        from mcpscanner.core.bundle import MCPBundleLoader
        
        with tempfile.NamedTemporaryFile(suffix=".mcpb", delete=False) as f:
            temp_path = f.name
        
        try:
            manifest = create_valid_manifest(name="test-bundle", description="Test bundle")
            
            server_code = '''
import mcp

@mcp.tool()
def hello(name: str) -> str:
    """Say hello to someone."""
    return f"Hello, {name}!"
'''
            
            with zipfile.ZipFile(temp_path, 'w') as zf:
                zf.writestr("manifest.json", json.dumps(manifest))
                zf.writestr("server/main.py", server_code)
            
            with MCPBundleLoader(temp_path) as loader:
                info = loader.info
                
                assert info is not None
                assert info.name == "test-bundle"
                assert info.version == "1.0.0"
                assert info.manifest.description == "Test bundle"
                assert len(info.python_files) == 1
                
        finally:
            os.unlink(temp_path)
    
    def test_loader_get_server_source_path(self):
        """Test getting server source path from bundle."""
        from mcpscanner.core.bundle import MCPBundleLoader
        
        with tempfile.NamedTemporaryFile(suffix=".mcpb", delete=False) as f:
            temp_path = f.name
        
        try:
            manifest = create_valid_manifest(name="source-test")
            
            with zipfile.ZipFile(temp_path, 'w') as zf:
                zf.writestr("manifest.json", json.dumps(manifest))
                zf.writestr("server/main.py", "# main")
                zf.writestr("server/utils.py", "# utils")
            
            with MCPBundleLoader(temp_path) as loader:
                source_path = loader.get_server_source_path()
                assert source_path.exists()
                assert source_path.is_dir()
                
        finally:
            os.unlink(temp_path)
    
    def test_loader_get_all_python_files(self):
        """Test getting all Python files from bundle."""
        from mcpscanner.core.bundle import MCPBundleLoader
        
        with tempfile.NamedTemporaryFile(suffix=".mcpb", delete=False) as f:
            temp_path = f.name
        
        try:
            manifest = create_valid_manifest(name="multi-file")
            
            with zipfile.ZipFile(temp_path, 'w') as zf:
                zf.writestr("manifest.json", json.dumps(manifest))
                zf.writestr("server/main.py", "# main")
                zf.writestr("server/utils.py", "# utils")
                zf.writestr("server/handlers/api.py", "# api handler")
                zf.writestr("lib/helper.py", "# helper")
            
            with MCPBundleLoader(temp_path) as loader:
                py_files = loader.get_all_python_files()
                assert len(py_files) == 4
                
                filenames = [f.name for f in py_files]
                assert "main.py" in filenames
                assert "utils.py" in filenames
                assert "api.py" in filenames
                assert "helper.py" in filenames
                
        finally:
            os.unlink(temp_path)
    
    def test_loader_context_manager_cleanup(self):
        """Test that context manager cleans up temp directory."""
        from mcpscanner.core.bundle import MCPBundleLoader
        
        with tempfile.NamedTemporaryFile(suffix=".mcpb", delete=False) as f:
            temp_path = f.name
        
        try:
            manifest = create_valid_manifest(name="cleanup-test")
            
            with zipfile.ZipFile(temp_path, 'w') as zf:
                zf.writestr("manifest.json", json.dumps(manifest))
                zf.writestr("server/main.py", "# main")
            
            extract_dir = None
            with MCPBundleLoader(temp_path) as loader:
                extract_dir = loader.info.extract_dir
                assert extract_dir.exists()
            
            # After context exit, temp dir should be cleaned up
            assert not extract_dir.exists()
            
        finally:
            os.unlink(temp_path)


class TestBundleInfo:
    """Test BundleInfo dataclass."""
    
    def test_bundle_info_properties(self):
        """Test BundleInfo name and version properties."""
        from mcpscanner.core.bundle import MCPBundleLoader
        
        with tempfile.NamedTemporaryFile(suffix=".mcpb", delete=False) as f:
            temp_path = f.name
        
        try:
            manifest = create_valid_manifest(name="property-test", version="2.5.0")
            
            with zipfile.ZipFile(temp_path, 'w') as zf:
                zf.writestr("manifest.json", json.dumps(manifest))
                zf.writestr("server/main.py", "# main")
            
            with MCPBundleLoader(temp_path) as loader:
                info = loader.info
                assert info.name == "property-test"
                assert info.version == "2.5.0"
                
        finally:
            os.unlink(temp_path)


class TestConvenienceFunctions:
    """Test convenience functions."""
    
    def test_load_bundle_function(self):
        """Test load_bundle convenience function."""
        from mcpscanner.core.bundle import load_bundle
        
        with tempfile.NamedTemporaryFile(suffix=".mcpb", delete=False) as f:
            temp_path = f.name
        
        try:
            manifest = create_valid_manifest(name="convenience-test", version="1.0.0")
            
            with zipfile.ZipFile(temp_path, 'w') as zf:
                zf.writestr("manifest.json", json.dumps(manifest))
                zf.writestr("server/main.py", "# main")
            
            with load_bundle(temp_path) as loader:
                assert loader.info.name == "convenience-test"
                
        finally:
            os.unlink(temp_path)
    
    def test_validate_bundle_function(self):
        """Test validate_bundle convenience function."""
        from mcpscanner.core.bundle import validate_bundle
        
        with tempfile.NamedTemporaryFile(suffix=".mcpb", delete=False) as f:
            temp_path = f.name
        
        try:
            manifest = create_valid_manifest(name="validate-test", version="3.0.0")
            
            with zipfile.ZipFile(temp_path, 'w') as zf:
                zf.writestr("manifest.json", json.dumps(manifest))
                zf.writestr("server/main.py", "# main")
            
            info = validate_bundle(temp_path)
            assert info.name == "validate-test"
            assert info.version == "3.0.0"
            
        finally:
            os.unlink(temp_path)


class TestBundleWithOptionalFiles:
    """Test bundle handling of optional files."""
    
    def test_bundle_with_requirements(self):
        """Test bundle with requirements.txt."""
        from mcpscanner.core.bundle import MCPBundleLoader
        
        with tempfile.NamedTemporaryFile(suffix=".mcpb", delete=False) as f:
            temp_path = f.name
        
        try:
            manifest = {"name": "req-test", "version": "1.0.0"}
            requirements = "mcp>=1.0.0\npydantic>=2.0\n"
            
            with zipfile.ZipFile(temp_path, 'w') as zf:
                zf.writestr("manifest.json", json.dumps(manifest))
                zf.writestr("server/main.py", "# main")
                zf.writestr("requirements.txt", requirements)
            
            with MCPBundleLoader(temp_path) as loader:
                info = loader.info
                assert info.requirements_path is not None
                assert info.requirements_path.exists()
                
        finally:
            os.unlink(temp_path)
    
    def test_bundle_with_lib_dir(self):
        """Test bundle with lib directory."""
        from mcpscanner.core.bundle import MCPBundleLoader
        
        with tempfile.NamedTemporaryFile(suffix=".mcpb", delete=False) as f:
            temp_path = f.name
        
        try:
            manifest = {"name": "lib-test", "version": "1.0.0"}
            
            with zipfile.ZipFile(temp_path, 'w') as zf:
                zf.writestr("manifest.json", json.dumps(manifest))
                zf.writestr("server/main.py", "# main")
                zf.writestr("lib/custom_module/__init__.py", "# init")
                zf.writestr("lib/custom_module/core.py", "# core")
            
            with MCPBundleLoader(temp_path) as loader:
                info = loader.info
                assert info.lib_dir is not None
                assert info.lib_dir.exists()
                
        finally:
            os.unlink(temp_path)
    
    def test_bundle_with_icon(self):
        """Test bundle with icon.png."""
        from mcpscanner.core.bundle import MCPBundleLoader
        
        with tempfile.NamedTemporaryFile(suffix=".mcpb", delete=False) as f:
            temp_path = f.name
        
        try:
            manifest = {"name": "icon-test", "version": "1.0.0"}
            # Minimal PNG header (not a real image, just for testing)
            fake_png = b'\x89PNG\r\n\x1a\n'
            
            with zipfile.ZipFile(temp_path, 'w') as zf:
                zf.writestr("manifest.json", json.dumps(manifest))
                zf.writestr("server/main.py", "# main")
                zf.writestr("icon.png", fake_png)
            
            with MCPBundleLoader(temp_path) as loader:
                info = loader.info
                assert info.icon_path is not None
                assert info.icon_path.exists()
                
        finally:
            os.unlink(temp_path)
