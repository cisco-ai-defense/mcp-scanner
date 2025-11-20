#!/usr/bin/env python3
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
Automated script to add Apache 2.0 license headers to all Python files
in the mcp-scanner project that are missing them.
"""

import os
import sys
from pathlib import Path

LICENSE_HEADER = """# Copyright 2025 Cisco Systems, Inc. and its affiliates
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

# Directories to skip
SKIP_DIRS = {
    '.venv',
    'venv',
    '__pycache__',
    '.pytest_cache',
    '.git',
    'build',
    'dist',
    '*.egg-info',
    'node_modules',
}

def should_skip_file(filepath):
    """Check if file should be skipped."""
    path_parts = Path(filepath).parts
    
    # Skip if any parent directory is in SKIP_DIRS
    for part in path_parts:
        if part in SKIP_DIRS or part.startswith('.'):
            return True
    
    return False

def has_license(filepath):
    """Check if file already has Apache license header."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read(500)  # Read first 500 chars
            return 'Apache License' in content or 'SPDX-License-Identifier: Apache-2.0' in content
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return True  # Skip files we can't read

def add_license_header(filepath):
    """Add license header to a Python file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Handle shebang if present
        if content.startswith('#!'):
            lines = content.split('\n', 1)
            shebang = lines[0] + '\n'
            rest = lines[1] if len(lines) > 1 else ''
            new_content = shebang + LICENSE_HEADER + rest
        else:
            new_content = LICENSE_HEADER + content
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        return True
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False

def find_python_files(root_dir):
    """Find all Python files in directory tree."""
    python_files = []
    
    for root, dirs, files in os.walk(root_dir):
        # Remove skip directories from dirs list (modifies in-place)
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith('.')]
        
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                if not should_skip_file(filepath):
                    python_files.append(filepath)
    
    return python_files

def main():
    """Main function to add licenses to all Python files."""
    # Get the script directory (mcp-scanner root)
    script_dir = Path(__file__).parent
    
    print(f"Scanning for Python files in: {script_dir}")
    print(f"Skipping directories: {', '.join(SKIP_DIRS)}")
    print("-" * 80)
    
    # Find all Python files
    python_files = find_python_files(script_dir)
    print(f"Found {len(python_files)} Python files")
    print("-" * 80)
    
    # Process files
    added_count = 0
    skipped_count = 0
    error_count = 0
    
    for filepath in python_files:
        rel_path = os.path.relpath(filepath, script_dir)
        
        if has_license(filepath):
            print(f"✓ SKIP: {rel_path} (already has license)")
            skipped_count += 1
        else:
            if add_license_header(filepath):
                print(f"✓ ADDED: {rel_path}")
                added_count += 1
            else:
                print(f"✗ ERROR: {rel_path}")
                error_count += 1
    
    # Summary
    print("-" * 80)
    print(f"Summary:")
    print(f"  Total files scanned: {len(python_files)}")
    print(f"  Licenses added: {added_count}")
    print(f"  Already had license: {skipped_count}")
    print(f"  Errors: {error_count}")
    print("-" * 80)
    
    if added_count > 0:
        print(f"\n✅ Successfully added licenses to {added_count} files!")
    else:
        print(f"\n✅ All files already have licenses!")
    
    return 0 if error_count == 0 else 1

if __name__ == '__main__':
    sys.exit(main())
