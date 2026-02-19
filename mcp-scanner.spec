# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec file for mcp-scanner."""

import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None
project_root = SPECPATH

litellm_datas = collect_data_files('litellm', include_py_files=False)
certifi_datas = collect_data_files('certifi')
jsonschema_datas = collect_data_files('jsonschema')
jsonschema_spec_datas = collect_data_files('jsonschema_specifications')
pydantic_datas = collect_data_files('pydantic')
litellm_imports = collect_submodules('litellm')
rich_hidden = collect_submodules('rich._unicode_data')
mcp_imports = collect_submodules('mcp')

a = Analysis(
    [os.path.join(project_root, 'mcp_scanner_entry.py')],
    pathex=[project_root],
    binaries=[],
    datas=[
        (os.path.join(project_root, 'mcpscanner', 'data', 'yara_rules'), os.path.join('mcpscanner', 'data', 'yara_rules')),
        (os.path.join(project_root, 'mcpscanner', 'data', 'prompts'), os.path.join('mcpscanner', 'data', 'prompts')),
        (os.path.join(project_root, 'mcpscanner', 'data', 'readiness_policies'), os.path.join('mcpscanner', 'data', 'readiness_policies')),
    ] + litellm_datas + certifi_datas + jsonschema_datas + jsonschema_spec_datas + pydantic_datas,
    hiddenimports=[
        'mcpscanner', 'mcpscanner.cli', 'mcpscanner.config', 'mcpscanner.config.constants',
        'mcpscanner.config.config', 'mcpscanner.core', 'mcpscanner.core.scanner',
        'mcpscanner.core.analyzers', 'mcpscanner.utils',
        'click', 'rich', 'httpx', 'yara', 'pydantic', 'dotenv', 'jsonschema',
        'aiohttp', 'requests', 'expandvars',
    ] + litellm_imports + rich_hidden + mcp_imports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        'mcpscanner.api', 'uvicorn', 'fastapi',
        'tkinter', 'matplotlib', 'numpy', 'pandas', 'scipy', 'PIL',
        'IPython', 'notebook', 'jupyter',
    ],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz, a.scripts, a.binaries, a.zipfiles, a.datas, [],
    name='mcp-scanner',
    debug=False, strip=False, upx=True,
    runtime_tmpdir=None, console=True,
    target_arch=None,
)
