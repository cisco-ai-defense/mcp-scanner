#!/usr/bin/env python3
"""
Multi-File JavaScript/TypeScript Taint Analysis

Tracks data flow from sources (user input) to sinks (dangerous functions)
across multiple JavaScript and TypeScript files.
"""

import re
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum


class TaintSource(Enum):
    """Types of taint sources (user-controlled input)"""
    FUNCTION_PARAMETER = "function_parameter"
    REQUEST_BODY = "request_body"
    REQUEST_QUERY = "request_query"
    REQUEST_PARAMS = "request_params"
    ARGS_OBJECT = "args_object"  # MCP args
    USER_INPUT = "user_input"
    IMPORTED_TAINTED = "imported_tainted"  # From another file


class TaintSink(Enum):
    """Types of dangerous sinks"""
    EXEC = "exec"  # child_process.exec, eval
    FILE_SYSTEM = "file_system"  # fs.readFile, fs.writeFile
    NETWORK = "network"  # fetch, http.request
    SQL_QUERY = "sql_query"  # db.query, execute
    COMMAND = "command"  # spawn, execSync
    TEMPLATE = "template"  # template rendering


@dataclass
class TaintedVariable:
    """Represents a tainted variable"""
    name: str
    source: TaintSource
    line: int
    file: str
    taint_level: str = "high"  # high, medium, low
    propagated_from: Optional[str] = None
    exported: bool = False  # Is this variable exported?


@dataclass
class TaintFlow:
    """Represents a complete taint flow from source to sink"""
    source_var: str
    source_type: TaintSource
    source_line: int
    source_file: str
    sink_function: str
    sink_type: TaintSink
    sink_line: int
    sink_file: str
    flow_path: List[str] = field(default_factory=list)
    files_involved: List[str] = field(default_factory=list)
    severity: str = "high"


@dataclass
class ExportedSymbol:
    """Represents an exported function or variable"""
    name: str
    file: str
    line: int
    is_tainted: bool = False
    tainted_params: List[str] = field(default_factory=list)


@dataclass
class ImportedSymbol:
    """Represents an imported symbol"""
    name: str
    imported_from: str  # module path
    file: str
    line: int
    alias: Optional[str] = None


class MultiFileJSTaintAnalyzer:
    """Multi-file taint analyzer for JavaScript/TypeScript code"""
    
    def __init__(self):
        # Taint sources patterns
        self.source_patterns = {
            TaintSource.FUNCTION_PARAMETER: [
                r'function\s+\w+\s*\(([^)]+)\)',  # function foo(param)
                r'async\s+function\s+\w+\s*\(([^)]+)\)',  # async function
                r'\(([^)]+)\)\s*=>\s*{',  # arrow function
                r'async\s*\(([^)]+)\)\s*=>\s*{',  # async arrow
            ],
            TaintSource.ARGS_OBJECT: [
                r'args\.(\w+)',  # args.url, args.command
                r'arguments\[(\d+)\]',  # arguments[0]
            ],
            TaintSource.REQUEST_BODY: [
                r'req\.body\.(\w+)',
                r'request\.body\.(\w+)',
            ],
            TaintSource.REQUEST_QUERY: [
                r'req\.query\.(\w+)',
                r'request\.query\.(\w+)',
            ],
            TaintSource.REQUEST_PARAMS: [
                r'req\.params\.(\w+)',
                r'request\.params\.(\w+)',
            ],
        }
        
        # Dangerous sinks
        self.sink_patterns = {
            TaintSink.EXEC: [
                r'exec\s*\(',
                r'execSync\s*\(',
                r'eval\s*\(',
                r'Function\s*\(',
            ],
            TaintSink.COMMAND: [
                r'spawn\s*\(',
                r'spawnSync\s*\(',
                r'execFile\s*\(',
                r'execFileSync\s*\(',
            ],
            TaintSink.FILE_SYSTEM: [
                r'readFile\s*\(',
                r'readFileSync\s*\(',
                r'writeFile\s*\(',
                r'writeFileSync\s*\(',
                r'unlink\s*\(',
                r'unlinkSync\s*\(',
                r'open\s*\(',
                r'openSync\s*\(',
            ],
            TaintSink.NETWORK: [
                r'fetch\s*\(',
                r'axios\.',
                r'http\.request\s*\(',
                r'https\.request\s*\(',
                r'request\s*\(',
            ],
            TaintSink.SQL_QUERY: [
                r'\.query\s*\(',
                r'\.execute\s*\(',
                r'\.run\s*\(',
                r'db\.',
            ],
            TaintSink.TEMPLATE: [
                r'\.render\s*\(',
                r'\.compile\s*\(',
                r'template\s*\(',
            ],
        }
        
        # Export patterns
        self.export_patterns = [
            r'export\s+(?:const|let|var|function|class)\s+(\w+)',
            r'export\s+default\s+(\w+)',
            r'module\.exports\s*=\s*(\w+)',
            r'exports\.(\w+)\s*=',
        ]
        
        # Import patterns
        self.import_patterns = [
            r'import\s+(\w+)\s+from\s+["\']([^"\']+)["\']',  # import foo from 'bar'
            r'import\s+{\s*([^}]+)\s*}\s+from\s+["\']([^"\']+)["\']',  # import { foo } from 'bar'
            r'const\s+(\w+)\s*=\s*require\(["\']([^"\']+)["\']\)',  # const foo = require('bar')
        ]
        
        # Propagation patterns
        self.propagation_patterns = [
            r'(\w+)\s*=\s*([^;]+)',  # assignment
            r'const\s+(\w+)\s*=\s*([^;]+)',  # const declaration
            r'let\s+(\w+)\s*=\s*([^;]+)',  # let declaration
            r'var\s+(\w+)\s*=\s*([^;]+)',  # var declaration
        ]
        
        # Global state for multi-file analysis
        self.all_files: Dict[str, str] = {}  # filename -> code
        self.tainted_vars: Dict[str, Dict[str, TaintedVariable]] = {}  # file -> {var -> TaintedVariable}
        self.exports: Dict[str, List[ExportedSymbol]] = {}  # file -> [ExportedSymbol]
        self.imports: Dict[str, List[ImportedSymbol]] = {}  # file -> [ImportedSymbol]
        self.flows: List[TaintFlow] = []
    
    def add_file(self, filepath: str, code: Optional[str] = None):
        """Add a file to the analysis
        
        Args:
            filepath: Path to the file
            code: Optional source code (if None, reads from file)
        """
        if code is None:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
            except Exception as e:
                print(f"Warning: Could not read {filepath}: {e}")
                return
        
        self.all_files[filepath] = code
    
    def add_directory(self, directory: str, pattern: str = "*.js", recursive: bool = True):
        """Add all matching files from a directory
        
        Args:
            directory: Directory path
            pattern: File pattern (e.g., "*.js", "*.ts")
            recursive: Whether to search recursively
        """
        dir_path = Path(directory)
        
        if recursive:
            files = dir_path.rglob(pattern)
        else:
            files = dir_path.glob(pattern)
        
        for file_path in files:
            if file_path.is_file():
                self.add_file(str(file_path))
    
    def analyze(self) -> Dict:
        """Analyze all files for taint flows
        
        Returns:
            Dictionary with comprehensive analysis results
        """
        # Phase 1: Analyze each file individually
        for filepath, code in self.all_files.items():
            self._analyze_single_file(filepath, code)
        
        # Phase 2: Resolve imports and propagate taint across files
        self._resolve_cross_file_taint()
        
        # Phase 3: Find flows to sinks (including cross-file)
        self._find_all_flows()
        
        # Generate report
        return self._generate_report()
    
    def _analyze_single_file(self, filepath: str, code: str):
        """Analyze a single file"""
        lines = code.split('\n')
        
        # Initialize storage for this file
        self.tainted_vars[filepath] = {}
        self.exports[filepath] = []
        self.imports[filepath] = []
        
        # Find sources
        sources = self._find_sources(lines, filepath)
        for source in sources:
            self.tainted_vars[filepath][source.name] = source
        
        # Find exports
        self.exports[filepath] = self._find_exports(lines, filepath)
        
        # Find imports
        self.imports[filepath] = self._find_imports(lines, filepath)
        
        # Propagate taint within file
        self.tainted_vars[filepath] = self._propagate_taint(lines, self.tainted_vars[filepath], filepath)
        
        # Mark exported tainted variables
        for export in self.exports[filepath]:
            if export.name in self.tainted_vars[filepath]:
                export.is_tainted = True
                self.tainted_vars[filepath][export.name].exported = True
    
    def _find_sources(self, lines: List[str], filepath: str) -> List[TaintedVariable]:
        """Find all taint sources in the code"""
        sources = []
        
        for line_num, line in enumerate(lines, 1):
            # Check for function parameters
            for pattern in self.source_patterns[TaintSource.FUNCTION_PARAMETER]:
                match = re.search(pattern, line)
                if match:
                    params = match.group(1).split(',')
                    for param in params:
                        param = param.strip()
                        param_name = self._extract_param_name(param)
                        if param_name:
                            sources.append(TaintedVariable(
                                name=param_name,
                                source=TaintSource.FUNCTION_PARAMETER,
                                line=line_num,
                                file=filepath,
                                taint_level="high"
                            ))
            
            # Check for args.* patterns (MCP specific)
            for pattern in self.source_patterns[TaintSource.ARGS_OBJECT]:
                for match in re.finditer(pattern, line):
                    var_name = match.group(1) if match.lastindex >= 1 else match.group(0)
                    sources.append(TaintedVariable(
                        name=f"args.{var_name}",
                        source=TaintSource.ARGS_OBJECT,
                        line=line_num,
                        file=filepath,
                        taint_level="high"
                    ))
            
            # Check for request body/query/params
            for source_type, patterns in self.source_patterns.items():
                if source_type in [TaintSource.REQUEST_BODY, TaintSource.REQUEST_QUERY, TaintSource.REQUEST_PARAMS]:
                    for pattern in patterns:
                        for match in re.finditer(pattern, line):
                            var_name = match.group(0)
                            sources.append(TaintedVariable(
                                name=var_name,
                                source=source_type,
                                line=line_num,
                                file=filepath,
                                taint_level="high"
                            ))
        
        return sources
    
    def _extract_param_name(self, param: str) -> Optional[str]:
        """Extract parameter name from parameter declaration"""
        param = param.strip()
        
        # Remove default values
        if '=' in param:
            param = param.split('=')[0].strip()
        
        # Handle destructured parameters: { path }, { url }, etc.
        if param.startswith('{') and param.endswith('}'):
            inner = param[1:-1].strip()
            props = [p.strip().split(':')[0].strip() for p in inner.split(',')]
            return props[0] if props and props[0] else None
        
        # Skip array destructuring
        if param.startswith('['):
            return None
        
        # Remove type annotations (TypeScript)
        if ':' in param:
            param = param.split(':')[0].strip()
        
        return param if param and param.replace('_', '').isalnum() else None
    
    def _find_exports(self, lines: List[str], filepath: str) -> List[ExportedSymbol]:
        """Find all exported symbols"""
        exports = []
        
        for line_num, line in enumerate(lines, 1):
            for pattern in self.export_patterns:
                match = re.search(pattern, line)
                if match:
                    name = match.group(1)
                    exports.append(ExportedSymbol(
                        name=name,
                        file=filepath,
                        line=line_num
                    ))
        
        return exports
    
    def _find_imports(self, lines: List[str], filepath: str) -> List[ImportedSymbol]:
        """Find all imported symbols"""
        imports = []
        
        for line_num, line in enumerate(lines, 1):
            # import foo from 'bar'
            match = re.search(self.import_patterns[0], line)
            if match:
                name = match.group(1)
                module = match.group(2)
                imports.append(ImportedSymbol(
                    name=name,
                    imported_from=module,
                    file=filepath,
                    line=line_num
                ))
            
            # import { foo, bar } from 'baz'
            match = re.search(self.import_patterns[1], line)
            if match:
                names = match.group(1)
                module = match.group(2)
                for name in names.split(','):
                    name = name.strip()
                    # Handle aliases: foo as bar
                    if ' as ' in name:
                        orig, alias = name.split(' as ')
                        imports.append(ImportedSymbol(
                            name=orig.strip(),
                            imported_from=module,
                            alias=alias.strip(),
                            file=filepath,
                            line=line_num
                        ))
                    else:
                        imports.append(ImportedSymbol(
                            name=name,
                            imported_from=module,
                            file=filepath,
                            line=line_num
                        ))
            
            # const foo = require('bar')
            match = re.search(self.import_patterns[2], line)
            if match:
                name = match.group(1)
                module = match.group(2)
                imports.append(ImportedSymbol(
                    name=name,
                    imported_from=module,
                    file=filepath,
                    line=line_num
                ))
        
        return imports
    
    def _propagate_taint(self, lines: List[str], tainted_vars: Dict[str, TaintedVariable], filepath: str) -> Dict[str, TaintedVariable]:
        """Propagate taint through variable assignments"""
        # Multiple passes
        for _ in range(5):
            new_tainted = {}
            
            for line_num, line in enumerate(lines, 1):
                for pattern in self.propagation_patterns:
                    match = re.search(pattern, line)
                    if match:
                        target_var = match.group(1)
                        source_expr = match.group(2)
                        
                        # Check if source expression contains tainted variables
                        for tainted_var in tainted_vars:
                            if tainted_var in source_expr:
                                if target_var not in tainted_vars:
                                    new_tainted[target_var] = TaintedVariable(
                                        name=target_var,
                                        source=tainted_vars[tainted_var].source,
                                        line=line_num,
                                        file=filepath,
                                        taint_level=tainted_vars[tainted_var].taint_level,
                                        propagated_from=tainted_var
                                    )
                                break
            
            if not new_tainted:
                break
            
            tainted_vars.update(new_tainted)
        
        return tainted_vars
    
    def _resolve_cross_file_taint(self):
        """Resolve taint propagation across file imports/exports"""
        # For each file with imports
        for filepath, imports in self.imports.items():
            for imported in imports:
                # Try to resolve the import to an actual file
                source_file = self._resolve_import_path(imported.imported_from, filepath)
                
                if source_file and source_file in self.exports:
                    # Check if the imported symbol is tainted in the source file
                    for export in self.exports[source_file]:
                        if export.name == imported.name and export.is_tainted:
                            # Propagate taint to importing file
                            imported_name = imported.alias or imported.name
                            
                            if filepath not in self.tainted_vars:
                                self.tainted_vars[filepath] = {}
                            
                            self.tainted_vars[filepath][imported_name] = TaintedVariable(
                                name=imported_name,
                                source=TaintSource.IMPORTED_TAINTED,
                                line=imported.line,
                                file=filepath,
                                taint_level="high",
                                propagated_from=f"{source_file}:{export.name}"
                            )
    
    def _resolve_import_path(self, module_path: str, importing_file: str) -> Optional[str]:
        """Resolve a module import path to an actual file"""
        # Skip node_modules and external packages
        if not module_path.startswith('.'):
            return None
        
        # Resolve relative path
        importing_dir = Path(importing_file).parent
        resolved = (importing_dir / module_path).resolve()
        
        # Try common extensions
        for ext in ['', '.js', '.ts', '.jsx', '.tsx', '/index.js', '/index.ts']:
            candidate = str(resolved) + ext
            if candidate in self.all_files:
                return candidate
        
        return None
    
    def _find_all_flows(self):
        """Find all taint flows to sinks across all files"""
        for filepath, code in self.all_files.items():
            lines = code.split('\n')
            tainted_vars = self.tainted_vars.get(filepath, {})
            
            for line_num, line in enumerate(lines, 1):
                # Check each sink type
                for sink_type, patterns in self.sink_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, line):
                            # Found a sink, check if tainted data flows into it
                            for var_name, tainted_var in tainted_vars.items():
                                if var_name in line or var_name.split('.')[-1] in line:
                                    # Build flow path
                                    flow_path, files_involved = self._build_cross_file_flow_path(tainted_var)
                                    
                                    self.flows.append(TaintFlow(
                                        source_var=tainted_var.name,
                                        source_type=tainted_var.source,
                                        source_line=tainted_var.line,
                                        source_file=tainted_var.file,
                                        sink_function=re.search(pattern, line).group(0),
                                        sink_type=sink_type,
                                        sink_line=line_num,
                                        sink_file=filepath,
                                        flow_path=flow_path,
                                        files_involved=files_involved,
                                        severity=self._calculate_severity(tainted_var.source, sink_type)
                                    ))
    
    def _build_cross_file_flow_path(self, tainted_var: TaintedVariable) -> Tuple[List[str], List[str]]:
        """Build the complete flow path including cross-file propagation"""
        path = [f"{Path(tainted_var.file).name}:{tainted_var.name}"]
        files = [tainted_var.file]
        current = tainted_var
        
        # Trace back through propagations
        while current.propagated_from:
            if ':' in current.propagated_from:
                # Cross-file propagation
                source_file, var_name = current.propagated_from.rsplit(':', 1)
                path.insert(0, f"{Path(source_file).name}:{var_name}")
                if source_file not in files:
                    files.insert(0, source_file)
                break
            else:
                # Same-file propagation
                path.insert(0, f"{Path(current.file).name}:{current.propagated_from}")
                
                # Find the source variable
                file_vars = self.tainted_vars.get(current.file, {})
                current = file_vars.get(current.propagated_from)
                if not current:
                    break
        
        return path, files
    
    def _calculate_severity(self, source: TaintSource, sink: TaintSink) -> str:
        """Calculate severity based on source and sink combination"""
        high_risk = [
            (TaintSource.ARGS_OBJECT, TaintSink.EXEC),
            (TaintSource.ARGS_OBJECT, TaintSink.COMMAND),
            (TaintSource.FUNCTION_PARAMETER, TaintSink.EXEC),
            (TaintSource.FUNCTION_PARAMETER, TaintSink.COMMAND),
            (TaintSource.REQUEST_BODY, TaintSink.SQL_QUERY),
            (TaintSource.IMPORTED_TAINTED, TaintSink.EXEC),
            (TaintSource.IMPORTED_TAINTED, TaintSink.COMMAND),
        ]
        
        if (source, sink) in high_risk:
            return "high"
        
        medium_risk = [
            (TaintSource.ARGS_OBJECT, TaintSink.FILE_SYSTEM),
            (TaintSource.ARGS_OBJECT, TaintSink.NETWORK),
            (TaintSource.FUNCTION_PARAMETER, TaintSink.FILE_SYSTEM),
            (TaintSource.FUNCTION_PARAMETER, TaintSink.NETWORK),
            (TaintSource.REQUEST_QUERY, TaintSink.SQL_QUERY),
            (TaintSource.REQUEST_PARAMS, TaintSink.FILE_SYSTEM),
            (TaintSource.IMPORTED_TAINTED, TaintSink.FILE_SYSTEM),
            (TaintSource.IMPORTED_TAINTED, TaintSink.NETWORK),
        ]
        
        if (source, sink) in medium_risk:
            return "medium"
        
        return "low"
    
    def _generate_report(self) -> Dict:
        """Generate comprehensive analysis report"""
        total_tainted = sum(len(vars) for vars in self.tainted_vars.values())
        cross_file_flows = [f for f in self.flows if len(f.files_involved) > 1]
        
        return {
            'total_files': len(self.all_files),
            'total_tainted_vars': total_tainted,
            'total_flows': len(self.flows),
            'cross_file_flows': len(cross_file_flows),
            'flows': self.flows,
            'tainted_vars_by_file': {
                filepath: list(vars.values())
                for filepath, vars in self.tainted_vars.items()
            },
            'exports_by_file': self.exports,
            'imports_by_file': self.imports,
        }
    
    def format_report(self, results: Dict) -> str:
        """Format analysis results as a readable report"""
        report = []
        report.append("=" * 80)
        report.append("  MULTI-FILE JAVASCRIPT/TYPESCRIPT TAINT ANALYSIS")
        report.append("=" * 80)
        report.append(f"\nTotal Files Analyzed: {results['total_files']}")
        report.append(f"Total Tainted Variables: {results['total_tainted_vars']}")
        report.append(f"Total Flows to Sinks: {results['total_flows']}")
        report.append(f"Cross-File Flows: {results['cross_file_flows']}")
        
        if results['flows']:
            report.append("\n" + "=" * 80)
            report.append("  TAINT FLOWS DETECTED")
            report.append("=" * 80)
            
            for i, flow in enumerate(results['flows'], 1):
                severity_icon = "🔴" if flow.severity == "high" else "🟠" if flow.severity == "medium" else "🟡"
                cross_file_marker = " [CROSS-FILE]" if len(flow.files_involved) > 1 else ""
                
                report.append(f"\n{severity_icon} Flow #{i} [{flow.severity.upper()}]{cross_file_marker}")
                report.append(f"   Source: {flow.source_var} ({flow.source_type.value})")
                report.append(f"           {Path(flow.source_file).name}:line {flow.source_line}")
                report.append(f"   Sink: {flow.sink_function} ({flow.sink_type.value})")
                report.append(f"         {Path(flow.sink_file).name}:line {flow.sink_line}")
                
                if flow.flow_path:
                    report.append(f"   Flow Path: {' → '.join(flow.flow_path)}")
                
                if len(flow.files_involved) > 1:
                    files_str = ', '.join([Path(f).name for f in flow.files_involved])
                    report.append(f"   Files Involved: {files_str}")
        else:
            report.append("\n✅ No taint flows detected")
        
        return "\n".join(report)


def test_multifile_analysis():
    """Test multi-file taint analysis"""
    
    # Create test files
    file1_code = """
// utils.js - Utility functions
export function sanitizeInput(input) {
    return input.replace(/[^a-zA-Z0-9]/g, '');
}

export function dangerousFunction(userInput) {
    const { exec } = require('child_process');
    // This is tainted!
    exec(userInput);
}
"""
    
    file2_code = """
// server.js - MCP Server
import { dangerousFunction } from './utils';

server.setRequestHandler(CallToolRequest, async (request) => {
    const { arguments: args } = request.params;
    
    // Cross-file taint flow!
    dangerousFunction(args.command);
});
"""
    
    file3_code = """
// fileHandler.js
export function readUserFile(filename) {
    const fs = require('fs');
    // Tainted file read
    return fs.readFileSync(filename, 'utf-8');
}
"""
    
    file4_code = """
// main.js
import { readUserFile } from './fileHandler';

server.tool("read_file", async ({ path }) => {
    // Cross-file taint: path -> readUserFile -> fs.readFileSync
    const content = readUserFile(path);
    return { content: [{ type: "text", text: content }] };
});
"""
    
    print("\n" + "=" * 80)
    print("  TESTING MULTI-FILE JS/TS TAINT ANALYZER")
    print("=" * 80)
    
    analyzer = MultiFileJSTaintAnalyzer()
    
    # Add files
    analyzer.add_file("utils.js", file1_code)
    analyzer.add_file("server.js", file2_code)
    analyzer.add_file("fileHandler.js", file3_code)
    analyzer.add_file("main.js", file4_code)
    
    # Analyze
    results = analyzer.analyze()
    
    # Print report
    print(analyzer.format_report(results))
    
    # Print detailed stats
    print("\n" + "=" * 80)
    print("  DETAILED STATISTICS")
    print("=" * 80)
    
    for filepath, tainted_vars in results['tainted_vars_by_file'].items():
        if tainted_vars:
            print(f"\n📄 {Path(filepath).name}")
            print(f"   Tainted Variables: {len(tainted_vars)}")
            for var in tainted_vars[:3]:  # Show first 3
                print(f"   • {var.name} ({var.source.value}) at line {var.line}")


if __name__ == "__main__":
    test_multifile_analysis()
