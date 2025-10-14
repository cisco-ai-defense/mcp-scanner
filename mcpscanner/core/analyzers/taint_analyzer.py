"""
Taint Analysis for MCP Server Code

This module performs static taint analysis on Python code to detect security vulnerabilities
by tracking data flow from user-controlled inputs (sources) to dangerous operations (sinks).

Supports analysis of:
- @mcp.tool() decorated functions
- @mcp.prompt() decorated functions  
- @mcp.resource() decorated functions
"""

import ast
import logging
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class TaintLevel(Enum):
    """Taint levels for tracking data flow"""
    SAFE = "safe"
    TAINTED = "tainted"
    SANITIZED = "sanitized"


class VulnerabilityType(Enum):
    """Types of vulnerabilities detected by taint analysis"""
    COMMAND_INJECTION = "Command Injection"
    SQL_INJECTION = "SQL Injection"
    NOSQL_INJECTION = "NoSQL Injection"
    PATH_TRAVERSAL = "Path Traversal"
    ARBITRARY_FILE_READ = "Arbitrary File Read"
    ARBITRARY_FILE_WRITE = "Arbitrary File Write"
    RCE = "Remote Code Execution"
    SSRF = "Server-Side Request Forgery"
    SSTI = "Server-Side Template Injection"
    DATA_EXFILTRATION = "Data Exfiltration"


@dataclass
class TaintSource:
    """Represents a source of tainted data (user input)"""
    name: str
    node: ast.AST
    function_name: str
    line_number: int


@dataclass
class TaintSink:
    """Represents a dangerous operation (vulnerability sink)"""
    sink_type: VulnerabilityType
    function_name: str
    node: ast.AST
    line_number: int
    description: str


@dataclass
class TaintPath:
    """Represents a complete taint flow from source to sink"""
    source: TaintSource
    sink: TaintSink
    path: List[Tuple[str, int]]  # List of (variable_name, line_number)
    severity: str = "HIGH"
    
    def __str__(self):
        path_str = " -> ".join([f"{var}(L{line})" for var, line in self.path])
        return f"{self.source.name}(L{self.source.line_number}) -> {path_str} -> {self.sink.function_name}(L{self.sink.line_number})"


class DataFlowTracker(ast.NodeVisitor):
    """
    Tracks data flow paths for function parameters without vulnerability detection.
    
    This analyzer simply tracks where each parameter flows through the code,
    recording all variables and function calls it touches. Useful for understanding
    data flow patterns and debugging.
    """
    
    def __init__(self, source_code: str, filename: str = "<unknown>"):
        self.source_code = source_code
        self.filename = filename
        self.source_lines = source_code.split('\n')
        
        # Track parameter flows
        self.parameter_flows: Dict[str, List[Dict[str, Any]]] = {}  # param -> [flow_events]
        self.current_function: Optional[str] = None
        self.current_function_params: Set[str] = set()
        self.is_mcp_function: bool = False
        
        # Data flow tracking
        self.tainted_vars: Dict[str, str] = {}  # var -> source_param
        self.variable_lines: Dict[str, int] = {}
    
    def analyze(self) -> Dict[str, Any]:
        """Perform data flow tracking"""
        try:
            tree = ast.parse(self.source_code, filename=self.filename)
            self.visit(tree)
            return self.get_flow_report()
        except SyntaxError as e:
            logger.error(f"Syntax error in {self.filename}: {e}")
            return {}
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Visit function definition to identify MCP functions"""
        is_mcp = False
        for decorator in node.decorator_list:
            decorator_name = self._get_decorator_name(decorator)
            if decorator_name in ['mcp.tool', 'mcp.prompt', 'mcp.resource', 'tool', 'prompt', 'resource']:
                is_mcp = True
                break
        
        if is_mcp:
            prev_function = self.current_function
            prev_params = self.current_function_params
            prev_is_mcp = self.is_mcp_function
            
            self.current_function = node.name
            self.is_mcp_function = True
            self.current_function_params = set()
            
            # Initialize flow tracking for each parameter
            for arg in node.args.args:
                param_name = arg.arg
                if param_name != 'self':
                    self.current_function_params.add(param_name)
                    self.tainted_vars[param_name] = param_name
                    self.variable_lines[param_name] = node.lineno
                    
                    self.parameter_flows[param_name] = [{
                        'event': 'parameter_defined',
                        'function': node.name,
                        'line': node.lineno,
                        'variable': param_name
                    }]
            
            self.generic_visit(node)
            
            self.current_function = prev_function
            self.current_function_params = prev_params
            self.is_mcp_function = prev_is_mcp
        else:
            self.generic_visit(node)
    
    def visit_Assign(self, node: ast.Assign):
        """Track variable assignments"""
        if not self.is_mcp_function:
            self.generic_visit(node)
            return
        
        target_vars = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                target_vars.append(target.id)
        
        source_vars = self._extract_variables(node.value)
        
        for target_var in target_vars:
            self.variable_lines[target_var] = node.lineno
            
            # Check if any source is tainted
            for src in source_vars:
                if src in self.tainted_vars:
                    source_param = self.tainted_vars[src]
                    self.tainted_vars[target_var] = source_param
                    
                    # Record flow event
                    self.parameter_flows[source_param].append({
                        'event': 'assignment',
                        'line': node.lineno,
                        'from_variable': src,
                        'to_variable': target_var,
                        'code': self._get_line(node.lineno)
                    })
        
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call):
        """Track function calls with tainted arguments"""
        if not self.is_mcp_function:
            self.generic_visit(node)
            return
        
        func_name = self._get_call_name(node)
        
        # Check arguments
        for arg in node.args:
            arg_vars = self._extract_variables(arg)
            for var in arg_vars:
                if var in self.tainted_vars:
                    source_param = self.tainted_vars[var]
                    self.parameter_flows[source_param].append({
                        'event': 'function_call',
                        'line': node.lineno,
                        'function': func_name,
                        'variable': var,
                        'code': self._get_line(node.lineno)
                    })
        
        # Check keyword arguments
        for keyword in node.keywords:
            arg_vars = self._extract_variables(keyword.value)
            for var in arg_vars:
                if var in self.tainted_vars:
                    source_param = self.tainted_vars[var]
                    self.parameter_flows[source_param].append({
                        'event': 'function_call',
                        'line': node.lineno,
                        'function': func_name,
                        'argument': keyword.arg,
                        'variable': var,
                        'code': self._get_line(node.lineno)
                    })
        
        self.generic_visit(node)
    
    def _get_decorator_name(self, decorator: ast.AST) -> str:
        """Extract decorator name"""
        if isinstance(decorator, ast.Name):
            return decorator.id
        elif isinstance(decorator, ast.Attribute):
            parts = []
            node = decorator
            while isinstance(node, ast.Attribute):
                parts.append(node.attr)
                node = node.value
            if isinstance(node, ast.Name):
                parts.append(node.id)
            return '.'.join(reversed(parts))
        elif isinstance(decorator, ast.Call):
            return self._get_decorator_name(decorator.func)
        return ""
    
    def _get_call_name(self, node: ast.Call) -> str:
        """Extract function call name"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        return ""
    
    def _extract_variables(self, node: ast.AST) -> List[str]:
        """Extract all variable names from expression"""
        variables = []
        
        class VariableExtractor(ast.NodeVisitor):
            def visit_Name(self, n):
                variables.append(n.id)
        
        VariableExtractor().visit(node)
        return variables
    
    def _get_line(self, line_number: int) -> str:
        """Get source code line"""
        if 0 < line_number <= len(self.source_lines):
            return self.source_lines[line_number - 1].strip()
        return ""
    
    def get_flow_report(self) -> Dict[str, Any]:
        """Generate data flow report"""
        return {
            "filename": self.filename,
            "total_parameters": len(self.parameter_flows),
            "parameter_flows": {
                param: {
                    "total_events": len(events),
                    "events": events
                }
                for param, events in self.parameter_flows.items()
            }
        }


class TaintAnalyzer(ast.NodeVisitor):
    """
    Performs taint analysis on Python AST to detect security vulnerabilities.
    
    Tracks data flow from tainted sources (function parameters) to dangerous sinks
    (vulnerable function calls) to identify potential security issues.
    """
    
    # Dangerous sinks mapped to vulnerability types
    DANGEROUS_SINKS = {
        # Command Injection
        'os.system': VulnerabilityType.COMMAND_INJECTION,
        'os.popen': VulnerabilityType.COMMAND_INJECTION,
        'subprocess.call': VulnerabilityType.COMMAND_INJECTION,
        'subprocess.run': VulnerabilityType.COMMAND_INJECTION,
        'subprocess.Popen': VulnerabilityType.COMMAND_INJECTION,
        'commands.getoutput': VulnerabilityType.COMMAND_INJECTION,
        
        # RCE
        'eval': VulnerabilityType.RCE,
        'exec': VulnerabilityType.RCE,
        'compile': VulnerabilityType.RCE,
        '__import__': VulnerabilityType.RCE,
        'importlib.import_module': VulnerabilityType.RCE,
        'pickle.loads': VulnerabilityType.RCE,
        'pickle.load': VulnerabilityType.RCE,
        'yaml.load': VulnerabilityType.RCE,
        'marshal.loads': VulnerabilityType.RCE,
        
        # File Operations
        'open': VulnerabilityType.ARBITRARY_FILE_READ,
        'Path.read_text': VulnerabilityType.ARBITRARY_FILE_READ,
        'Path.read_bytes': VulnerabilityType.ARBITRARY_FILE_READ,
        'Path.write_text': VulnerabilityType.ARBITRARY_FILE_WRITE,
        'Path.write_bytes': VulnerabilityType.ARBITRARY_FILE_WRITE,
        
        # SQL
        'cursor.execute': VulnerabilityType.SQL_INJECTION,
        'connection.execute': VulnerabilityType.SQL_INJECTION,
        'db.execute': VulnerabilityType.SQL_INJECTION,
        
        # NoSQL
        'collection.find': VulnerabilityType.NOSQL_INJECTION,
        'collection.find_one': VulnerabilityType.NOSQL_INJECTION,
        'db.find': VulnerabilityType.NOSQL_INJECTION,
        
        # SSRF
        'requests.get': VulnerabilityType.SSRF,
        'requests.post': VulnerabilityType.SSRF,
        'httpx.get': VulnerabilityType.SSRF,
        'httpx.post': VulnerabilityType.SSRF,
        'urllib.request.urlopen': VulnerabilityType.SSRF,
        
        # SSTI
        'Template': VulnerabilityType.SSTI,
        'render_template_string': VulnerabilityType.SSTI,
    }
    
    # Sanitization functions that clean tainted data
    SANITIZERS = {
        'os.path.basename',
        'os.path.abspath',
        'html.escape',
        'urllib.parse.quote',
        'shlex.quote',
        're.escape',
        'bleach.clean',
        'validate_path',
        'sanitize',
    }
    
    def __init__(self, source_code: str, filename: str = "<unknown>"):
        self.source_code = source_code
        self.filename = filename
        self.source_lines = source_code.split('\n')
        
        # Taint tracking
        self.tainted_vars: Dict[str, TaintLevel] = {}
        self.taint_sources: List[TaintSource] = []
        self.taint_sinks: List[TaintSink] = []
        self.taint_paths: List[TaintPath] = []
        
        # Current context
        self.current_function: Optional[str] = None
        self.current_function_params: Set[str] = set()
        self.is_mcp_function: bool = False
        
        # Data flow tracking
        self.assignments: Dict[str, List[str]] = {}  # var -> [source_vars]
        self.variable_lines: Dict[str, int] = {}  # var -> line_number
        
    def analyze(self) -> List[TaintPath]:
        """
        Perform taint analysis on the source code.
        
        Returns:
            List of detected taint paths (vulnerabilities)
        """
        try:
            tree = ast.parse(self.source_code, filename=self.filename)
            self.visit(tree)
            self._find_taint_paths()
            return self.taint_paths
        except SyntaxError as e:
            logger.error(f"Syntax error in {self.filename}: {e}")
            return []
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Visit function definition to identify MCP functions and their parameters"""
        # Check if this is an MCP function
        is_mcp = False
        for decorator in node.decorator_list:
            decorator_name = self._get_decorator_name(decorator)
            if decorator_name in ['mcp.tool', 'mcp.prompt', 'mcp.resource', 'tool', 'prompt', 'resource']:
                is_mcp = True
                break
        
        if is_mcp:
            # Save previous context
            prev_function = self.current_function
            prev_params = self.current_function_params
            prev_is_mcp = self.is_mcp_function
            
            # Set new context
            self.current_function = node.name
            self.is_mcp_function = True
            self.current_function_params = set()
            
            # Mark all function parameters as tainted sources
            for arg in node.args.args:
                param_name = arg.arg
                if param_name != 'self':
                    self.current_function_params.add(param_name)
                    self.tainted_vars[param_name] = TaintLevel.TAINTED
                    self.variable_lines[param_name] = node.lineno
                    
                    # Record as taint source
                    source = TaintSource(
                        name=param_name,
                        node=arg,
                        function_name=node.name,
                        line_number=node.lineno
                    )
                    self.taint_sources.append(source)
            
            # Visit function body
            self.generic_visit(node)
            
            # Restore previous context
            self.current_function = prev_function
            self.current_function_params = prev_params
            self.is_mcp_function = prev_is_mcp
        else:
            self.generic_visit(node)
    
    def visit_Assign(self, node: ast.Assign):
        """Track variable assignments for data flow analysis"""
        if not self.is_mcp_function:
            self.generic_visit(node)
            return
        
        # Get assigned variable names
        target_vars = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                target_vars.append(target.id)
            elif isinstance(target, ast.Tuple):
                for elt in target.elts:
                    if isinstance(elt, ast.Name):
                        target_vars.append(elt.id)
        
        # Get source variables from the value
        source_vars = self._extract_variables(node.value)
        
        # Propagate taint
        for target_var in target_vars:
            self.variable_lines[target_var] = node.lineno
            self.assignments[target_var] = source_vars
            
            # Check if any source is tainted
            is_tainted = any(
                self.tainted_vars.get(src, TaintLevel.SAFE) == TaintLevel.TAINTED
                for src in source_vars
            )
            
            # Check if sanitized
            is_sanitized = self._is_sanitized(node.value)
            
            if is_sanitized:
                self.tainted_vars[target_var] = TaintLevel.SANITIZED
            elif is_tainted:
                self.tainted_vars[target_var] = TaintLevel.TAINTED
            else:
                self.tainted_vars[target_var] = TaintLevel.SAFE
        
        self.generic_visit(node)
    
    def visit_AugAssign(self, node: ast.AugAssign):
        """Track augmented assignments (+=, etc.)"""
        if not self.is_mcp_function:
            self.generic_visit(node)
            return
        
        if isinstance(node.target, ast.Name):
            target_var = node.target.id
            source_vars = self._extract_variables(node.value)
            
            # Augmented assignment uses both target and value
            all_sources = [target_var] + source_vars
            self.assignments[target_var] = all_sources
            
            # Propagate taint
            is_tainted = any(
                self.tainted_vars.get(src, TaintLevel.SAFE) == TaintLevel.TAINTED
                for src in all_sources
            )
            
            if is_tainted:
                self.tainted_vars[target_var] = TaintLevel.TAINTED
        
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call):
        """Detect dangerous function calls (sinks) with tainted arguments"""
        if not self.is_mcp_function:
            self.generic_visit(node)
            return
        
        # Get function name
        func_name = self._get_call_name(node)
        
        # Check if this is a dangerous sink
        vuln_type = None
        for sink_pattern, vtype in self.DANGEROUS_SINKS.items():
            if func_name == sink_pattern or func_name.endswith('.' + sink_pattern):
                vuln_type = vtype
                break
        
        if vuln_type:
            # Check if any argument is tainted
            tainted_args = []
            for arg in node.args:
                arg_vars = self._extract_variables(arg)
                for var in arg_vars:
                    if self.tainted_vars.get(var, TaintLevel.SAFE) == TaintLevel.TAINTED:
                        tainted_args.append(var)
            
            # Check keyword arguments
            for keyword in node.keywords:
                arg_vars = self._extract_variables(keyword.value)
                for var in arg_vars:
                    if self.tainted_vars.get(var, TaintLevel.SAFE) == TaintLevel.TAINTED:
                        tainted_args.append(var)
            
            # Special checks for specific sinks
            if func_name in ['subprocess.run', 'subprocess.call', 'subprocess.Popen']:
                # Check for shell=True
                has_shell_true = any(
                    kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords
                )
                if not has_shell_true and not tainted_args:
                    # shell=False with list args is safer
                    self.generic_visit(node)
                    return
            
            if func_name == 'open':
                # Determine if read or write based on mode
                mode = 'r'
                for kw in node.keywords:
                    if kw.arg == 'mode' and isinstance(kw.value, ast.Constant):
                        mode = kw.value.value
                
                if 'w' in mode or 'a' in mode:
                    vuln_type = VulnerabilityType.ARBITRARY_FILE_WRITE
                else:
                    vuln_type = VulnerabilityType.ARBITRARY_FILE_READ
            
            if tainted_args:
                # Record sink
                sink = TaintSink(
                    sink_type=vuln_type,
                    function_name=func_name,
                    node=node,
                    line_number=node.lineno,
                    description=f"Tainted data flows to {func_name}"
                )
                self.taint_sinks.append(sink)
        
        self.generic_visit(node)
    
    def _get_decorator_name(self, decorator: ast.AST) -> str:
        """Extract decorator name from AST node"""
        if isinstance(decorator, ast.Name):
            return decorator.id
        elif isinstance(decorator, ast.Attribute):
            parts = []
            node = decorator
            while isinstance(node, ast.Attribute):
                parts.append(node.attr)
                node = node.value
            if isinstance(node, ast.Name):
                parts.append(node.id)
            return '.'.join(reversed(parts))
        elif isinstance(decorator, ast.Call):
            return self._get_decorator_name(decorator.func)
        return ""
    
    def _get_call_name(self, node: ast.Call) -> str:
        """Extract function call name from AST node"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        return ""
    
    def _extract_variables(self, node: ast.AST) -> List[str]:
        """Extract all variable names used in an expression"""
        variables = []
        
        class VariableExtractor(ast.NodeVisitor):
            def visit_Name(self, n):
                variables.append(n.id)
        
        VariableExtractor().visit(node)
        return variables
    
    def _is_sanitized(self, node: ast.AST) -> bool:
        """Check if an expression applies sanitization"""
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node)
            return any(sanitizer in func_name for sanitizer in self.SANITIZERS)
        return False
    
    def _find_taint_paths(self):
        """Find complete paths from tainted sources to dangerous sinks"""
        for sink in self.taint_sinks:
            # Get tainted variables at this sink
            sink_vars = self._extract_variables(sink.node)
            
            for var in sink_vars:
                if self.tainted_vars.get(var, TaintLevel.SAFE) == TaintLevel.TAINTED:
                    # Trace back to source
                    path = self._trace_to_source(var)
                    
                    if path:
                        # Find the original source
                        source_var = path[0][0]
                        source = next(
                            (s for s in self.taint_sources if s.name == source_var),
                            None
                        )
                        
                        if source:
                            taint_path = TaintPath(
                                source=source,
                                sink=sink,
                                path=path,
                                severity=self._determine_severity(sink.sink_type)
                            )
                            self.taint_paths.append(taint_path)
    
    def _trace_to_source(self, var: str) -> List[Tuple[str, int]]:
        """Trace a variable back to its tainted source"""
        path = []
        visited = set()
        
        def trace(v: str):
            if v in visited:
                return
            visited.add(v)
            
            line = self.variable_lines.get(v, 0)
            path.append((v, line))
            
            # If this is a parameter (source), stop
            if v in self.current_function_params:
                return
            
            # Trace back through assignments
            if v in self.assignments:
                for source_var in self.assignments[v]:
                    if self.tainted_vars.get(source_var, TaintLevel.SAFE) == TaintLevel.TAINTED:
                        trace(source_var)
                        return
        
        trace(var)
        return list(reversed(path))
    
    def _determine_severity(self, vuln_type: VulnerabilityType) -> str:
        """Determine severity based on vulnerability type"""
        high_severity = {
            VulnerabilityType.RCE,
            VulnerabilityType.COMMAND_INJECTION,
            VulnerabilityType.SQL_INJECTION,
            VulnerabilityType.ARBITRARY_FILE_WRITE,
        }
        
        if vuln_type in high_severity:
            return "HIGH"
        else:
            return "MEDIUM"
    
    def get_report(self) -> Dict[str, Any]:
        """Generate a comprehensive taint analysis report"""
        return {
            "filename": self.filename,
            "total_sources": len(self.taint_sources),
            "total_sinks": len(self.taint_sinks),
            "total_vulnerabilities": len(self.taint_paths),
            "sources": [
                {
                    "name": s.name,
                    "function": s.function_name,
                    "line": s.line_number
                }
                for s in self.taint_sources
            ],
            "sinks": [
                {
                    "type": s.sink_type.value,
                    "function": s.function_name,
                    "line": s.line_number,
                    "description": s.description
                }
                for s in self.taint_sinks
            ],
            "vulnerabilities": [
                {
                    "severity": p.severity,
                    "type": p.sink.sink_type.value,
                    "source": {
                        "name": p.source.name,
                        "line": p.source.line_number,
                        "function": p.source.function_name
                    },
                    "sink": {
                        "function": p.sink.function_name,
                        "line": p.sink.line_number
                    },
                    "path": str(p),
                    "code_snippet": self._get_code_snippet(p.sink.line_number)
                }
                for p in self.taint_paths
            ]
        }
    
    def _get_code_snippet(self, line_number: int, context: int = 2) -> str:
        """Get code snippet around a line"""
        start = max(0, line_number - context - 1)
        end = min(len(self.source_lines), line_number + context)
        lines = self.source_lines[start:end]
        return '\n'.join(f"{start + i + 1:4d}: {line}" for i, line in enumerate(lines))


def analyze_file(filepath: str) -> Dict[str, Any]:
    """
    Analyze a Python file for taint vulnerabilities.
    
    Args:
        filepath: Path to Python file
        
    Returns:
        Taint analysis report
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        source_code = f.read()
    
    analyzer = TaintAnalyzer(source_code, filepath)
    analyzer.analyze()
    return analyzer.get_report()


def analyze_code(source_code: str, filename: str = "<string>") -> Dict[str, Any]:
    """
    Analyze Python source code for taint vulnerabilities.
    
    Args:
        source_code: Python source code as string
        filename: Optional filename for reporting
        
    Returns:
        Taint analysis report
    """
    analyzer = TaintAnalyzer(source_code, filename)
    analyzer.analyze()
    return analyzer.get_report()


class MultiFileTaintAnalyzer:
    """
    Performs taint analysis across multiple Python files.
    
    Tracks data flow across file boundaries through imports and function calls.
    """
    
    def __init__(self):
        self.files: Dict[str, TaintAnalyzer] = {}
        self.all_taint_paths: List[TaintPath] = []
        self.cross_file_flows: List[Dict[str, Any]] = []
        
    def add_file(self, filepath: str, source_code: Optional[str] = None):
        """
        Add a file to the multi-file analysis.
        
        Args:
            filepath: Path to the file
            source_code: Optional source code (if None, reads from file)
        """
        if source_code is None:
            with open(filepath, 'r', encoding='utf-8') as f:
                source_code = f.read()
        
        analyzer = TaintAnalyzer(source_code, filepath)
        self.files[filepath] = analyzer
    
    def add_directory(self, directory: str, pattern: str = "*.py", recursive: bool = True):
        """
        Add all Python files from a directory.
        
        Args:
            directory: Directory path
            pattern: File pattern (default: *.py)
            recursive: Whether to search recursively
        """
        from pathlib import Path
        
        dir_path = Path(directory)
        
        if recursive:
            files = dir_path.rglob(pattern)
        else:
            files = dir_path.glob(pattern)
        
        for filepath in files:
            if filepath.is_file():
                try:
                    self.add_file(str(filepath))
                except Exception as e:
                    logger.warning(f"Failed to add {filepath}: {e}")
    
    def analyze(self) -> Dict[str, Any]:
        """
        Perform taint analysis on all files.
        
        Returns:
            Comprehensive multi-file analysis report
        """
        # Analyze each file individually
        file_reports = {}
        for filepath, analyzer in self.files.items():
            try:
                analyzer.analyze()
                file_reports[filepath] = analyzer.get_report()
                self.all_taint_paths.extend(analyzer.taint_paths)
            except Exception as e:
                logger.error(f"Error analyzing {filepath}: {e}")
                file_reports[filepath] = {
                    "error": str(e),
                    "total_vulnerabilities": 0
                }
        
        # Aggregate results
        total_sources = sum(r.get('total_sources', 0) for r in file_reports.values())
        total_sinks = sum(r.get('total_sinks', 0) for r in file_reports.values())
        total_vulns = sum(r.get('total_vulnerabilities', 0) for r in file_reports.values())
        
        # Group vulnerabilities by type
        vulns_by_type = {}
        vulns_by_severity = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        vulns_by_file = {}
        
        for filepath, report in file_reports.items():
            if 'vulnerabilities' in report:
                vulns_by_file[filepath] = len(report['vulnerabilities'])
                
                for vuln in report['vulnerabilities']:
                    vtype = vuln['type']
                    vulns_by_type[vtype] = vulns_by_type.get(vtype, 0) + 1
                    
                    severity = vuln.get('severity', 'MEDIUM')
                    vulns_by_severity[severity] = vulns_by_severity.get(severity, 0) + 1
        
        return {
            "total_files": len(self.files),
            "total_sources": total_sources,
            "total_sinks": total_sinks,
            "total_vulnerabilities": total_vulns,
            "vulnerabilities_by_type": vulns_by_type,
            "vulnerabilities_by_severity": vulns_by_severity,
            "vulnerabilities_by_file": vulns_by_file,
            "file_reports": file_reports,
            "all_vulnerabilities": self._get_all_vulnerabilities(file_reports)
        }
    
    def _get_all_vulnerabilities(self, file_reports: Dict[str, Dict]) -> List[Dict[str, Any]]:
        """Extract all vulnerabilities from file reports"""
        all_vulns = []
        
        for filepath, report in file_reports.items():
            if 'vulnerabilities' in report:
                for vuln in report['vulnerabilities']:
                    vuln_copy = vuln.copy()
                    vuln_copy['file'] = filepath
                    all_vulns.append(vuln_copy)
        
        # Sort by severity (HIGH first)
        severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        all_vulns.sort(key=lambda v: severity_order.get(v.get('severity', 'MEDIUM'), 1))
        
        return all_vulns
    
    def get_summary(self) -> str:
        """Get a human-readable summary of the analysis"""
        report = self.analyze()
        
        lines = []
        lines.append("=" * 80)
        lines.append("  MULTI-FILE TAINT ANALYSIS SUMMARY")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"📁 Files Analyzed: {report['total_files']}")
        lines.append(f"📍 Taint Sources: {report['total_sources']}")
        lines.append(f"⚠️  Dangerous Sinks: {report['total_sinks']}")
        lines.append(f"🔴 Total Vulnerabilities: {report['total_vulnerabilities']}")
        lines.append("")
        
        if report['vulnerabilities_by_severity']:
            lines.append("Severity Breakdown:")
            for severity in ['HIGH', 'MEDIUM', 'LOW']:
                count = report['vulnerabilities_by_severity'].get(severity, 0)
                if count > 0:
                    emoji = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}[severity]
                    lines.append(f"  {emoji} {severity}: {count}")
            lines.append("")
        
        if report['vulnerabilities_by_type']:
            lines.append("Vulnerability Types:")
            for vtype, count in sorted(report['vulnerabilities_by_type'].items(), 
                                      key=lambda x: x[1], reverse=True):
                lines.append(f"  - {vtype}: {count}")
            lines.append("")
        
        if report['vulnerabilities_by_file']:
            lines.append("Files with Vulnerabilities:")
            for filepath, count in sorted(report['vulnerabilities_by_file'].items(), 
                                         key=lambda x: x[1], reverse=True):
                lines.append(f"  - {filepath}: {count} vulnerabilities")
            lines.append("")
        
        lines.append("=" * 80)
        
        return "\n".join(lines)
    
    def get_detailed_report(self) -> str:
        """Get a detailed report with all vulnerabilities"""
        report = self.analyze()
        
        lines = []
        lines.append(self.get_summary())
        lines.append("")
        
        if report['all_vulnerabilities']:
            lines.append("=" * 80)
            lines.append("  DETAILED VULNERABILITY REPORT")
            lines.append("=" * 80)
            lines.append("")
            
            for i, vuln in enumerate(report['all_vulnerabilities'], 1):
                severity_emoji = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}.get(
                    vuln.get('severity', 'MEDIUM'), "⚪"
                )
                
                lines.append(f"{i}. {severity_emoji} {vuln['type']} [{vuln['severity']}]")
                lines.append(f"   File: {vuln['file']}")
                lines.append(f"   Source: {vuln['source']['name']} (line {vuln['source']['line']})")
                lines.append(f"   Sink: {vuln['sink']['function']} (line {vuln['sink']['line']})")
                lines.append(f"   Path: {vuln['path']}")
                
                if 'code_snippet' in vuln:
                    lines.append(f"\n   Code:")
                    for line in vuln['code_snippet'].split('\n'):
                        lines.append(f"     {line}")
                
                lines.append("")
        
        return "\n".join(lines)


def analyze_directory(directory: str, pattern: str = "*.py", recursive: bool = True) -> Dict[str, Any]:
    """
    Analyze all Python files in a directory for taint vulnerabilities.
    
    Args:
        directory: Directory path
        pattern: File pattern (default: *.py)
        recursive: Whether to search recursively
        
    Returns:
        Multi-file taint analysis report
    """
    analyzer = MultiFileTaintAnalyzer()
    analyzer.add_directory(directory, pattern, recursive)
    return analyzer.analyze()


def track_data_flow(source_code: str, filename: str = "<string>") -> Dict[str, Any]:
    """
    Track data flow paths for parameters without vulnerability detection.
    
    Args:
        source_code: Python source code as string
        filename: Optional filename for reporting
        
    Returns:
        Data flow report showing where each parameter flows
    """
    tracker = DataFlowTracker(source_code, filename)
    return tracker.analyze()


def track_data_flow_file(filepath: str) -> Dict[str, Any]:
    """
    Track data flow paths in a Python file.
    
    Args:
        filepath: Path to Python file
        
    Returns:
        Data flow report
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        source_code = f.read()
    
    return track_data_flow(source_code, filepath)
