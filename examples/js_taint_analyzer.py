#!/usr/bin/env python3
"""
JavaScript/TypeScript Taint Analysis

Tracks data flow from sources (user input) to sinks (dangerous functions)
in JavaScript and TypeScript code.
"""

import re
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
    taint_level: str = "high"  # high, medium, low
    propagated_from: Optional[str] = None


@dataclass
class TaintFlow:
    """Represents a complete taint flow from source to sink"""
    source_var: str
    source_type: TaintSource
    source_line: int
    sink_function: str
    sink_type: TaintSink
    sink_line: int
    flow_path: List[str] = field(default_factory=list)
    severity: str = "high"


class JSTaintAnalyzer:
    """Taint analyzer for JavaScript/TypeScript code"""
    
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
        
        # Propagation patterns (how taint spreads)
        self.propagation_patterns = [
            r'(\w+)\s*=\s*([^;]+)',  # assignment
            r'const\s+(\w+)\s*=\s*([^;]+)',  # const declaration
            r'let\s+(\w+)\s*=\s*([^;]+)',  # let declaration
            r'var\s+(\w+)\s*=\s*([^;]+)',  # var declaration
        ]
        
        # String operations that propagate taint
        self.string_operations = [
            'concat', 'replace', 'substring', 'substr', 'slice',
            'toLowerCase', 'toUpperCase', 'trim', 'split', 'join'
        ]
    
    def analyze(self, code: str, filename: str = "unknown") -> Dict:
        """Analyze JavaScript/TypeScript code for taint flows
        
        Args:
            code: Source code to analyze
            filename: Name of the file being analyzed
            
        Returns:
            Dictionary with taint analysis results
        """
        lines = code.split('\n')
        
        # Track tainted variables
        tainted_vars: Dict[str, TaintedVariable] = {}
        
        # Find all taint sources
        sources = self._find_sources(lines)
        for source in sources:
            tainted_vars[source.name] = source
        
        # Propagate taint through assignments
        tainted_vars = self._propagate_taint(lines, tainted_vars)
        
        # Find flows to sinks
        flows = self._find_flows_to_sinks(lines, tainted_vars)
        
        return {
            'filename': filename,
            'total_sources': len(sources),
            'total_tainted_vars': len(tainted_vars),
            'total_flows': len(flows),
            'sources': sources,
            'tainted_variables': list(tainted_vars.values()),
            'flows': flows,
        }
    
    def _find_sources(self, lines: List[str]) -> List[TaintedVariable]:
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
                        # Extract parameter name (handle destructuring)
                        param_name = self._extract_param_name(param)
                        if param_name:
                            sources.append(TaintedVariable(
                                name=param_name,
                                source=TaintSource.FUNCTION_PARAMETER,
                                line=line_num,
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
                                taint_level="high"
                            ))
        
        return sources
    
    def _extract_param_name(self, param: str) -> Optional[str]:
        """Extract parameter name from parameter declaration"""
        # Handle: param, param = default, {destructured}, [array]
        param = param.strip()
        
        # Remove default values
        if '=' in param:
            param = param.split('=')[0].strip()
        
        # Handle destructured parameters: { path }, { url }, etc.
        if param.startswith('{') and param.endswith('}'):
            # Extract property names from destructuring
            inner = param[1:-1].strip()
            # For now, return the first property
            props = [p.strip().split(':')[0].strip() for p in inner.split(',')]
            return props[0] if props and props[0] else None
        
        # Skip array destructuring for now
        if param.startswith('['):
            return None
        
        # Remove type annotations (TypeScript)
        if ':' in param:
            param = param.split(':')[0].strip()
        
        return param if param and param.isidentifier() else None
    
    def _propagate_taint(self, lines: List[str], tainted_vars: Dict[str, TaintedVariable]) -> Dict[str, TaintedVariable]:
        """Propagate taint through variable assignments"""
        # Multiple passes to handle complex flows
        for _ in range(5):  # Max 5 propagation passes
            new_tainted = {}
            
            for line_num, line in enumerate(lines, 1):
                # Check for assignments
                for pattern in self.propagation_patterns:
                    match = re.search(pattern, line)
                    if match:
                        target_var = match.group(1)
                        source_expr = match.group(2)
                        
                        # Check if source expression contains tainted variables
                        for tainted_var in tainted_vars:
                            if tainted_var in source_expr:
                                # Propagate taint
                                if target_var not in tainted_vars:
                                    new_tainted[target_var] = TaintedVariable(
                                        name=target_var,
                                        source=tainted_vars[tainted_var].source,
                                        line=line_num,
                                        taint_level=tainted_vars[tainted_var].taint_level,
                                        propagated_from=tainted_var
                                    )
                                break
            
            # Add newly tainted variables
            if not new_tainted:
                break  # No new taint propagation
            
            tainted_vars.update(new_tainted)
        
        return tainted_vars
    
    def _find_flows_to_sinks(self, lines: List[str], tainted_vars: Dict[str, TaintedVariable]) -> List[TaintFlow]:
        """Find taint flows from sources to dangerous sinks"""
        flows = []
        
        for line_num, line in enumerate(lines, 1):
            # Check each sink type
            for sink_type, patterns in self.sink_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line):
                        # Found a sink, check if tainted data flows into it
                        for var_name, tainted_var in tainted_vars.items():
                            if var_name in line or var_name.split('.')[-1] in line:
                                # Build flow path
                                flow_path = self._build_flow_path(tainted_var, tainted_vars)
                                
                                flows.append(TaintFlow(
                                    source_var=tainted_var.name,
                                    source_type=tainted_var.source,
                                    source_line=tainted_var.line,
                                    sink_function=re.search(pattern, line).group(0),
                                    sink_type=sink_type,
                                    sink_line=line_num,
                                    flow_path=flow_path,
                                    severity=self._calculate_severity(tainted_var.source, sink_type)
                                ))
        
        return flows
    
    def _build_flow_path(self, tainted_var: TaintedVariable, all_tainted: Dict[str, TaintedVariable]) -> List[str]:
        """Build the complete flow path for a tainted variable"""
        path = [tainted_var.name]
        current = tainted_var
        
        # Trace back through propagations
        while current.propagated_from:
            path.insert(0, current.propagated_from)
            current = all_tainted.get(current.propagated_from)
            if not current:
                break
        
        return path
    
    def _calculate_severity(self, source: TaintSource, sink: TaintSink) -> str:
        """Calculate severity based on source and sink combination"""
        # High severity combinations
        high_risk = [
            (TaintSource.ARGS_OBJECT, TaintSink.EXEC),
            (TaintSource.ARGS_OBJECT, TaintSink.COMMAND),
            (TaintSource.FUNCTION_PARAMETER, TaintSink.EXEC),
            (TaintSource.FUNCTION_PARAMETER, TaintSink.COMMAND),
            (TaintSource.REQUEST_BODY, TaintSink.SQL_QUERY),
        ]
        
        if (source, sink) in high_risk:
            return "high"
        
        # Medium severity
        medium_risk = [
            (TaintSource.ARGS_OBJECT, TaintSink.FILE_SYSTEM),
            (TaintSource.ARGS_OBJECT, TaintSink.NETWORK),
            (TaintSource.FUNCTION_PARAMETER, TaintSink.FILE_SYSTEM),
            (TaintSource.FUNCTION_PARAMETER, TaintSink.NETWORK),
            (TaintSource.REQUEST_QUERY, TaintSink.SQL_QUERY),
            (TaintSource.REQUEST_PARAMS, TaintSink.FILE_SYSTEM),
        ]
        
        if (source, sink) in medium_risk:
            return "medium"
        
        return "low"
    
    def format_report(self, results: Dict) -> str:
        """Format analysis results as a readable report"""
        report = []
        report.append("=" * 80)
        report.append(f"  JavaScript/TypeScript Taint Analysis Report")
        report.append("=" * 80)
        report.append(f"\nFile: {results['filename']}")
        report.append(f"Total Sources: {results['total_sources']}")
        report.append(f"Total Tainted Variables: {results['total_tainted_vars']}")
        report.append(f"Total Flows to Sinks: {results['total_flows']}")
        
        if results['flows']:
            report.append("\n" + "=" * 80)
            report.append("  TAINT FLOWS DETECTED")
            report.append("=" * 80)
            
            for i, flow in enumerate(results['flows'], 1):
                severity_icon = "🔴" if flow.severity == "high" else "🟠" if flow.severity == "medium" else "🟡"
                report.append(f"\n{severity_icon} Flow #{i} [{flow.severity.upper()}]")
                report.append(f"   Source: {flow.source_var} ({flow.source_type.value}) at line {flow.source_line}")
                report.append(f"   Sink: {flow.sink_function} ({flow.sink_type.value}) at line {flow.sink_line}")
                if flow.flow_path:
                    report.append(f"   Flow Path: {' → '.join(flow.flow_path)}")
        else:
            report.append("\n✅ No taint flows detected")
        
        return "\n".join(report)


def test_mcp_server_code():
    """Test with MCP server code examples"""
    
    # Example 1: Command injection via args
    code1 = """
server.setRequestHandler(CallToolRequest, async (request) => {
    const { name, arguments: args } = request.params;
    
    if (name === "execute_command") {
        const command = args.command;
        const { exec } = require('child_process');
        
        // Dangerous: command injection
        exec(command, (error, stdout, stderr) => {
            return { content: [{ type: "text", text: stdout }] };
        });
    }
});
"""
    
    # Example 2: File read via args
    code2 = """
server.tool("read_file", async ({ path }) => {
    const fs = require('fs');
    const filePath = path;
    
    // Dangerous: arbitrary file read
    const content = fs.readFileSync(filePath, 'utf-8');
    
    return {
        content: [{ type: "text", text: content }]
    };
});
"""
    
    # Example 3: SSRF via fetch
    code3 = """
server.registerTool("fetch_url", async ({ url }) => {
    const targetUrl = url;
    
    // Dangerous: SSRF
    const response = await fetch(targetUrl);
    const data = await response.text();
    
    return { content: [{ type: "text", text: data }] };
});
"""
    
    analyzer = JSTaintAnalyzer()
    
    print("\n" + "=" * 80)
    print("  TESTING JS/TS TAINT ANALYZER")
    print("=" * 80)
    
    # Test 1
    print("\n\n📝 Test 1: Command Injection")
    print("-" * 80)
    results1 = analyzer.analyze(code1, "command_injection.js")
    print(analyzer.format_report(results1))
    
    # Test 2
    print("\n\n📝 Test 2: Arbitrary File Read")
    print("-" * 80)
    results2 = analyzer.analyze(code2, "file_read.js")
    print(analyzer.format_report(results2))
    
    # Test 3
    print("\n\n📝 Test 3: SSRF")
    print("-" * 80)
    results3 = analyzer.analyze(code3, "ssrf.js")
    print(analyzer.format_report(results3))


if __name__ == "__main__":
    test_mcp_server_code()
