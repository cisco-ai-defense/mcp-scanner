"""
JavaScript/TypeScript Call Chain Tracker

Tracks complete function call chains across multiple files:
- function add(a, b) calls function process(c, d)
- function process(c, d) calls function execute(e, f)
- Tracks parameter flow through the entire chain
"""

import re
import logging
from pathlib import Path
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class FunctionDefinition:
    """Represents a function definition"""
    name: str
    file: str
    line: int
    parameters: List[str]
    body: str
    calls_functions: List[str] = field(default_factory=list)
    is_exported: bool = False


@dataclass
class FunctionCall:
    """Represents a function call"""
    caller_function: str
    caller_file: str
    caller_line: int
    called_function: str
    arguments: List[str]  # Variable names passed as arguments
    resolved_file: Optional[str] = None  # Where the called function is defined


@dataclass
class CallChain:
    """Represents a complete call chain"""
    chain: List[FunctionCall]
    source_params: List[str]  # Original parameters from entry point
    reaches_sink: bool = False
    sink_type: Optional[str] = None
    severity: str = "low"


class JSCallChainTracker:
    """Tracks function call chains across multiple JavaScript/TypeScript files"""
    
    def __init__(self):
        # Dangerous sinks
        self.sinks = {
            'exec': ['exec(', 'execSync(', 'eval(', 'Function('],
            'command': ['spawn(', 'spawnSync(', 'execFile(', 'execFileSync('],
            'file_system': ['readFile(', 'readFileSync(', 'writeFile(', 'writeFileSync(',
                           'unlink(', 'unlinkSync(', 'open(', 'openSync('],
            'network': ['fetch(', 'axios.', 'http.request(', 'https.request(', 'request('],
            'sql_query': ['.query(', '.execute(', '.run(', 'db.'],
        }
        
        # Storage
        self.files: Dict[str, str] = {}  # filepath -> code
        self.functions: Dict[str, Dict[str, FunctionDefinition]] = {}  # file -> {func_name -> FunctionDef}
        self.function_calls: List[FunctionCall] = []
        self.imports: Dict[str, Dict[str, str]] = {}  # file -> {imported_name -> source_file}
        self.exports: Dict[str, Set[str]] = {}  # file -> {exported_function_names}
        self.call_chains: List[CallChain] = []
    
    def add_file(self, filepath: str, code: Optional[str] = None):
        """Add a file to analyze"""
        if code is None:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
            except Exception as e:
                logger.warning(f"Could not read {filepath}: {e}")
                return
        
        self.files[filepath] = code
    
    def add_directory(self, directory: str, pattern: str = "*.js", recursive: bool = True):
        """Add all matching files from a directory"""
        dir_path = Path(directory)
        
        if recursive:
            files = dir_path.rglob(pattern)
        else:
            files = dir_path.glob(pattern)
        
        for file_path in files:
            if file_path.is_file():
                self.add_file(str(file_path))
    
    def analyze(self) -> Dict[str, Any]:
        """Analyze all files and build call chains"""
        
        # Phase 1: Extract all function definitions
        for filepath, code in self.files.items():
            self._extract_functions(filepath, code)
        
        # Phase 2: Extract imports and exports
        for filepath, code in self.files.items():
            self._extract_imports_exports(filepath, code)
        
        # Phase 3: Find all function calls
        for filepath, code in self.files.items():
            self._extract_function_calls(filepath, code)
        
        # Phase 4: Build call chains
        self._build_call_chains()
        
        # Phase 5: Check if chains reach sinks
        self._check_chains_reach_sinks()
        
        return self._generate_report()
    
    def _extract_functions(self, filepath: str, code: str):
        """Extract all function definitions from a file"""
        self.functions[filepath] = {}
        lines = code.split('\n')
        
        # Function patterns
        patterns = [
            # function name(params) { }
            r'function\s+(\w+)\s*\(([^)]*)\)\s*{',
            # async function name(params) { }
            r'async\s+function\s+(\w+)\s*\(([^)]*)\)\s*{',
            # const name = (params) => { }
            r'const\s+(\w+)\s*=\s*\(([^)]*)\)\s*=>\s*{',
            # const name = async (params) => { }
            r'const\s+(\w+)\s*=\s*async\s*\(([^)]*)\)\s*=>\s*{',
            # export function name(params) { }
            r'export\s+function\s+(\w+)\s*\(([^)]*)\)\s*{',
            # export const name = (params) => { }
            r'export\s+const\s+(\w+)\s*=\s*\(([^)]*)\)\s*=>\s*{',
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in patterns:
                match = re.search(pattern, line)
                if match:
                    func_name = match.group(1)
                    params_str = match.group(2)
                    params = self._parse_parameters(params_str)
                    
                    # Extract function body (simplified - just get next 50 lines)
                    body_lines = lines[line_num:min(line_num + 50, len(lines))]
                    body = '\n'.join(body_lines)
                    
                    is_exported = 'export' in line
                    
                    self.functions[filepath][func_name] = FunctionDefinition(
                        name=func_name,
                        file=filepath,
                        line=line_num,
                        parameters=params,
                        body=body,
                        is_exported=is_exported
                    )
                    break
    
    def _parse_parameters(self, params_str: str) -> List[str]:
        """Parse function parameters"""
        params = []
        
        for param in params_str.split(','):
            param = param.strip()
            if not param:
                continue
            
            # Remove default values
            if '=' in param:
                param = param.split('=')[0].strip()
            
            # Handle destructured parameters: { path }, { url }
            if param.startswith('{') and param.endswith('}'):
                inner = param[1:-1].strip()
                for prop in inner.split(','):
                    prop = prop.strip().split(':')[0].strip()
                    if prop:
                        params.append(prop)
            elif not param.startswith('['):
                # Remove type annotations
                if ':' in param:
                    param = param.split(':')[0].strip()
                if param and param.replace('_', '').replace('$', '').isalnum():
                    params.append(param)
        
        return params
    
    def _extract_imports_exports(self, filepath: str, code: str):
        """Extract imports and exports"""
        self.imports[filepath] = {}
        self.exports[filepath] = set()
        
        lines = code.split('\n')
        
        for line in lines:
            # import { foo } from './bar'
            match = re.search(r'import\s+{\s*([^}]+)\s*}\s+from\s+["\']([^"\']+)["\']', line)
            if match:
                names = match.group(1)
                module = match.group(2)
                
                # Resolve module path
                resolved = self._resolve_import(module, filepath)
                if resolved:
                    for name in names.split(','):
                        name = name.strip().split(' as ')[0].strip()
                        self.imports[filepath][name] = resolved
            
            # import foo from './bar'
            match = re.search(r'import\s+(\w+)\s+from\s+["\']([^"\']+)["\']', line)
            if match:
                name = match.group(1)
                module = match.group(2)
                resolved = self._resolve_import(module, filepath)
                if resolved:
                    self.imports[filepath][name] = resolved
            
            # export function foo
            match = re.search(r'export\s+(?:function|const)\s+(\w+)', line)
            if match:
                self.exports[filepath].add(match.group(1))
    
    def _resolve_import(self, module_path: str, importing_file: str) -> Optional[str]:
        """Resolve import path to actual file"""
        if not module_path.startswith('.'):
            return None  # External module
        
        importing_dir = Path(importing_file).parent
        resolved = (importing_dir / module_path).resolve()
        
        # Try common extensions
        for ext in ['', '.js', '.ts', '.jsx', '.tsx', '/index.js', '/index.ts']:
            candidate = str(resolved) + ext
            if candidate in self.files:
                return candidate
        
        return None
    
    def _extract_function_calls(self, filepath: str, code: str):
        """Extract all function calls in a file"""
        lines = code.split('\n')
        
        # Find which function we're currently in
        current_function = None
        
        for line_num, line in enumerate(lines, 1):
            # Check if we're entering a function
            for func_name, func_def in self.functions.get(filepath, {}).items():
                if func_def.line == line_num:
                    current_function = func_name
                    break
            
            # Find function calls in this line
            # Pattern: functionName(arg1, arg2, ...)
            for match in re.finditer(r'(\w+)\s*\(([^)]*)\)', line):
                called_func = match.group(1)
                args_str = match.group(2)
                
                # Skip if it's a method call (has a dot before it)
                if line[:match.start()].rstrip().endswith('.'):
                    continue
                
                # Parse arguments
                args = [arg.strip() for arg in args_str.split(',') if arg.strip()]
                
                # Resolve where this function is defined
                resolved_file = None
                if called_func in self.functions.get(filepath, {}):
                    resolved_file = filepath
                elif called_func in self.imports.get(filepath, {}):
                    resolved_file = self.imports[filepath][called_func]
                
                self.function_calls.append(FunctionCall(
                    caller_function=current_function or '<module>',
                    caller_file=filepath,
                    caller_line=line_num,
                    called_function=called_func,
                    arguments=args,
                    resolved_file=resolved_file
                ))
                
                # Track that this function calls another
                if current_function and current_function in self.functions.get(filepath, {}):
                    self.functions[filepath][current_function].calls_functions.append(called_func)
    
    def _build_call_chains(self):
        """Build complete call chains starting from entry points"""
        
        # Find entry points (MCP handlers, exported functions)
        entry_points = []
        
        for filepath, funcs in self.functions.items():
            for func_name, func_def in funcs.items():
                # Entry points are typically:
                # 1. Functions with 'handler' in name
                # 2. Functions with 'tool', 'prompt', 'resource' in name
                # 3. Exported functions with parameters
                # 4. Any function that's not called by others (top-level)
                if (any(keyword in func_name.lower() for keyword in ['handler', 'tool', 'prompt', 'resource']) 
                    or (func_def.is_exported and func_def.parameters)):
                    entry_points.append((filepath, func_name, func_def))
        
        # If no entry points found, use all exported functions
        if not entry_points:
            for filepath, funcs in self.functions.items():
                for func_name, func_def in funcs.items():
                    if func_def.is_exported or func_def.parameters:
                        entry_points.append((filepath, func_name, func_def))
        
        # Build chains from each entry point
        for filepath, func_name, func_def in entry_points:
            chains = self._trace_calls_from(filepath, func_name, func_def.parameters, [], [])
            self.call_chains.extend(chains)
    
    def _trace_calls_from(self, filepath: str, func_name: str, params: List[str], visited: List[str], current_chain: List[FunctionCall]) -> List[CallChain]:
        """Recursively trace function calls from a starting point"""
        
        # Prevent infinite recursion
        call_id = f"{filepath}:{func_name}"
        if call_id in visited:
            return []
        
        visited = visited + [call_id]
        chains = []
        
        # Find all calls made by this function
        calls_from_func = [
            call for call in self.function_calls
            if call.caller_file == filepath and call.caller_function == func_name
        ]
        
        if not calls_from_func:
            # Leaf node - return the current chain
            if current_chain:
                return [CallChain(chain=current_chain, source_params=params)]
            return []
        
        # For each call, create a chain
        for call in calls_from_func:
            # Always trace into the called function if we can resolve it
            if call.resolved_file:
                called_func_def = self.functions.get(call.resolved_file, {}).get(call.called_function)
                
                if called_func_def:
                    # Map arguments to parameters of called function
                    new_params = called_func_def.parameters
                    
                    # Recursively trace
                    sub_chains = self._trace_calls_from(
                        call.resolved_file,
                        call.called_function,
                        new_params,
                        visited,
                        current_chain + [call]
                    )
                    
                    chains.extend(sub_chains)
                else:
                    # Called function not found, end chain here
                    chains.append(CallChain(
                        chain=current_chain + [call],
                        source_params=params
                    ))
            else:
                # Can't resolve, but still record the call
                chains.append(CallChain(
                    chain=current_chain + [call],
                    source_params=params
                ))
        
        return chains if chains else [CallChain(chain=current_chain, source_params=params)]
    
    def _check_chains_reach_sinks(self):
        """Check if any call chains reach dangerous sinks"""
        
        for chain in self.call_chains:
            # Check all functions in the chain, not just the last one
            for call in chain.chain:
                # Get the function body of the called function
                if call.resolved_file:
                    func_def = self.functions.get(call.resolved_file, {}).get(call.called_function)
                    
                    if func_def:
                        # Check if function body contains sinks
                        for sink_type, sink_patterns in self.sinks.items():
                            for sink_pattern in sink_patterns:
                                if sink_pattern in func_def.body:
                                    chain.reaches_sink = True
                                    chain.sink_type = sink_type
                                    chain.severity = self._calculate_severity(len(chain.chain), sink_type)
                                    break
                            if chain.reaches_sink:
                                break
                
                if chain.reaches_sink:
                    break
            
            # Also check the caller function body (for inline sinks)
            if not chain.reaches_sink and chain.chain:
                first_call = chain.chain[0]
                caller_func = self.functions.get(first_call.caller_file, {}).get(first_call.caller_function)
                
                if caller_func:
                    for sink_type, sink_patterns in self.sinks.items():
                        for sink_pattern in sink_patterns:
                            if sink_pattern in caller_func.body:
                                chain.reaches_sink = True
                                chain.sink_type = sink_type
                                chain.severity = self._calculate_severity(len(chain.chain), sink_type)
                                break
                        if chain.reaches_sink:
                            break
    
    def _calculate_severity(self, chain_length: int, sink_type: str) -> str:
        """Calculate severity based on chain length and sink type"""
        
        # Longer chains are generally less severe (more validation opportunities)
        # But exec/command are always high risk
        if sink_type in ['exec', 'command']:
            return 'high' if chain_length <= 2 else 'medium'
        elif sink_type in ['file_system', 'network']:
            return 'medium' if chain_length <= 2 else 'low'
        else:
            return 'low'
    
    def _generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive report"""
        
        dangerous_chains = [c for c in self.call_chains if c.reaches_sink]
        
        return {
            'total_files': len(self.files),
            'total_functions': sum(len(funcs) for funcs in self.functions.values()),
            'total_function_calls': len(self.function_calls),
            'total_call_chains': len(self.call_chains),
            'dangerous_chains': len(dangerous_chains),
            'call_chains': self.call_chains,
            'functions': self.functions,
            'function_calls': self.function_calls,
            'high_severity_chains': [c for c in dangerous_chains if c.severity == 'high'],
            'medium_severity_chains': [c for c in dangerous_chains if c.severity == 'medium'],
        }
    
    def format_report(self, results: Dict[str, Any]) -> str:
        """Format analysis results"""
        lines = []
        lines.append("=" * 80)
        lines.append("  JAVASCRIPT/TYPESCRIPT CALL CHAIN ANALYSIS")
        lines.append("=" * 80)
        lines.append(f"\nTotal Files: {results['total_files']}")
        lines.append(f"Total Functions: {results['total_functions']}")
        lines.append(f"Total Function Calls: {results['total_function_calls']}")
        lines.append(f"Total Call Chains: {results['total_call_chains']}")
        lines.append(f"Dangerous Chains: {results['dangerous_chains']}")
        
        if results.get('high_severity_chains'):
            lines.append(f"\n🔴 HIGH Severity Chains: {len(results['high_severity_chains'])}")
            for i, chain in enumerate(results['high_severity_chains'][:3], 1):
                lines.append(f"\n  Chain #{i}:")
                lines.append(f"  Source Parameters: {', '.join(chain.source_params)}")
                lines.append(f"  Sink Type: {chain.sink_type}")
                lines.append(f"  Call Path ({len(chain.chain)} calls):")
                for call in chain.chain:
                    lines.append(f"    → {call.caller_function}() calls {call.called_function}()")
                    lines.append(f"      {Path(call.caller_file).name}:line {call.caller_line}")
        
        if results.get('medium_severity_chains'):
            lines.append(f"\n🟠 MEDIUM Severity Chains: {len(results['medium_severity_chains'])}")
            for i, chain in enumerate(results['medium_severity_chains'][:2], 1):
                lines.append(f"\n  Chain #{i}: {len(chain.chain)} calls → {chain.sink_type}")
        
        return '\n'.join(lines)


def test_call_chain_tracker():
    """Test the call chain tracker"""
    
    # Create test files
    file1 = """
// utils.js
export function processInput(userInput) {
    const cleaned = sanitize(userInput);
    return execute(cleaned);
}

function sanitize(input) {
    return input.trim();
}

function execute(command) {
    const { exec } = require('child_process');
    exec(command);  // SINK!
}
"""
    
    file2 = """
// server.js
import { processInput } from './utils';

server.tool("run_command", async ({ command }) => {
    // Entry point - command flows through processInput -> execute -> exec
    const result = processInput(command);
    return { content: [{ type: "text", text: result }] };
});
"""
    
    print("\n" + "=" * 80)
    print("  TESTING CALL CHAIN TRACKER")
    print("=" * 80)
    
    tracker = JSCallChainTracker()
    tracker.add_file("utils.js", file1)
    tracker.add_file("server.js", file2)
    
    results = tracker.analyze()
    
    print(tracker.format_report(results))
    
    print("\n✅ Call Chain Tracker Working!")
    print(f"   - Tracked {results['total_functions']} functions")
    print(f"   - Found {results['total_function_calls']} function calls")
    print(f"   - Built {results['total_call_chains']} call chains")
    print(f"   - Detected {results['dangerous_chains']} dangerous chains")


if __name__ == "__main__":
    test_call_chain_tracker()
