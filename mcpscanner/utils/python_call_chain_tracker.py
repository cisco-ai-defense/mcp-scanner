"""
Python Call Chain Tracker

Tracks complete function call chains across multiple Python files:
- function add(a, b) calls function process(c, d)
- function process(c, d) calls function execute(e, f)
- Tracks parameter flow through the entire chain
"""

import ast
import logging
from pathlib import Path
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class PythonFunctionDefinition:
    """Represents a Python function definition"""
    name: str
    file: str
    line: int
    parameters: List[str]
    calls_functions: List[str] = field(default_factory=list)
    is_imported: bool = False
    module: Optional[str] = None


@dataclass
class PythonFunctionCall:
    """Represents a Python function call"""
    caller_function: str
    caller_file: str
    caller_line: int
    called_function: str
    arguments: List[str]  # Variable names passed as arguments
    resolved_file: Optional[str] = None  # Where the called function is defined


@dataclass
class PythonCallChain:
    """Represents a complete call chain"""
    chain: List[PythonFunctionCall]
    source_params: List[str]  # Original parameters from entry point
    entry_function: str
    entry_file: str


class PythonCallChainTracker:
    """Tracks function call chains across multiple Python files"""
    
    def __init__(self):
        # Storage
        self.files: Dict[str, str] = {}  # filepath -> code
        self.functions: Dict[str, Dict[str, PythonFunctionDefinition]] = {}  # file -> {func_name -> FunctionDef}
        self.function_calls: List[PythonFunctionCall] = []
        self.imports: Dict[str, Dict[str, str]] = {}  # file -> {imported_name -> source_file}
        self.call_chains: List[PythonCallChain] = []
    
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
    
    def add_directory(self, directory: str, pattern: str = "*.py", recursive: bool = True):
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
        
        # Phase 2: Extract imports
        for filepath, code in self.files.items():
            self._extract_imports(filepath, code)
        
        # Phase 3: Find all function calls
        for filepath, code in self.files.items():
            self._extract_function_calls(filepath, code)
        
        # Phase 4: Build call chains
        self._build_call_chains()
        
        return self._generate_report()
    
    def _extract_functions(self, filepath: str, code: str):
        """Extract all function definitions using AST"""
        self.functions[filepath] = {}
        
        try:
            tree = ast.parse(code)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    params = [arg.arg for arg in node.args.args]
                    
                    self.functions[filepath][node.name] = PythonFunctionDefinition(
                        name=node.name,
                        file=filepath,
                        line=node.lineno,
                        parameters=params
                    )
        except Exception as e:
            logger.warning(f"Failed to parse {filepath}: {e}")
    
    def _extract_imports(self, filepath: str, code: str):
        """Extract imports using AST"""
        self.imports[filepath] = {}
        
        try:
            tree = ast.parse(code)
            
            for node in ast.walk(tree):
                # from module import function
                if isinstance(node, ast.ImportFrom):
                    if node.module:
                        for alias in node.names:
                            name = alias.asname if alias.asname else alias.name
                            # Try to resolve the module to a file
                            resolved = self._resolve_import(node.module, filepath)
                            if resolved:
                                self.imports[filepath][name] = resolved
                
                # import module
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        name = alias.asname if alias.asname else alias.name
                        resolved = self._resolve_import(alias.name, filepath)
                        if resolved:
                            self.imports[filepath][name] = resolved
        except Exception as e:
            logger.warning(f"Failed to extract imports from {filepath}: {e}")
    
    def _resolve_import(self, module_path: str, importing_file: str) -> Optional[str]:
        """Resolve an import path to an actual file"""
        # Handle relative imports
        if module_path.startswith('.'):
            importing_dir = Path(importing_file).parent
            # Convert relative import to path
            parts = module_path.split('.')
            level = len([p for p in parts if p == ''])
            module_name = [p for p in parts if p != '']
            
            target_dir = importing_dir
            for _ in range(level - 1):
                target_dir = target_dir.parent
            
            if module_name:
                target_path = target_dir / '/'.join(module_name)
            else:
                target_path = target_dir
            
            # Try common patterns
            for candidate in [
                str(target_path) + '.py',
                str(target_path / '__init__.py'),
            ]:
                if candidate in self.files:
                    return candidate
        else:
            # Absolute import - try to find in loaded files
            for filepath in self.files:
                if module_path in filepath or filepath.endswith(f"{module_path}.py"):
                    return filepath
        
        return None
    
    def _extract_function_calls(self, filepath: str, code: str):
        """Extract all function calls using AST"""
        
        try:
            tree = ast.parse(code)
            
            # Track which function we're currently in
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    current_function = node.name
                    
                    # Find all calls within this function
                    for child in ast.walk(node):
                        if isinstance(child, ast.Call):
                            # Get the function name being called
                            called_func = None
                            if isinstance(child.func, ast.Name):
                                called_func = child.func.id
                            elif isinstance(child.func, ast.Attribute):
                                # For method calls like obj.method()
                                if isinstance(child.func.value, ast.Name):
                                    called_func = child.func.attr
                            
                            if called_func:
                                # Extract argument names
                                args = []
                                for arg in child.args:
                                    if isinstance(arg, ast.Name):
                                        args.append(arg.id)
                                    elif isinstance(arg, ast.Constant):
                                        args.append(str(arg.value))
                                
                                # Resolve where this function is defined
                                resolved_file = None
                                if called_func in self.functions.get(filepath, {}):
                                    resolved_file = filepath
                                elif called_func in self.imports.get(filepath, {}):
                                    resolved_file = self.imports[filepath][called_func]
                                
                                self.function_calls.append(PythonFunctionCall(
                                    caller_function=current_function,
                                    caller_file=filepath,
                                    caller_line=child.lineno,
                                    called_function=called_func,
                                    arguments=args,
                                    resolved_file=resolved_file
                                ))
                                
                                # Track that this function calls another
                                if current_function in self.functions.get(filepath, {}):
                                    self.functions[filepath][current_function].calls_functions.append(called_func)
        except Exception as e:
            logger.warning(f"Failed to extract function calls from {filepath}: {e}")
    
    def _build_call_chains(self):
        """Build complete call chains starting from entry points"""
        
        # Find entry points (MCP decorators, main functions)
        entry_points = []
        
        for filepath, funcs in self.functions.items():
            for func_name, func_def in funcs.items():
                # Entry points are typically:
                # 1. Functions with decorators (MCP tools, prompts, resources)
                # 2. Functions with 'handler', 'tool', 'prompt' in name
                # 3. main() function
                if (any(keyword in func_name.lower() for keyword in ['handler', 'tool', 'prompt', 'resource', 'main'])
                    or func_def.parameters):  # Has parameters
                    entry_points.append((filepath, func_name, func_def))
        
        # Build chains from each entry point
        for filepath, func_name, func_def in entry_points:
            chains = self._trace_calls_from(filepath, func_name, func_def.parameters, [], [])
            self.call_chains.extend(chains)
    
    def _trace_calls_from(
        self, 
        filepath: str, 
        func_name: str, 
        params: List[str], 
        visited: List[str], 
        current_chain: List[PythonFunctionCall]
    ) -> List[PythonCallChain]:
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
                return [PythonCallChain(
                    chain=current_chain, 
                    source_params=params,
                    entry_function=current_chain[0].caller_function if current_chain else func_name,
                    entry_file=current_chain[0].caller_file if current_chain else filepath
                )]
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
                    chains.append(PythonCallChain(
                        chain=current_chain + [call],
                        source_params=params,
                        entry_function=current_chain[0].caller_function if current_chain else func_name,
                        entry_file=current_chain[0].caller_file if current_chain else filepath
                    ))
            else:
                # Can't resolve, but still record the call
                chains.append(PythonCallChain(
                    chain=current_chain + [call],
                    source_params=params,
                    entry_function=current_chain[0].caller_function if current_chain else func_name,
                    entry_file=current_chain[0].caller_file if current_chain else filepath
                ))
        
        return chains if chains else [PythonCallChain(
            chain=current_chain, 
            source_params=params,
            entry_function=func_name,
            entry_file=filepath
        )]
    
    def _generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive report"""
        
        return {
            'total_files': len(self.files),
            'total_functions': sum(len(funcs) for funcs in self.functions.values()),
            'total_function_calls': len(self.function_calls),
            'total_call_chains': len(self.call_chains),
            'call_chains': self.call_chains,
            'functions': self.functions,
            'function_calls': self.function_calls,
        }
    
    def format_report(self, results: Dict[str, Any]) -> str:
        """Format analysis results"""
        lines = []
        lines.append("=" * 80)
        lines.append("  PYTHON CALL CHAIN ANALYSIS")
        lines.append("=" * 80)
        lines.append(f"\nTotal Files: {results['total_files']}")
        lines.append(f"Total Functions: {results['total_functions']}")
        lines.append(f"Total Function Calls: {results['total_function_calls']}")
        lines.append(f"Total Call Chains: {results['total_call_chains']}")
        
        if results.get('call_chains'):
            lines.append(f"\nCall Chains Found: {len(results['call_chains'])}")
            for i, chain in enumerate(results['call_chains'][:5], 1):
                lines.append(f"\n  Chain #{i}:")
                lines.append(f"  Entry: {chain.entry_function}() in {Path(chain.entry_file).name}")
                lines.append(f"  Parameters: {', '.join(chain.source_params)}")
                lines.append(f"  Chain Length: {len(chain.chain)} calls")
                if chain.chain:
                    lines.append(f"  Call Path:")
                    for call in chain.chain[:5]:
                        lines.append(f"    → {call.caller_function}() calls {call.called_function}()")
        
        return '\n'.join(lines)


def get_python_call_chain_summary(call_chain_report: Dict[str, Any]) -> str:
    """Generate a human-readable summary of call chain analysis for LLM
    
    Args:
        call_chain_report: Call chain analysis report
        
    Returns:
        Formatted summary string
    """
    if not call_chain_report or call_chain_report.get('total_call_chains', 0) == 0:
        return "No call chains detected."
    
    lines = []
    lines.append(f"Total Functions: {call_chain_report['total_functions']}")
    lines.append(f"Total Call Chains: {call_chain_report['total_call_chains']}")
    
    # Show call chains
    if call_chain_report.get('call_chains'):
        lines.append(f"\nCall Chain Details:")
        
        # Show up to 10 most interesting chains (longest chains first)
        chains_sorted = sorted(
            call_chain_report['call_chains'],
            key=lambda x: len(x.chain),
            reverse=True
        )
        
        for i, chain in enumerate(chains_sorted[:10], 1):
            lines.append(f"\n  Chain {i}: {chain.entry_function}()")
            lines.append(f"    Entry Parameters: {', '.join(chain.source_params)}")
            lines.append(f"    Depth: {len(chain.chain)} function calls")
            
            if chain.chain:
                lines.append(f"    Call Path:")
                for call in chain.chain[:5]:  # Show first 5 calls
                    args_str = ', '.join(call.arguments[:3]) if call.arguments else ''
                    if args_str:
                        lines.append(f"      → {call.called_function}({args_str})")
                    else:
                        lines.append(f"      → {call.called_function}()")
    
    return '\n'.join(lines)
