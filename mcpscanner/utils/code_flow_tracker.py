"""
Code Flow Tracker Utility

Lightweight data flow tracker that extracts parameter flow paths
from Python code without vulnerability detection.
"""

import ast
import logging
from typing import Dict, List, Set, Optional, Any

logger = logging.getLogger(__name__)


class CodeFlowTracker(ast.NodeVisitor):
    """
    Tracks data flow paths for function parameters.
    
    This is a lightweight tracker that shows where each parameter flows
    through the code without making security judgments.
    """
    
    def __init__(self, source_code: str, filename: str = "<unknown>"):
        self.source_code = source_code
        self.filename = filename
        self.source_lines = source_code.split('\n')
        
        # Track parameter flows
        self.parameter_flows: Dict[str, List[Dict[str, Any]]] = {}
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
    
    def get_formatted_flows(self) -> str:
        """Get human-readable formatted flow paths"""
        lines = []
        
        for param_name, flow_data in self.parameter_flows.items():
            lines.append(f"\nParameter: {param_name}")
            lines.append(f"  Flow Events: {flow_data['total_events']}")
            
            for i, event in enumerate(flow_data['events'], 1):
                event_type = event['event']
                line = event['line']
                
                if event_type == 'parameter_defined':
                    lines.append(f"    {i}. [Line {line}] Defined in function '{event['function']}'")
                
                elif event_type == 'assignment':
                    from_var = event['from_variable']
                    to_var = event['to_variable']
                    lines.append(f"    {i}. [Line {line}] {from_var} → {to_var}")
                    if event.get('code'):
                        lines.append(f"        Code: {event['code']}")
                
                elif event_type == 'function_call':
                    func = event['function']
                    var = event['variable']
                    arg = event.get('argument', '')
                    if arg:
                        lines.append(f"    {i}. [Line {line}] Used in {func}({arg}={var})")
                    else:
                        lines.append(f"    {i}. [Line {line}] Used in {func}()")
                    if event.get('code'):
                        lines.append(f"        Code: {event['code']}")
        
        return '\n'.join(lines)


def track_code_flow(source_code: str, filename: str = "<string>") -> Dict[str, Any]:
    """
    Track data flow paths for parameters in source code.
    
    Args:
        source_code: Python source code as string
        filename: Optional filename for reporting
        
    Returns:
        Data flow report
    """
    tracker = CodeFlowTracker(source_code, filename)
    return tracker.analyze()


def get_flow_summary(flow_report: Dict[str, Any]) -> str:
    """
    Get a concise summary of flow report for LLM context.
    
    Args:
        flow_report: Flow report from CodeFlowTracker
        
    Returns:
        Formatted summary string
    """
    if not flow_report or not flow_report.get('parameter_flows'):
        return "No parameter flows detected."
    
    lines = []
    lines.append(f"Data Flow Analysis ({flow_report.get('total_parameters', 0)} parameters):")
    
    for param, flow_data in flow_report['parameter_flows'].items():
        events = flow_data['events']
        
        # Build flow path
        path_parts = [param]
        for event in events[1:]:  # Skip parameter_defined
            if event['event'] == 'assignment':
                path_parts.append(event['to_variable'])
            elif event['event'] == 'function_call':
                path_parts.append(f"{event['function']}()")
        
        flow_path = " → ".join(path_parts)
        lines.append(f"  • {param}: {flow_path}")
    
    return '\n'.join(lines)


class MultiFileCodeFlowTracker:
    """
    Tracks data flow across multiple Python files.
    
    Provides robust multi-file analysis with error handling and aggregation.
    """
    
    def __init__(self):
        self.files: Dict[str, CodeFlowTracker] = {}
        self.file_reports: Dict[str, Dict[str, Any]] = {}
        self.errors: Dict[str, str] = {}
        
    def add_file(self, filepath: str, source_code: Optional[str] = None):
        """
        Add a file to the multi-file analysis.
        
        Args:
            filepath: Path to the file
            source_code: Optional source code (if None, reads from file)
        """
        try:
            if source_code is None:
                with open(filepath, 'r', encoding='utf-8') as f:
                    source_code = f.read()
            
            tracker = CodeFlowTracker(source_code, filepath)
            self.files[filepath] = tracker
        except Exception as e:
            logger.warning(f"Failed to add file {filepath}: {e}")
            self.errors[filepath] = str(e)
    
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
        
        if not dir_path.exists():
            logger.error(f"Directory does not exist: {directory}")
            return
        
        if not dir_path.is_dir():
            logger.error(f"Not a directory: {directory}")
            return
        
        try:
            if recursive:
                files = dir_path.rglob(pattern)
            else:
                files = dir_path.glob(pattern)
            
            for filepath in files:
                if filepath.is_file():
                    self.add_file(str(filepath))
        except Exception as e:
            logger.error(f"Error scanning directory {directory}: {e}")
    
    def analyze(self) -> Dict[str, Any]:
        """
        Perform flow analysis on all files.
        
        Returns:
            Comprehensive multi-file analysis report
        """
        # Analyze each file
        for filepath, tracker in self.files.items():
            try:
                report = tracker.analyze()
                self.file_reports[filepath] = report
            except Exception as e:
                logger.error(f"Error analyzing {filepath}: {e}")
                self.errors[filepath] = str(e)
                self.file_reports[filepath] = {
                    "error": str(e),
                    "total_parameters": 0,
                    "parameter_flows": {}
                }
        
        # Aggregate statistics
        total_files = len(self.files)
        total_files_with_flows = sum(
            1 for r in self.file_reports.values() 
            if r.get('total_parameters', 0) > 0
        )
        total_parameters = sum(
            r.get('total_parameters', 0) 
            for r in self.file_reports.values()
        )
        total_flow_events = sum(
            sum(
                flow['total_events'] 
                for flow in r.get('parameter_flows', {}).values()
            )
            for r in self.file_reports.values()
        )
        
        # Group by file
        flows_by_file = {}
        for filepath, report in self.file_reports.items():
            if report.get('total_parameters', 0) > 0:
                flows_by_file[filepath] = {
                    'parameters': report['total_parameters'],
                    'events': sum(
                        flow['total_events'] 
                        for flow in report['parameter_flows'].values()
                    )
                }
        
        return {
            "total_files": total_files,
            "files_with_flows": total_files_with_flows,
            "total_parameters": total_parameters,
            "total_flow_events": total_flow_events,
            "flows_by_file": flows_by_file,
            "file_reports": self.file_reports,
            "errors": self.errors
        }
    
    def get_summary(self) -> str:
        """Get human-readable summary"""
        report = self.analyze()
        
        lines = []
        lines.append("=" * 80)
        lines.append("  MULTI-FILE CODE FLOW ANALYSIS")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"📁 Total Files: {report['total_files']}")
        lines.append(f"📊 Files with MCP Functions: {report['files_with_flows']}")
        lines.append(f"📍 Total Parameters: {report['total_parameters']}")
        lines.append(f"🔄 Total Flow Events: {report['total_flow_events']}")
        
        if report['errors']:
            lines.append(f"\n⚠️  Errors: {len(report['errors'])}")
        
        if report['flows_by_file']:
            lines.append("\n📋 Files with Parameter Flows:")
            for filepath, flow_data in sorted(
                report['flows_by_file'].items(),
                key=lambda x: x[1]['parameters'],
                reverse=True
            ):
                from pathlib import Path
                filename = Path(filepath).name
                lines.append(
                    f"  • {filename}: "
                    f"{flow_data['parameters']} params, "
                    f"{flow_data['events']} events"
                )
        
        lines.append("\n" + "=" * 80)
        
        return '\n'.join(lines)
    
    def get_file_report(self, filepath: str) -> Optional[Dict[str, Any]]:
        """Get flow report for a specific file"""
        return self.file_reports.get(filepath)
    
    def get_all_flows(self) -> Dict[str, Dict[str, Any]]:
        """Get all parameter flows across all files"""
        all_flows = {}
        
        for filepath, report in self.file_reports.items():
            if report.get('parameter_flows'):
                from pathlib import Path
                filename = Path(filepath).name
                all_flows[filename] = report['parameter_flows']
        
        return all_flows


def analyze_directory(directory: str, pattern: str = "*.py", recursive: bool = True) -> Dict[str, Any]:
    """
    Analyze all Python files in a directory for data flows.
    
    Args:
        directory: Directory path
        pattern: File pattern (default: *.py)
        recursive: Whether to search recursively
        
    Returns:
        Multi-file flow analysis report
    """
    tracker = MultiFileCodeFlowTracker()
    tracker.add_directory(directory, pattern, recursive)
    return tracker.analyze()


def analyze_files(filepaths: List[str]) -> Dict[str, Any]:
    """
    Analyze multiple specific files for data flows.
    
    Args:
        filepaths: List of file paths to analyze
        
    Returns:
        Multi-file flow analysis report
    """
    tracker = MultiFileCodeFlowTracker()
    for filepath in filepaths:
        tracker.add_file(filepath)
    return tracker.analyze()
