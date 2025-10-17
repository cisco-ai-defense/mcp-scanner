"""
JavaScript/TypeScript Code Flow Tracker

Tracks data flow from sources to sinks in JavaScript/TypeScript code
for MCP server vulnerability analysis.
"""

import re
import logging
from pathlib import Path
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class JSFlowEvent:
    """Represents a single flow event"""
    event: str  # 'parameter_defined', 'assignment', 'function_call', 'sink'
    line: int
    variable: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class JSParameterFlow:
    """Tracks the flow of a single parameter"""
    parameter_name: str
    source_type: str  # 'function_parameter', 'args_object', 'request_body', etc.
    defined_line: int
    events: List[JSFlowEvent] = field(default_factory=list)
    reaches_sink: bool = False
    sink_type: Optional[str] = None
    severity: str = "low"


class JSFlowTracker:
    """Tracks data flow in JavaScript/TypeScript code"""
    
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
        
        # Source patterns
        self.source_patterns = {
            'function_parameter': [
                r'function\s+\w+\s*\(([^)]+)\)',
                r'async\s+function\s+\w+\s*\(([^)]+)\)',
                r'\(([^)]+)\)\s*=>\s*{',
                r'async\s*\(([^)]+)\)\s*=>\s*{',
            ],
            'args_object': r'args\.(\w+)',
            'request_body': r'req(?:uest)?\.body\.(\w+)',
            'request_query': r'req(?:uest)?\.query\.(\w+)',
            'request_params': r'req(?:uest)?\.params\.(\w+)',
        }
    
    def track_flow(self, code: str, filename: str = "unknown.js") -> Dict[str, Any]:
        """Track data flow in JavaScript/TypeScript code
        
        Args:
            code: Source code to analyze
            filename: Name of the file
            
        Returns:
            Dictionary with flow analysis results
        """
        lines = code.split('\n')
        
        # Track all parameters and their flows
        parameter_flows: Dict[str, JSParameterFlow] = {}
        
        # Phase 1: Find all sources (parameters)
        self._find_sources(lines, parameter_flows)
        
        # Phase 2: Track assignments and propagation
        self._track_assignments(lines, parameter_flows)
        
        # Phase 3: Track function calls
        self._track_function_calls(lines, parameter_flows)
        
        # Phase 4: Check if parameters reach sinks
        self._check_sinks(lines, parameter_flows)
        
        # Generate summary
        return self._generate_summary(parameter_flows, filename)
    
    def _find_sources(self, lines: List[str], parameter_flows: Dict[str, JSParameterFlow]):
        """Find all taint sources (function parameters, args.*, etc.)"""
        
        for line_num, line in enumerate(lines, 1):
            # Find function parameters
            for pattern in self.source_patterns['function_parameter']:
                match = re.search(pattern, line)
                if match:
                    params_str = match.group(1)
                    params = self._parse_parameters(params_str)
                    
                    for param in params:
                        if param and param not in parameter_flows:
                            parameter_flows[param] = JSParameterFlow(
                                parameter_name=param,
                                source_type='function_parameter',
                                defined_line=line_num,
                                events=[JSFlowEvent(
                                    event='parameter_defined',
                                    line=line_num,
                                    variable=param,
                                    details={'context': line.strip()}
                                )]
                            )
            
            # Find args.* patterns (MCP specific)
            for match in re.finditer(self.source_patterns['args_object'], line):
                param_name = f"args.{match.group(1)}"
                if param_name not in parameter_flows:
                    parameter_flows[param_name] = JSParameterFlow(
                        parameter_name=param_name,
                        source_type='args_object',
                        defined_line=line_num,
                        events=[JSFlowEvent(
                            event='parameter_defined',
                            line=line_num,
                            variable=param_name,
                            details={'context': line.strip()}
                        )]
                    )
            
            # Find request.body/query/params
            for source_type in ['request_body', 'request_query', 'request_params']:
                pattern = self.source_patterns[source_type]
                for match in re.finditer(pattern, line):
                    param_name = match.group(0)
                    if param_name not in parameter_flows:
                        parameter_flows[param_name] = JSParameterFlow(
                            parameter_name=param_name,
                            source_type=source_type,
                            defined_line=line_num,
                            events=[JSFlowEvent(
                                event='parameter_defined',
                                line=line_num,
                                variable=param_name,
                                details={'context': line.strip()}
                            )]
                        )
    
    def _parse_parameters(self, params_str: str) -> List[str]:
        """Parse function parameters including destructured ones"""
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
                # Extract property names
                for prop in inner.split(','):
                    prop = prop.strip().split(':')[0].strip()
                    if prop:
                        params.append(prop)
            elif not param.startswith('['):  # Skip array destructuring
                # Remove type annotations (TypeScript)
                if ':' in param:
                    param = param.split(':')[0].strip()
                
                if param and param.replace('_', '').replace('$', '').isalnum():
                    params.append(param)
        
        return params
    
    def _track_assignments(self, lines: List[str], parameter_flows: Dict[str, JSParameterFlow]):
        """Track variable assignments and propagation"""
        
        # Assignment patterns
        assignment_patterns = [
            r'const\s+(\w+)\s*=\s*([^;]+)',
            r'let\s+(\w+)\s*=\s*([^;]+)',
            r'var\s+(\w+)\s*=\s*([^;]+)',
            r'(\w+)\s*=\s*([^;]+)',
        ]
        
        # Multiple passes for propagation
        for _ in range(3):
            new_flows = {}
            
            for line_num, line in enumerate(lines, 1):
                for pattern in assignment_patterns:
                    match = re.search(pattern, line)
                    if match:
                        target_var = match.group(1)
                        source_expr = match.group(2).strip()
                        
                        # Check if source expression contains tracked parameters
                        for param_name in parameter_flows:
                            # Check for direct usage or property access
                            param_base = param_name.split('.')[0]
                            if param_name in source_expr or param_base in source_expr:
                                # Record assignment event
                                parameter_flows[param_name].events.append(JSFlowEvent(
                                    event='assignment',
                                    line=line_num,
                                    variable=target_var,
                                    details={
                                        'from_variable': param_name,
                                        'to_variable': target_var,
                                        'expression': source_expr[:50]
                                    }
                                ))
                                
                                # Track the new variable
                                if target_var not in parameter_flows and target_var not in new_flows:
                                    new_flows[target_var] = JSParameterFlow(
                                        parameter_name=target_var,
                                        source_type=parameter_flows[param_name].source_type,
                                        defined_line=line_num,
                                        events=[JSFlowEvent(
                                            event='propagated_from',
                                            line=line_num,
                                            variable=target_var,
                                            details={'source': param_name}
                                        )]
                                    )
            
            # Add newly tracked variables
            parameter_flows.update(new_flows)
    
    def _track_function_calls(self, lines: List[str], parameter_flows: Dict[str, JSParameterFlow]):
        """Track function calls that use tracked parameters"""
        
        for line_num, line in enumerate(lines, 1):
            # Find function calls
            func_calls = re.finditer(r'(\w+)\s*\(([^)]*)\)', line)
            
            for match in func_calls:
                func_name = match.group(1)
                args = match.group(2)
                
                # Check if any tracked parameter is used in the call
                for param_name in parameter_flows:
                    param_base = param_name.split('.')[0]
                    if param_name in args or param_base in args:
                        parameter_flows[param_name].events.append(JSFlowEvent(
                            event='function_call',
                            line=line_num,
                            variable=param_name,
                            details={
                                'function': func_name,
                                'arguments': args[:50]
                            }
                        ))
    
    def _check_sinks(self, lines: List[str], parameter_flows: Dict[str, JSParameterFlow]):
        """Check if tracked parameters reach dangerous sinks"""
        
        for line_num, line in enumerate(lines, 1):
            # Check each sink type
            for sink_type, sink_patterns in self.sinks.items():
                for sink_pattern in sink_patterns:
                    if sink_pattern in line:
                        # Check if any tracked parameter is used in this sink
                        for param_name in parameter_flows:
                            param_base = param_name.split('.')[0]
                            if param_name in line or param_base in line:
                                parameter_flows[param_name].reaches_sink = True
                                parameter_flows[param_name].sink_type = sink_type
                                parameter_flows[param_name].severity = self._calculate_severity(
                                    parameter_flows[param_name].source_type,
                                    sink_type
                                )
                                
                                parameter_flows[param_name].events.append(JSFlowEvent(
                                    event='reaches_sink',
                                    line=line_num,
                                    variable=param_name,
                                    details={
                                        'sink_type': sink_type,
                                        'sink_pattern': sink_pattern,
                                        'severity': parameter_flows[param_name].severity
                                    }
                                ))
    
    def _calculate_severity(self, source_type: str, sink_type: str) -> str:
        """Calculate severity based on source and sink combination"""
        
        high_risk = [
            ('args_object', 'exec'),
            ('args_object', 'command'),
            ('function_parameter', 'exec'),
            ('function_parameter', 'command'),
            ('request_body', 'sql_query'),
        ]
        
        if (source_type, sink_type) in high_risk:
            return 'high'
        
        medium_risk = [
            ('args_object', 'file_system'),
            ('args_object', 'network'),
            ('function_parameter', 'file_system'),
            ('function_parameter', 'network'),
            ('request_query', 'sql_query'),
        ]
        
        if (source_type, sink_type) in medium_risk:
            return 'medium'
        
        return 'low'
    
    def _generate_summary(self, parameter_flows: Dict[str, JSParameterFlow], filename: str) -> Dict[str, Any]:
        """Generate flow analysis summary"""
        
        flows_to_sinks = {
            name: flow for name, flow in parameter_flows.items()
            if flow.reaches_sink
        }
        
        return {
            'filename': filename,
            'total_parameters': len(parameter_flows),
            'parameters_reaching_sinks': len(flows_to_sinks),
            'total_flow_events': sum(len(flow.events) for flow in parameter_flows.values()),
            'parameter_flows': {
                name: {
                    'source_type': flow.source_type,
                    'defined_line': flow.defined_line,
                    'total_events': len(flow.events),
                    'reaches_sink': flow.reaches_sink,
                    'sink_type': flow.sink_type,
                    'severity': flow.severity,
                    'events': [
                        {
                            'event': event.event,
                            'line': event.line,
                            'variable': event.variable,
                            'details': event.details
                        }
                        for event in flow.events
                    ]
                }
                for name, flow in parameter_flows.items()
            },
            'high_severity_flows': [
                name for name, flow in flows_to_sinks.items()
                if flow.severity == 'high'
            ],
            'medium_severity_flows': [
                name for name, flow in flows_to_sinks.items()
                if flow.severity == 'medium'
            ],
        }


def get_js_flow_summary(flow_report: Dict[str, Any]) -> str:
    """Generate a human-readable summary of the flow analysis
    
    Args:
        flow_report: Flow analysis report from JSFlowTracker
        
    Returns:
        Formatted summary string
    """
    if not flow_report or flow_report.get('total_parameters', 0) == 0:
        return "No data flow detected."
    
    lines = []
    lines.append(f"File: {flow_report['filename']}")
    lines.append(f"Total Parameters Tracked: {flow_report['total_parameters']}")
    lines.append(f"Total Flow Events: {flow_report['total_flow_events']}")
    
    # Show ALL parameter flows (not just ones reaching sinks)
    if flow_report.get('parameter_flows'):
        lines.append(f"\nParameter Flow Details:")
        
        # Show up to 10 most interesting parameters
        params_sorted = sorted(
            flow_report['parameter_flows'].items(),
            key=lambda x: x[1]['total_events'],
            reverse=True
        )
        
        for param_name, flow_data in params_sorted[:10]:
            lines.append(f"\n  Parameter: {param_name}")
            lines.append(f"    Source: {flow_data['source_type']} (line {flow_data['defined_line']})")
            lines.append(f"    Events: {flow_data['total_events']}")
            
            # Show key flow events
            key_events = [e for e in flow_data['events'] if e['event'] in ['assignment', 'function_call']]
            if key_events:
                lines.append(f"    Flow:")
                for event in key_events[:5]:  # Show first 5 events
                    if event['event'] == 'assignment':
                        lines.append(f"      → Assigned to '{event['variable']}' (line {event['line']})")
                    elif event['event'] == 'function_call':
                        func_name = event['details'].get('function', 'unknown')
                        lines.append(f"      → Used in {func_name}() (line {event['line']})")
    
    return '\n'.join(lines)


def track_js_code_flow(code: str, filename: str = "unknown.js") -> Dict[str, Any]:
    """Convenience function to track flow in JavaScript/TypeScript code
    
    Args:
        code: Source code to analyze
        filename: Name of the file
        
    Returns:
        Flow analysis report
    """
    tracker = JSFlowTracker()
    return tracker.track_flow(code, filename)
