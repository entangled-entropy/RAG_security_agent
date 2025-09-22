"""
JavaScript AST parsing utilities for complexity and data flow analysis.
Uses esprima for JavaScript parsing and analysis.
"""

import esprima
from typing import Dict, List, Any, Optional, Set, Tuple
import re

class JSParser:
    def __init__(self):
        self.parser_options = {
            'tolerant': True,
            'range': True,
            'loc': True
        }
    
    def parse_script(self, script_content: str) -> Optional[Dict[str, Any]]:
        """Parse JavaScript code into AST"""
        try:
            ast = esprima.parseScript(script_content, **self.parser_options)
            # Convert esprima Script object to dictionary
            return ast.toDict()
        except Exception as e:
            # Fallbacks for modern syntax not supported by esprima
            try:
                # Try as module
                ast = esprima.parseModule(script_content, **self.parser_options)
                return ast.toDict()
            except Exception:
                pass
            try:
                # Simple normalization of optional chaining/nullish coalescing
                normalized = script_content.replace('?.', '.').replace('??', '||')
                ast = esprima.parseScript(normalized, **self.parser_options)
                return ast.toDict()
            except Exception as e2:
                print(f"Failed to parse JavaScript: {e2}")
                return None
    
    def analyze_complexity(self, script_content: str) -> Dict[str, Any]:
        """Analyze code complexity and unusual patterns"""
        ast = self.parse_script(script_content)
        if not ast:
            return {
                "is_unusual": False,
                "confidence": 0.0,
                "complexity_score": 0.0,
                "metrics": {}
            }
        
        # Calculate various complexity metrics
        metrics = self._calculate_complexity_metrics(ast)
        
        # Determine if code is unusual
        is_unusual = self._is_unusual_complexity(metrics)
        
        # Calculate confidence
        confidence = self._calculate_complexity_confidence(metrics)
        
        return {
            "is_unusual": is_unusual,
            "confidence": confidence,
            "complexity_score": metrics.get("overall_complexity", 0.0),
            "metrics": metrics
        }
    
    def analyze_data_flow(self, script_content: str) -> Dict[str, Any]:
        """Analyze data flow for tainted data patterns"""
        ast = self.parse_script(script_content)
        if not ast:
            return {
                "suspicion_score": 0.0,
                "confidence": 0.0,
                "tainted_flows": [],
                "sinks": []
            }
        
        # Find data sources and sinks
        sources = self._find_data_sources(ast)
        sinks = self._find_data_sinks(ast)
        
        # Analyze tainted data flows
        tainted_flows = self._analyze_tainted_flows(sources, sinks, ast)
        
        # Calculate suspicion score
        suspicion_score = self._calculate_suspicion_score(tainted_flows, sinks)
        
        return {
            "suspicion_score": suspicion_score,
            "confidence": min(suspicion_score, 1.0),
            "tainted_flows": tainted_flows,
            "sinks": sinks
        }
    
    def _calculate_complexity_metrics(self, ast: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate various complexity metrics from AST"""
        metrics = {
            "function_count": 0,
            "variable_count": 0,
            "nested_depth": 0,
            "cyclomatic_complexity": 0,
            "string_literals": 0,
            "eval_calls": 0,
            "dynamic_code_generation": 0,
            "overall_complexity": 0.0
        }
        
        # Walk through AST and collect metrics
        self._walk_ast(ast, metrics)
        
        # Calculate overall complexity score
        metrics["overall_complexity"] = self._calculate_overall_complexity(metrics)
        
        return metrics
    
    def _walk_ast(self, node: Dict[str, Any], metrics: Dict[str, Any], depth: int = 0):
        """Recursively walk AST and collect metrics"""
        if not isinstance(node, dict):
            return
        
        node_type = node.get('type', '')
        
        # Count functions
        if node_type in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']:
            metrics["function_count"] += 1
        
        # Count variables
        elif node_type in ['VariableDeclaration']:
            metrics["variable_count"] += 1
        
        # Count string literals
        elif node_type == 'Literal' and isinstance(node.get('value'), str):
            metrics["string_literals"] += 1
        
        # Count eval calls
        elif node_type == 'CallExpression':
            callee = node.get('callee', {})
            if callee.get('name') == 'eval':
                metrics["eval_calls"] += 1
        
        # Count dynamic code generation
        elif node_type == 'NewExpression':
            callee = node.get('callee', {})
            if callee.get('name') == 'Function':
                metrics["dynamic_code_generation"] += 1
        
        # Track nesting depth
        if node_type in ['IfStatement', 'ForStatement', 'WhileStatement', 'DoWhileStatement', 'SwitchStatement']:
            metrics["nested_depth"] = max(metrics["nested_depth"], depth)
        
        # Recursively process children
        for key, value in node.items():
            if isinstance(value, list):
                for item in value:
                    self._walk_ast(item, metrics, depth + 1)
            elif isinstance(value, dict):
                self._walk_ast(value, metrics, depth + 1)
    
    def _calculate_overall_complexity(self, metrics: Dict[str, Any]) -> float:
        """Calculate overall complexity score"""
        # Weighted combination of various metrics
        weights = {
            "function_count": 0.2,
            "variable_count": 0.1,
            "nested_depth": 0.3,
            "eval_calls": 0.4,
            "dynamic_code_generation": 0.3,
            "string_literals": 0.1
        }
        
        total_score = 0.0
        total_weight = 0.0
        
        for metric, weight in weights.items():
            if metric in metrics:
                # Normalize metric values
                normalized_value = min(metrics[metric] / 10.0, 1.0)  # Cap at 1.0
                total_score += normalized_value * weight
                total_weight += weight
        
        return total_score / max(total_weight, 0.001)  # Avoid division by zero
    
    def _is_unusual_complexity(self, metrics: Dict[str, Any]) -> bool:
        """Determine if code has unusual complexity patterns"""
        # High function count relative to code size
        if metrics["function_count"] > 20:
            return True
        
        # High nesting depth
        if metrics["nested_depth"] > 5:
            return True
        
        # Presence of eval or dynamic code generation
        if metrics["eval_calls"] > 0 or metrics["dynamic_code_generation"] > 0:
            return True
        
        # High overall complexity
        if metrics["overall_complexity"] > 0.7:
            return True
        
        return False
    
    def _calculate_complexity_confidence(self, metrics: Dict[str, Any]) -> float:
        """Calculate confidence in complexity analysis"""
        confidence = 0.0
        
        # High confidence for clear indicators
        if metrics["eval_calls"] > 0:
            confidence = max(confidence, 0.9)
        
        if metrics["dynamic_code_generation"] > 0:
            confidence = max(confidence, 0.8)
        
        if metrics["nested_depth"] > 5:
            confidence = max(confidence, 0.7)
        
        if metrics["overall_complexity"] > 0.7:
            confidence = max(confidence, 0.6)
        
        # Add confidence for high function count
        if metrics["function_count"] > 20:
            confidence = max(confidence, 0.5)
        
        return confidence
    
    def _find_data_sources(self, ast: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find potential data sources (user input, external data)"""
        sources = []
        
        # Common data source patterns
        source_patterns = [
            'location.search', 'location.hash', 'document.URL',
            'document.referrer', 'window.name', 'document.cookie',
            'localStorage', 'sessionStorage', 'XMLHttpRequest',
            'fetch', 'FormData', 'URLSearchParams', 'localStorage.getItem',
            'sessionStorage.getItem'
        ]
        
        self._find_patterns_in_ast(ast, source_patterns, sources, 'source')
        
        return sources
    
    def _find_data_sinks(self, ast: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find potential data sinks (dangerous operations)"""
        sinks = []
        
        # Common sink patterns
        sink_patterns = [
            'innerHTML', 'outerHTML', 'document.write',
            'eval', 'Function', 'setTimeout', 'setInterval',
            'location.href', 'location.replace', 'location.assign'
        ]
        
        self._find_patterns_in_ast(ast, sink_patterns, sinks, 'sink')
        
        return sinks
    
    def _find_patterns_in_ast(self, node: Dict[str, Any], patterns: List[str], 
                             results: List[Dict[str, Any]], pattern_type: str):
        """Find specific patterns in AST"""
        if not isinstance(node, dict):
            return
        
        node_type = node.get('type', '')
        
        # Check for assignment expressions (e.g., element.innerHTML = data)
        if node_type == 'AssignmentExpression':
            left = node.get('left', {})
            if left.get('type') == 'MemberExpression':
                # For sinks, we want to match just the property name (e.g., 'innerHTML')
                simple_name = self._get_simple_member_name(left)
                if simple_name and simple_name in patterns:
                    results.append({
                        "type": pattern_type,
                        "pattern": simple_name,
                        "location": node.get('loc', {}),
                        "range": node.get('range', [])
                    })
        
        # Check for member expressions (e.g., document.write)
        elif node_type == 'MemberExpression':
            full_name = self._get_full_member_name(node)
            
            if full_name and full_name in patterns:
                results.append({
                    "type": pattern_type,
                    "pattern": full_name,
                    "location": node.get('loc', {}),
                    "range": node.get('range', [])
                })
        
        # Check for call expressions (e.g., eval())
        elif node_type == 'CallExpression':
            callee = node.get('callee', {})
            if callee.get('name') in patterns:
                results.append({
                    "type": pattern_type,
                    "pattern": callee.get('name'),
                    "location": node.get('loc', {}),
                    "range": node.get('range', [])
                })
        
        # Recursively process children
        for key, value in node.items():
            if isinstance(value, list):
                for item in value:
                    self._find_patterns_in_ast(item, patterns, results, pattern_type)
            elif isinstance(value, dict):
                self._find_patterns_in_ast(value, patterns, results, pattern_type)
    
    def _get_object_name(self, node: Dict[str, Any]) -> Optional[str]:
        """Get object name from member expression"""
        if node.get('type') == 'Identifier':
            return node.get('name')
        elif node.get('type') == 'MemberExpression':
            obj = self._get_object_name(node.get('object', {}))
            prop = self._get_property_name(node.get('property', {}))
            if obj and prop:
                return f"{obj}.{prop}"
        return None
    
    def _get_full_member_name(self, node: Dict[str, Any]) -> Optional[str]:
        """Get full member expression name (e.g., 'location.search')"""
        if node.get('type') == 'MemberExpression':
            obj = self._get_object_name(node.get('object', {}))
            prop = self._get_property_name(node.get('property', {}))
            if obj and prop:
                return f"{obj}.{prop}"
        elif node.get('type') == 'Identifier':
            return node.get('name')
        return None
    
    def _get_simple_member_name(self, node: Dict[str, Any]) -> Optional[str]:
        """Get simple member expression name for sink detection (e.g., 'innerHTML')"""
        if node.get('type') == 'MemberExpression':
            prop = self._get_property_name(node.get('property', {}))
            return prop
        elif node.get('type') == 'Identifier':
            return node.get('name')
        return None
    
    def _get_property_name(self, node: Dict[str, Any]) -> Optional[str]:
        """Get property name from member expression"""
        if node.get('type') == 'Identifier':
            return node.get('name')
        elif node.get('type') == 'Literal':
            return str(node.get('value', ''))
        return None
    
    def _analyze_tainted_flows(self, sources: List[Dict[str, Any]], 
                              sinks: List[Dict[str, Any]], ast: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze potential tainted data flows from sources to sinks"""
        tainted_flows = []
        
        # Simple analysis: check if sources and sinks are in the same scope
        for source in sources:
            for sink in sinks:
                # Check if they're in the same function or global scope
                if self._are_in_same_scope(source, sink, ast):
                    tainted_flows.append({
                        "source": source,
                        "sink": sink,
                        "risk_level": self._calculate_flow_risk(source, sink)
                    })
        
        return tainted_flows
    
    def _are_in_same_scope(self, source: Dict[str, Any], sink: Dict[str, Any], 
                           ast: Dict[str, Any]) -> bool:
        """Check if source and sink are in the same scope"""
        # Simplified scope analysis - in practice, this would be more complex
        source_range = source.get('range', [])
        sink_range = sink.get('range', [])
        
        if not source_range or not sink_range:
            return False
        
        # Check if they're within reasonable distance (same function/block)
        distance = abs(source_range[0] - sink_range[0])
        return distance < 1000  # Within 1000 characters
    
    def _calculate_flow_risk(self, source: Dict[str, Any], sink: Dict[str, Any]) -> str:
        """Calculate risk level for a tainted data flow"""
        source_pattern = source.get('pattern', '')
        sink_pattern = sink.get('pattern', '')
        
        # High risk combinations
        high_risk_combinations = [
            ('location.search', 'innerHTML'),
            ('location.hash', 'eval'),
            ('document.cookie', 'document.write'),
            ('localStorage', 'Function')
        ]
        
        for source_type, sink_type in high_risk_combinations:
            if source_type in source_pattern and sink_type in sink_pattern:
                return 'high'
        
        # Medium risk for any source to dangerous sink
        dangerous_sinks = ['eval', 'Function', 'innerHTML', 'document.write']
        if any(sink in sink_pattern for sink in dangerous_sinks):
            return 'medium'
        
        return 'low'
    
    def _calculate_suspicion_score(self, tainted_flows: List[Dict[str, Any]], 
                                  sinks: List[Dict[str, Any]]) -> float:
        """Calculate overall suspicion score based on tainted flows"""
        if not tainted_flows:
            return 0.0
        
        # Weight flows by risk level
        risk_weights = {'high': 1.0, 'medium': 0.6, 'low': 0.3}
        
        total_score = 0.0
        for flow in tainted_flows:
            risk_level = flow.get('risk_level', 'low')
            total_score += risk_weights.get(risk_level, 0.3)
        
        # Normalize by number of flows and sinks
        normalization_factor = max(len(tainted_flows), 1) * max(len(sinks), 1)
        return min(total_score / normalization_factor, 1.0)

    # -------------------------------------------------------------
    # Function extraction helpers for targeted LLM analysis
    # -------------------------------------------------------------
    def _find_enclosing_function_node(self, node: Dict[str, Any], target_range: List[int]) -> Optional[Dict[str, Any]]:
        """Find the function node that encloses the given character range."""
        if not isinstance(node, dict):
            return None
        node_type = node.get('type')
        node_range = node.get('range') or []
        if (
            node_type in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'] and
            isinstance(node_range, list) and len(node_range) == 2 and
            isinstance(target_range, list) and len(target_range) == 2 and
            node_range[0] <= target_range[0] and node_range[1] >= target_range[1]
        ):
            # Check children for a more specific enclosing function
            for key, value in node.items():
                if isinstance(value, list):
                    for item in value:
                        found = self._find_enclosing_function_node(item, target_range)
                        if found is not None:
                            return found
                elif isinstance(value, dict):
                    found = self._find_enclosing_function_node(value, target_range)
                    if found is not None:
                        return found
            return node
        # Recurse into children
        for key, value in node.items():
            if isinstance(value, list):
                for item in value:
                    found = self._find_enclosing_function_node(item, target_range)
                    if found is not None:
                        return found
            elif isinstance(value, dict):
                found = self._find_enclosing_function_node(value, target_range)
                if found is not None:
                    return found
        return None

    def extract_enclosing_function_source(self, script_content: str, target_range: List[int]) -> Optional[str]:
        """Return the source code of the function enclosing the target range, if any."""
        ast = self.parse_script(script_content)
        if not ast:
            return None
        func_node = self._find_enclosing_function_node(ast, target_range)
        if func_node and isinstance(func_node.get('range'), list) and len(func_node['range']) == 2:
            start, end = func_node['range']
            try:
                # Clamp to valid bounds
                start = max(0, min(len(script_content), start))
                end = max(start, min(len(script_content), end))
                return script_content[start:end]
            except Exception:
                return None
        return None

    def extract_first_function_source(self, script_content: str) -> Optional[str]:
        """Return the source code of the first function found in the script, if any."""
        ast = self.parse_script(script_content)
        if not ast:
            return None
        # DFS search for first function node
        stack: List[Dict[str, Any]] = [ast]
        while stack:
            node = stack.pop()
            if not isinstance(node, dict):
                continue
            node_type = node.get('type')
            if node_type in ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']:
                r = node.get('range') or []
                if isinstance(r, list) and len(r) == 2:
                    start, end = r
                    try:
                        start = max(0, min(len(script_content), start))
                        end = max(start, min(len(script_content), end))
                        return script_content[start:end]
                    except Exception:
                        return None
            # push children
            for key, value in node.items():
                if isinstance(value, list):
                    for item in value:
                        stack.append(item)
                elif isinstance(value, dict):
                    stack.append(value)
        return None
