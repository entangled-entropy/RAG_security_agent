"""
Simple syntax and structure tests for Phase 3 integration.
This test verifies that the integration code compiles and has the expected structure.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import ast
import inspect


def test_zap_collector_has_script_analysis_methods():
    """Test that ZAP collector has the expected script analysis methods"""
    # Read the file and parse it
    with open('src/zap_rag_security_agent/collectors/zap_collector.py', 'r') as f:
        content = f.read()
    
    tree = ast.parse(content)
    
    # Find the ZAPCollector class
    zap_collector_class = None
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == 'ZAPCollector':
            zap_collector_class = node
            break
    
    assert zap_collector_class is not None, "ZAPCollector class not found"
    
    # Check for expected methods (both sync and async)
    method_names = []
    for method in zap_collector_class.body:
        if isinstance(method, ast.FunctionDef):
            method_names.append(method.name)
        elif isinstance(method, ast.AsyncFunctionDef):
            method_names.append(method.name)
    
    assert '_analyze_client_scripts' in method_names, "Missing _analyze_client_scripts method"
    
    # Check for script analysis imports
    assert 'from ..preprocessing.script_extractor import ScriptExtractor' in content
    assert 'from ..detectors.client_script_analyzer import ClientScriptAnalyzer' in content
    
    # Check for script analysis parameters in __init__
    init_method = None
    for method in zap_collector_class.body:
        if isinstance(method, ast.FunctionDef) and method.name == '__init__':
            init_method = method
            break
    
    assert init_method is not None, "ZAPCollector __init__ method not found"
    
    # Check for script analysis parameters
    init_args = [arg.arg for arg in init_method.args.args]
    assert 'enable_script_analysis' in init_args, "Missing enable_script_analysis parameter"
    assert 'script_analysis_config' in init_args, "Missing script_analysis_config parameter"


def test_agent_has_script_analysis_methods():
    """Test that Security Analysis Agent has the expected script analysis methods"""
    # Read the file and parse it
    with open('src/zap_rag_security_agent/core/agent.py', 'r') as f:
        content = f.read()
    
    tree = ast.parse(content)
    
    # Find the SecurityAnalysisAgent class
    agent_class = None
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == 'SecurityAnalysisAgent':
            agent_class = node
            break
    
    assert agent_class is not None, "SecurityAnalysisAgent class not found"
    
    # Check for expected methods (both sync and async)
    method_names = []
    for method in agent_class.body:
        if isinstance(method, ast.FunctionDef):
            method_names.append(method.name)
        elif isinstance(method, ast.AsyncFunctionDef):
            method_names.append(method.name)
    
    assert 'analyze_client_scripts' in method_names, "Missing analyze_client_scripts method"
    assert 'reconstruct_client_script_analysis' in method_names, "Missing reconstruct_client_script_analysis method"
    
    # Check for script analysis imports
    assert 'from ..detectors.client_script_analyzer import ClientScriptAnalyzer' in content
    
    # Check for script analysis in system prompt
    assert 'client-side JavaScript analysis' in content
    assert 'obfuscated code' in content
    assert 'suspicious patterns' in content


def test_script_analysis_integration_structure():
    """Test that the script analysis integration has the expected structure"""
    # Check that all required files exist
    required_files = [
        'src/zap_rag_security_agent/preprocessing/script_extractor.py',
        'src/zap_rag_security_agent/utils/pattern_matcher.py',
        'src/zap_rag_security_agent/utils/entropy_calculator.py',
        'src/zap_rag_security_agent/utils/js_parser.py',
        'src/zap_rag_security_agent/detectors/client_script_analyzer.py'
    ]
    
    for file_path in required_files:
        assert os.path.exists(file_path), f"Required file {file_path} not found"
    
    # Check that the main integration points are in place
    with open('src/zap_rag_security_agent/collectors/zap_collector.py', 'r') as f:
        collector_content = f.read()
    
    with open('src/zap_rag_security_agent/core/agent.py', 'r') as f:
        agent_content = f.read()
    
    # Check for script analysis integration in collector
    assert 'enable_script_analysis' in collector_content
    assert 'script_analysis_config' in collector_content
    assert 'ClientScriptAnalyzer' in collector_content
    assert '_analyze_client_scripts' in collector_content
    
    # Check for script analysis integration in agent
    assert 'ClientScriptAnalyzer' in agent_content
    assert 'analyze_client_scripts' in agent_content
    assert 'reconstruct_client_script_analysis' in agent_content
    assert 'client-side JavaScript analysis' in agent_content


def test_configuration_structure():
    """Test that the configuration structure is correct"""
    # Check that the collector accepts script analysis configuration
    with open('src/zap_rag_security_agent/collectors/zap_collector.py', 'r') as f:
        content = f.read()
    
    # Check for configuration handling
    assert 'script_analysis_config' in content
    assert 'enable_script_analysis' in content
    assert 'self.script_analyzer' in content


if __name__ == "__main__":
    test_zap_collector_has_script_analysis_methods()
    test_agent_has_script_analysis_methods()
    test_script_analysis_integration_structure()
    test_configuration_structure()
    print("All Phase 3 integration structure tests passed!")
