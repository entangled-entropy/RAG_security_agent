"""
Main client script analyzer implementing the hybrid cherry-picking strategy.
Coordinates all analysis components and makes final decisions.
"""

import json
from typing import Dict, List, Any, Optional, Tuple
from ..preprocessing.script_extractor import ScriptExtractor
from ..utils.pattern_matcher import PatternMatcher
from ..utils.entropy_calculator import EntropyCalculator
from ..utils.js_parser import JSParser

class ClientScriptAnalyzer:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        # Merge custom config with default config
        default_config = self._default_config()
        if config:
            # Deep merge configs
            self.config = self._merge_configs(default_config, config)
        else:
            self.config = default_config
        
        # Initialize components
        self.script_extractor = ScriptExtractor(timeout=self.config['download_timeout'])
        self.pattern_matcher = PatternMatcher()
        self.entropy_calculator = EntropyCalculator()
        self.js_parser = JSParser()
        
        # Analysis cache
        self.analysis_cache = {}
    
    def _merge_configs(self, default: Dict[str, Any], custom: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge custom config with default config"""
        result = default.copy()
        
        for key, value in custom.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _default_config(self) -> Dict[str, Any]:
        """Default configuration for the analyzer"""
        return {
            'download_timeout': 5,
            'cache_analyses': True,
            'thresholds': {
                'suspicion_density': 0.1,  # 10% of lines have suspicious patterns
                'entropy_threshold': 4.5,  # High entropy threshold
                'complexity_threshold': 0.3,  # 30% complexity density
                'min_custom_confidence': 0.7,  # 70% confidence it's custom
                'min_llm_confidence': 0.8  # 80% confidence for LLM analysis
            },
            'enable_ast_analysis': True,
            'enable_data_flow_analysis': True,
            'max_script_size': 100000  # 100KB max script size
        }
    
    def analyze_html_response(self, html_content: str, url: str = "") -> Dict[str, Any]:
        """
        Main entry point for HTML response analysis.
        
        Returns:
            {
                "scripts_analyzed": int,
                "scripts_for_llm": List[Dict],
                "summary": Dict,
                "all_scripts": List[Dict]
            }
        """
        # Extract scripts from HTML
        extracted_scripts = self.script_extractor.extract_scripts_from_html(html_content, url)
        
        all_scripts = []
        scripts_for_llm = []
        
        # Analyze inline scripts
        for script in extracted_scripts['inline_scripts']:
            analysis = self._analyze_single_script(
                script_content=script['content'],
                script_url=f"inline:{script['line']}",
                script_type="inline"
            )
            
            script['analysis'] = analysis
            all_scripts.append(script)
            
            if analysis['should_analyze_with_llm']:
                scripts_for_llm.append(script)
        
        # Analyze external scripts
        for script in extracted_scripts['external_scripts']:
            if script['download_success']:
                analysis = self._analyze_single_script(
                    script_content=script['content'],
                    script_url=script['url'],
                    script_type="external"
                )
                
                script['analysis'] = analysis
                all_scripts.append(script)
                
                if analysis['should_analyze_with_llm']:
                    scripts_for_llm.append(script)
        
        # Generate summary
        summary = self._generate_summary(all_scripts, scripts_for_llm)
        
        return {
            "scripts_analyzed": len(all_scripts),
            "scripts_for_llm": scripts_for_llm,
            "summary": summary,
            "all_scripts": all_scripts
        }
    
    def _analyze_single_script(self, script_content: str, script_url: str, script_type: str) -> Dict[str, Any]:
        """Analyze a single script using the hybrid cherry-picking strategy"""
        
        # Check cache first
        cache_key = f"{script_url}:{hash(script_content)}"
        if self.config['cache_analyses'] and cache_key in self.analysis_cache:
            return self.analysis_cache[cache_key]
        
        # Skip if script is too large
        if len(script_content) > self.config['max_script_size']:
            return {
                "should_analyze_with_llm": False,
                "reason": "script_too_large",
                "confidence": 0.0
            }
        
        # Stage 1: Custom vs Third-party Detection
        custom_analysis = self.pattern_matcher.is_custom_script(script_url, script_content)
        
        if not custom_analysis['is_custom']:
            result = {
                "should_analyze_with_llm": False,
                "reason": "third_party_library",
                "confidence": 0.0,
                "stages": {
                    "custom_detection": custom_analysis
                }
            }
            self._cache_result(cache_key, result)
            return result
        
        # Stage 2: Suspicion Analysis
        suspicion_density, suspicion_matches = self.pattern_matcher.calculate_suspicion_density(script_content)
        
        # Stage 3: Obfuscation Analysis
        obfuscation_analysis = self.entropy_calculator.analyze_obfuscation(script_content)
        
        # Stage 4: Complexity Analysis (if enabled)
        complexity_analysis = {}
        if self.config['enable_ast_analysis']:
            complexity_analysis = self.js_parser.analyze_complexity(script_content)
        
        # Stage 5: Data Flow Analysis (if enabled)
        data_flow_analysis = {}
        if self.config['enable_data_flow_analysis']:
            data_flow_analysis = self.js_parser.analyze_data_flow(script_content)
        
        # Decision Logic
        should_analyze, reasons, confidence = self._make_decision(
            custom_analysis, suspicion_density, obfuscation_analysis,
            complexity_analysis, data_flow_analysis
        )
        
        result = {
            "should_analyze_with_llm": should_analyze,
            "reasons": reasons,
            "confidence": confidence,
            "stages": {
                "custom_detection": custom_analysis,
                "suspicion_analysis": {
                    "density": suspicion_density,
                    "matches": suspicion_matches
                },
                "obfuscation_analysis": obfuscation_analysis,
                "complexity_analysis": complexity_analysis,
                "data_flow_analysis": data_flow_analysis
            }
        }
        
        self._cache_result(cache_key, result)
        return result
    
    def _make_decision(self, custom_analysis: Dict, suspicion_density: float,
                      obfuscation_analysis: Dict, complexity_analysis: Dict,
                      data_flow_analysis: Dict) -> Tuple[bool, List[str], float]:
        """Make final decision on whether to analyze with LLM"""
        
        should_analyze = False
        reasons = []
        confidence_scores = []
        
        # Check suspicion density
        if suspicion_density > self.config['thresholds']['suspicion_density']:
            should_analyze = True
            reasons.append(f"high_suspicion_density_{suspicion_density:.2f}")
            confidence_scores.append(0.8)
        
        # Check obfuscation
        if obfuscation_analysis.get('is_obfuscated', False):
            should_analyze = True
            reasons.append("obfuscated_code")
            confidence_scores.append(obfuscation_analysis.get('confidence', 0.5))
        
        # Check complexity (if available)
        if complexity_analysis.get('is_unusual', False):
            should_analyze = True
            reasons.append("unusual_complexity")
            confidence_scores.append(0.7)
        
        # Check data flow issues (if available)
        if data_flow_analysis.get('suspicion_score', 0) > 0:
            should_analyze = True
            reasons.append("data_flow_issues")
            confidence_scores.append(0.9)
        
        # Calculate overall confidence
        if confidence_scores:
            overall_confidence = sum(confidence_scores) / len(confidence_scores)
        else:
            overall_confidence = 0.0
        
        return should_analyze, reasons, overall_confidence
    
    def _generate_summary(self, all_scripts: List[Dict], scripts_for_llm: List[Dict]) -> Dict[str, Any]:
        """Generate analysis summary"""
        
        total_scripts = len(all_scripts)
        llm_scripts = len(scripts_for_llm)
        
        # Categorize scripts
        inline_count = sum(1 for s in all_scripts if s.get('type') == 'inline')
        external_count = sum(1 for s in all_scripts if s.get('type') == 'external')
        
        # Count by analysis results
        custom_count = sum(1 for s in all_scripts if s.get('analysis', {}).get('stages', {}).get('custom_detection', {}).get('is_custom', False))
        obfuscated_count = sum(1 for s in all_scripts if s.get('analysis', {}).get('stages', {}).get('obfuscation_analysis', {}).get('is_obfuscated', False))
        
        return {
            "total_scripts": total_scripts,
            "inline_scripts": inline_count,
            "external_scripts": external_count,
            "custom_scripts": custom_count,
            "obfuscated_scripts": obfuscated_count,
            "scripts_for_llm": llm_scripts,
            "llm_percentage": (llm_scripts / max(total_scripts, 1)) * 100,
            "filtering_efficiency": f"{(total_scripts - llm_scripts) / max(total_scripts, 1) * 100:.1f}% filtered out"
        }
    
    def _cache_result(self, cache_key: str, result: Dict[str, Any]):
        """Cache analysis result"""
        if self.config['cache_analyses']:
            self.analysis_cache[cache_key] = result
    
    def get_llm_analysis_prompt(self, script: Dict[str, Any]) -> str:
        """Generate LLM analysis prompt for a script.

        Only include the smallest relevant function when available; fall back to
        the first function, then finally a truncated script.
        """
        analysis = script.get('analysis', {})
        stages = analysis.get('stages', {})

        script_content = script.get('content', '') or ''

        # Try to extract function enclosing a suspicious sink/source
        targeted_source = ''
        target_range = None
        dfa = stages.get('data_flow_analysis', {}) or {}

        # Prefer tainted flows when ranges are available
        flows = dfa.get('tainted_flows') or []
        if isinstance(flows, list) and flows:
            first_flow = flows[0]
            sink = (first_flow or {}).get('sink') or {}
            target_range = sink.get('range') or []
            if not target_range:
                source = (first_flow or {}).get('source') or {}
                target_range = source.get('range') or []

        # Else fall back to first sink or source
        if not target_range:
            sinks = dfa.get('sinks') or []
            if isinstance(sinks, list) and sinks:
                target_range = (sinks[0] or {}).get('range') or []
        if not target_range:
            sources = dfa.get('sources') or []
            if isinstance(sources, list) and sources:
                target_range = (sources[0] or {}).get('range') or []

        if target_range:
            extracted = self.js_parser.extract_enclosing_function_source(script_content, target_range)
            if extracted:
                targeted_source = extracted

        # If nothing extracted, try first function in the file
        if not targeted_source:
            extracted_first = self.js_parser.extract_first_function_source(script_content)
            if extracted_first:
                targeted_source = extracted_first

        # Final fallback: use a small truncated slice of the script
        if not targeted_source:
            targeted_source = script_content[:1200]

        prompt = f"""
Analyze this JavaScript code for security vulnerabilities:

SCRIPT URL: {script.get('url', 'inline')}
SCRIPT TYPE: {script.get('type', 'unknown')}

ANALYSIS CONTEXT:
- Custom Script Confidence: {stages.get('custom_detection', {}).get('confidence', 0):.2f}
- Suspicion Density: {stages.get('suspicion_analysis', {}).get('density', 0):.2f}
- Is Obfuscated: {stages.get('obfuscation_analysis', {}).get('is_obfuscated', False)}
- Analysis Reasons: {', '.join(analysis.get('reasons', []))}

TARGETED CODE (only the suspicious function or minimal region):
```javascript
{targeted_source}
```

Please analyze this code for:
1. Security vulnerabilities (XSS, code injection, etc.)
2. Suspicious patterns or behaviors
3. Potential attack vectors
4. Risk assessment and recommendations

Focus on the specific reasons this script was flagged for analysis.
"""
        return prompt
