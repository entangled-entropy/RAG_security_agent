"""
Script extraction utilities for HTML content analysis.
Extracts inline and external JavaScript from HTML responses.
"""

import re
import requests
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse

class ScriptExtractor:
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; SecurityAnalyzer/1.0)'
        })
    
    def extract_scripts_from_html(self, html_content: str, base_url: str = "") -> Dict[str, List[Dict[str, Any]]]:
        """
        Extract all JavaScript from HTML content.
        
        Returns:
            {
                "inline_scripts": [{"content": str, "line": int, "type": str}],
                "external_scripts": [{"url": str, "content": str, "line": int}]
            }
        """
        inline_scripts = self._extract_inline_scripts(html_content)
        external_scripts = self._extract_external_scripts(html_content, base_url)
        
        return {
            "inline_scripts": inline_scripts,
            "external_scripts": external_scripts
        }
    
    def _extract_inline_scripts(self, html_content: str) -> List[Dict[str, Any]]:
        """Extract inline <script> tags"""
        scripts = []
        
        # Pattern for <script> tags (handles multiline)
        script_pattern = r'<script[^>]*>(.*?)</script>'
        
        for match in re.finditer(script_pattern, html_content, re.DOTALL | re.IGNORECASE):
            script_content = match.group(1).strip()
            if script_content:  # Skip empty scripts
                # Calculate approximate line number
                line_number = html_content[:match.start()].count('\n') + 1
                
                scripts.append({
                    "content": script_content,
                    "line": line_number,
                    "type": "inline",
                    "start_pos": match.start(),
                    "end_pos": match.end()
                })
        
        return scripts
    
    def _extract_external_scripts(self, html_content: str, base_url: str) -> List[Dict[str, Any]]:
        """Extract external script URLs and download content"""
        scripts = []
        
        # Pattern for <script src="..."> tags
        src_pattern = r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>'
        
        for match in re.finditer(src_pattern, html_content, re.IGNORECASE):
            script_url = match.group(1)
            line_number = html_content[:match.start()].count('\n') + 1
            
            # Normalize odd protocol forms first
            try:
                if script_url.startswith('https:/') and not script_url.startswith('https://'):
                    script_url = 'https://' + script_url[len('https:/'):]
                elif script_url.startswith('http:/') and not script_url.startswith('http://'):
                    script_url = 'http://' + script_url[len('http:/'):]
                elif script_url.startswith('//'):
                    # protocol-relative; prefer scheme from base_url, default https
                    scheme = urlparse(base_url).scheme or 'https'
                    script_url = f"{scheme}:{script_url}"
            except Exception:
                pass
            
            # Resolve relative URLs against base_url
            if base_url:
                try:
                    script_url = urljoin(base_url, script_url)
                except Exception:
                    pass
            
            # Download script content
            content = self._download_script(script_url)
            
            scripts.append({
                "url": script_url,
                "content": content,
                "line": line_number,
                "type": "external",
                "download_success": content is not None
            })
        
        return scripts
    
    def _download_script(self, url: str) -> Optional[str]:
        """Download external script content"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            return response.text
        except Exception as e:
            print(f"Failed to download script {url}: {e}")
            return None
