"""
Version Database for Technology Stack Detection

This module maintains a comprehensive database of technology versions,
including latest stable versions, LTS versions, and security information.
Used by the stack detector to identify outdated and vulnerable components.
"""

import json
import requests
import asyncio
import aiohttp
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
import os
from pathlib import Path


class VersionDatabase:
    """
    Comprehensive version database for technology stack detection.
    Maintains latest versions, LTS versions, and security information.
    """
    
    def __init__(self, cache_file: str = "version_cache.json"):
        """Initialize the version database with cache file."""
        self.cache_file = cache_file
        self.cache_dir = Path(__file__).parent
        self.cache_path = self.cache_dir / cache_file
        
        # Load cached data
        self.versions = self._load_cache()
        
        # API endpoints for version fetching
        self.api_endpoints = {
            'npm': 'https://registry.npmjs.org/{package}',
            'pypi': 'https://pypi.org/pypi/{package}/json',
            'maven': 'https://search.maven.org/solrsearch/select?q=g:{group}+AND+a:{artifact}&rows=1&wt=json',
            'rubygems': 'https://rubygems.org/api/v1/gems/{gem}.json',
            'packagist': 'https://packagist.org/p/{package}.json',
            'nuget': 'https://api.nuget.org/v3-flatcontainer/{package}/index.json',
            'github': 'https://api.github.com/repos/{owner}/{repo}/releases/latest'
        }
        
        # Technology mappings to their package managers
        self.technology_mappings = {
            # Frontend Frameworks
            'jquery': {'npm': 'jquery', 'github': 'jquery/jquery'},
            'react': {'npm': 'react', 'github': 'facebook/react'},
            'vue': {'npm': 'vue', 'github': 'vuejs/vue'},
            'angular': {'npm': '@angular/core', 'github': 'angular/angular'},
            'bootstrap': {'npm': 'bootstrap', 'github': 'twbs/bootstrap'},
            'foundation': {'npm': 'foundation-sites', 'github': 'foundation/foundation-sites'},
            'tailwindcss': {'npm': 'tailwindcss', 'github': 'tailwindlabs/tailwindcss'},
            'svelte': {'npm': 'svelte', 'github': 'sveltejs/svelte'},
            'ember': {'npm': 'ember-source', 'github': 'emberjs/ember.js'},
            
            # Backend Frameworks
            'express': {'npm': 'express', 'github': 'expressjs/express'},
            'koa': {'npm': 'koa', 'github': 'koajs/koa'},
            'hapi': {'npm': '@hapi/hapi', 'github': 'hapijs/hapi'},
            'fastify': {'npm': 'fastify', 'github': 'fastify/fastify'},
            'django': {'pypi': 'django', 'github': 'django/django'},
            'flask': {'pypi': 'flask', 'github': 'pallets/flask'},
            'fastapi': {'pypi': 'fastapi', 'github': 'tiangolo/fastapi'},
            'rails': {'rubygems': 'rails', 'github': 'rails/rails'},
            'sinatra': {'rubygems': 'sinatra', 'github': 'sinatra/sinatra'},
            'spring': {'maven': 'org.springframework:spring-core', 'github': 'spring-projects/spring-framework'},
            'laravel': {'packagist': 'laravel/framework', 'github': 'laravel/laravel'},
            'symfony': {'packagist': 'symfony/symfony', 'github': 'symfony/symfony'},
            'codeigniter': {'packagist': 'codeigniter4/framework', 'github': 'codeigniter4/CodeIgniter4'},
            'cakephp': {'packagist': 'cakephp/cakephp', 'github': 'cakephp/cakephp'},
            'yii': {'packagist': 'yiisoft/yii2', 'github': 'yiisoft/yii2'},
            'zend': {'packagist': 'laminas/laminas-mvc', 'github': 'laminas/laminas-mvc'},
            
            # Databases
            'mysql': {'github': 'mysql/mysql-server'},
            'postgresql': {'github': 'postgres/postgres'},
            'mongodb': {'github': 'mongodb/mongo'},
            'redis': {'github': 'redis/redis'},
            'elasticsearch': {'github': 'elastic/elasticsearch'},
            'sqlite': {'github': 'sqlite/sqlite'},
            'mariadb': {'github': 'mariadb/server'},
            
            # Web Servers
            'nginx': {'github': 'nginx/nginx'},
            'apache': {'github': 'apache/httpd'},
            'caddy': {'github': 'caddyserver/caddy'},
            'traefik': {'github': 'traefik/traefik'},
            
            # Programming Languages
            'node': {'npm': 'node', 'github': 'nodejs/node'},
            'python': {'github': 'python/cpython'},
            'php': {'github': 'php/php-src'},
            'ruby': {'github': 'ruby/ruby'},
            'java': {'github': 'openjdk/jdk'},
            'go': {'github': 'golang/go'},
            'rust': {'github': 'rust-lang/rust'},
            'typescript': {'npm': 'typescript', 'github': 'microsoft/TypeScript'},
            
            # Build Tools
            'webpack': {'npm': 'webpack', 'github': 'webpack/webpack'},
            'vite': {'npm': 'vite', 'github': 'vitejs/vite'},
            'rollup': {'npm': 'rollup', 'github': 'roll/rollup'},
            'parcel': {'npm': 'parcel', 'github': 'parcel-bundler/parcel'},
            'gulp': {'npm': 'gulp', 'github': 'gulpjs/gulp'},
            'grunt': {'npm': 'grunt', 'github': 'gruntjs/grunt'},
            
            # Testing Frameworks
            'jest': {'npm': 'jest', 'github': 'facebook/jest'},
            'mocha': {'npm': 'mocha', 'github': 'mochajs/mocha'},
            'cypress': {'npm': 'cypress', 'github': 'cypress-io/cypress'},
            'playwright': {'npm': 'playwright', 'github': 'microsoft/playwright'},
            'pytest': {'pypi': 'pytest', 'github': 'pytest-dev/pytest'},
            'phpunit': {'packagist': 'phpunit/phpunit', 'github': 'sebastianbergmann/phpunit'},
            
            # CMS
            'wordpress': {'github': 'wordpress/wordpress'},
            'drupal': {'github': 'drupal/drupal'},
            'joomla': {'github': 'joomla/joomla-cms'},
            'ghost': {'npm': 'ghost', 'github': 'TryGhost/Ghost'},
            'strapi': {'npm': 'strapi', 'github': 'strapi/strapi'},
            'contentful': {'npm': 'contentful', 'github': 'contentful/contentful.js'},
            
            # E-commerce
            'magento': {'github': 'magento/magento2'},
            'shopify': {'github': 'Shopify/shopify-cli'},
            'woocommerce': {'github': 'woocommerce/woocommerce'},
            'prestashop': {'github': 'PrestaShop/PrestaShop'},
            
            # Security Tools
            'owasp': {'github': 'OWASP/owasp'},
            'burp': {'github': 'PortSwigger/burp-suite'},
            'zap': {'github': 'zaproxy/zaproxy'},
            'nmap': {'github': 'nmap/nmap'},
            'metasploit': {'github': 'rapid7/metasploit-framework'},
            
            # Cloud & DevOps
            'docker': {'github': 'docker/docker'},
            'kubernetes': {'github': 'kubernetes/kubernetes'},
            'terraform': {'github': 'hashicorp/terraform'},
            'ansible': {'github': 'ansible/ansible'},
            'jenkins': {'github': 'jenkinsci/jenkins'},
            'gitlab': {'github': 'gitlab-org/gitlab'},
            'github': {'github': 'github/github'},
        }
    
    def _load_cache(self) -> Dict[str, Any]:
        """Load version data from cache file."""
        if self.cache_path.exists():
            try:
                with open(self.cache_path, 'r') as f:
                    data = json.load(f)
                    # Check if cache is still valid (24 hours)
                    if 'last_updated' in data:
                        last_update = datetime.fromisoformat(data['last_updated'])
                        if datetime.now() - last_update < timedelta(hours=24):
                            return data.get('versions', {})
            except (json.JSONDecodeError, KeyError, ValueError):
                pass
        
        return self._get_default_versions()
    
    def _save_cache(self):
        """Save version data to cache file."""
        cache_data = {
            'last_updated': datetime.now().isoformat(),
            'versions': self.versions
        }
        
        try:
            with open(self.cache_path, 'w') as f:
                json.dump(cache_data, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save version cache: {e}")
    
    def _get_default_versions(self) -> Dict[str, Any]:
        """Get default version data when cache is unavailable."""
        return {
            # Frontend Frameworks - Latest stable versions as of 2024
            'jquery': {'latest': '3.7.1', 'lts': '3.7.1', 'min_safe': '3.0.0'},
            'react': {'latest': '18.2.0', 'lts': '18.2.0', 'min_safe': '16.8.0'},
            'vue': {'latest': '3.4.0', 'lts': '3.4.0', 'min_safe': '2.6.0'},
            'angular': {'latest': '17.0.0', 'lts': '16.2.0', 'min_safe': '12.0.0'},
            'bootstrap': {'latest': '5.3.2', 'lts': '5.3.2', 'min_safe': '4.6.0'},
            'foundation': {'latest': '6.8.1', 'lts': '6.8.1', 'min_safe': '6.4.0'},
            'tailwindcss': {'latest': '3.4.0', 'lts': '3.4.0', 'min_safe': '3.0.0'},
            'svelte': {'latest': '4.2.0', 'lts': '4.2.0', 'min_safe': '3.0.0'},
            'ember': {'latest': '5.0.0', 'lts': '4.12.0', 'min_safe': '3.28.0'},
            
            # Backend Frameworks
            'express': {'latest': '4.18.2', 'lts': '4.18.2', 'min_safe': '4.16.0'},
            'koa': {'latest': '2.14.2', 'lts': '2.14.2', 'min_safe': '2.13.0'},
            'hapi': {'latest': '21.0.0', 'lts': '21.0.0', 'min_safe': '20.0.0'},
            'fastify': {'latest': '4.24.0', 'lts': '4.24.0', 'min_safe': '4.0.0'},
            'django': {'latest': '5.0.0', 'lts': '4.2.0', 'min_safe': '3.2.0'},
            'flask': {'latest': '3.0.0', 'lts': '3.0.0', 'min_safe': '2.0.0'},
            'fastapi': {'latest': '0.104.0', 'lts': '0.104.0', 'min_safe': '0.68.0'},
            'rails': {'latest': '7.1.0', 'lts': '7.0.0', 'min_safe': '6.1.0'},
            'sinatra': {'latest': '3.1.0', 'lts': '3.1.0', 'min_safe': '2.2.0'},
            'spring': {'latest': '6.1.0', 'lts': '6.0.0', 'min_safe': '5.3.0'},
            'laravel': {'latest': '10.0.0', 'lts': '9.0.0', 'min_safe': '8.0.0'},
            'symfony': {'latest': '7.0.0', 'lts': '6.4.0', 'min_safe': '5.4.0'},
            'codeigniter': {'latest': '4.4.0', 'lts': '4.4.0', 'min_safe': '4.0.0'},
            'cakephp': {'latest': '5.0.0', 'lts': '4.4.0', 'min_safe': '4.0.0'},
            'yii': {'latest': '2.0.50', 'lts': '2.0.50', 'min_safe': '2.0.30'},
            'zend': {'latest': '3.6.0', 'lts': '3.6.0', 'min_safe': '3.0.0'},
            
            # Databases
            'mysql': {'latest': '8.0.35', 'lts': '8.0.35', 'min_safe': '8.0.0'},
            'postgresql': {'latest': '16.1', 'lts': '15.5', 'min_safe': '12.0'},
            'mongodb': {'latest': '7.0.0', 'lts': '6.0.0', 'min_safe': '4.4.0'},
            'redis': {'latest': '7.2.0', 'lts': '7.0.0', 'min_safe': '6.0.0'},
            'elasticsearch': {'latest': '8.11.0', 'lts': '8.10.0', 'min_safe': '7.17.0'},
            'sqlite': {'latest': '3.45.0', 'lts': '3.45.0', 'min_safe': '3.35.0'},
            'mariadb': {'latest': '11.2.0', 'lts': '10.11.0', 'min_safe': '10.5.0'},
            
            # Web Servers
            'nginx': {'latest': '1.25.0', 'lts': '1.24.0', 'min_safe': '1.20.0'},
            'apache': {'latest': '2.4.58', 'lts': '2.4.58', 'min_safe': '2.4.41'},
            'caddy': {'latest': '2.7.0', 'lts': '2.7.0', 'min_safe': '2.6.0'},
            'traefik': {'latest': '3.0.0', 'lts': '2.10.0', 'min_safe': '2.6.0'},
            
            # Programming Languages
            'node': {'latest': '20.10.0', 'lts': '20.10.0', 'min_safe': '18.0.0'},
            'python': {'latest': '3.12.0', 'lts': '3.11.0', 'min_safe': '3.8.0'},
            'php': {'latest': '8.3.0', 'lts': '8.2.0', 'min_safe': '8.0.0'},
            'ruby': {'latest': '3.3.0', 'lts': '3.2.0', 'min_safe': '3.0.0'},
            'java': {'latest': '21.0.0', 'lts': '17.0.0', 'min_safe': '11.0.0'},
            'go': {'latest': '1.21.0', 'lts': '1.20.0', 'min_safe': '1.18.0'},
            'rust': {'latest': '1.75.0', 'lts': '1.75.0', 'min_safe': '1.70.0'},
            'typescript': {'latest': '5.3.0', 'lts': '5.2.0', 'min_safe': '4.5.0'},
            
            # Build Tools
            'webpack': {'latest': '5.89.0', 'lts': '5.89.0', 'min_safe': '5.0.0'},
            'vite': {'latest': '5.0.0', 'lts': '5.0.0', 'min_safe': '4.0.0'},
            'rollup': {'latest': '4.6.0', 'lts': '4.6.0', 'min_safe': '3.0.0'},
            'parcel': {'latest': '2.10.0', 'lts': '2.10.0', 'min_safe': '2.0.0'},
            'gulp': {'latest': '5.0.0', 'lts': '4.0.0', 'min_safe': '4.0.0'},
            'grunt': {'latest': '1.6.0', 'lts': '1.6.0', 'min_safe': '1.5.0'},
            
            # Testing Frameworks
            'jest': {'latest': '29.7.0', 'lts': '29.7.0', 'min_safe': '27.0.0'},
            'mocha': {'latest': '10.2.0', 'lts': '10.2.0', 'min_safe': '9.0.0'},
            'cypress': {'latest': '13.6.0', 'lts': '13.6.0', 'min_safe': '10.0.0'},
            'playwright': {'latest': '1.40.0', 'lts': '1.40.0', 'min_safe': '1.20.0'},
            'pytest': {'latest': '7.4.0', 'lts': '7.4.0', 'min_safe': '6.0.0'},
            'phpunit': {'latest': '10.5.0', 'lts': '10.5.0', 'min_safe': '9.0.0'},
            
            # CMS
            'wordpress': {'latest': '6.4.0', 'lts': '6.3.0', 'min_safe': '5.8.0'},
            'drupal': {'latest': '10.2.0', 'lts': '9.5.0', 'min_safe': '9.0.0'},
            'joomla': {'latest': '5.0.0', 'lts': '4.4.0', 'min_safe': '4.0.0'},
            'ghost': {'latest': '5.0.0', 'lts': '5.0.0', 'min_safe': '4.0.0'},
            'strapi': {'latest': '4.15.0', 'lts': '4.15.0', 'min_safe': '4.0.0'},
            
            # E-commerce
            'magento': {'latest': '2.4.6', 'lts': '2.4.6', 'min_safe': '2.4.0'},
            'shopify': {'latest': '3.0.0', 'lts': '3.0.0', 'min_safe': '2.0.0'},
            'woocommerce': {'latest': '8.5.0', 'lts': '8.5.0', 'min_safe': '6.0.0'},
            'prestashop': {'latest': '8.1.0', 'lts': '8.1.0', 'min_safe': '1.7.0'},
            
            # Security Tools
            'owasp': {'latest': '2023.0', 'lts': '2021.0', 'min_safe': '2021.0'},
            'burp': {'latest': '2023.12.0', 'lts': '2023.12.0', 'min_safe': '2023.0'},
            'zap': {'latest': '2.14.0', 'lts': '2.14.0', 'min_safe': '2.10.0'},
            'nmap': {'latest': '7.95.0', 'lts': '7.95.0', 'min_safe': '7.80.0'},
            'metasploit': {'latest': '6.4.0', 'lts': '6.4.0', 'min_safe': '6.0.0'},
            
            # Cloud & DevOps
            'docker': {'latest': '24.0.0', 'lts': '24.0.0', 'min_safe': '20.10.0'},
            'kubernetes': {'latest': '1.29.0', 'lts': '1.28.0', 'min_safe': '1.25.0'},
            'terraform': {'latest': '1.6.0', 'lts': '1.5.0', 'min_safe': '1.0.0'},
            'ansible': {'latest': '8.0.0', 'lts': '7.0.0', 'min_safe': '6.0.0'},
            'jenkins': {'latest': '2.426.0', 'lts': '2.426.0', 'min_safe': '2.400.0'},
            'gitlab': {'latest': '16.7.0', 'lts': '16.6.0', 'min_safe': '15.0.0'},
            'github': {'latest': '2023.12.0', 'lts': '2023.12.0', 'min_safe': '2023.0'},
        }
    
    async def fetch_latest_version(self, technology: str) -> Optional[str]:
        """Fetch the latest version for a technology from its package manager."""
        if technology not in self.technology_mappings:
            return None
        
        mappings = self.technology_mappings[technology]
        
        # Try different package managers in order of preference
        for manager, package in mappings.items():
            try:
                if manager == 'npm':
                    version = await self._fetch_npm_version(package)
                elif manager == 'pypi':
                    version = await self._fetch_pypi_version(package)
                elif manager == 'maven':
                    version = await self._fetch_maven_version(package)
                elif manager == 'rubygems':
                    version = await self._fetch_rubygems_version(package)
                elif manager == 'packagist':
                    version = await self._fetch_packagist_version(package)
                elif manager == 'nuget':
                    version = await self._fetch_nuget_version(package)
                elif manager == 'github':
                    version = await self._fetch_github_version(package)
                
                if version:
                    return version
            except Exception as e:
                print(f"Warning: Failed to fetch version for {technology} from {manager}: {e}")
                continue
        
        return None
    
    async def _fetch_npm_version(self, package: str) -> Optional[str]:
        """Fetch version from npm registry."""
        url = self.api_endpoints['npm'].format(package=package)
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('dist-tags', {}).get('latest')
        return None
    
    async def _fetch_pypi_version(self, package: str) -> Optional[str]:
        """Fetch version from PyPI."""
        url = self.api_endpoints['pypi'].format(package=package)
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('info', {}).get('version')
        return None
    
    async def _fetch_maven_version(self, package: str) -> Optional[str]:
        """Fetch version from Maven Central."""
        group, artifact = package.split(':')
        url = self.api_endpoints['maven'].format(group=group, artifact=artifact)
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    docs = data.get('response', {}).get('docs', [])
                    if docs:
                        return docs[0].get('latestVersion')
        return None
    
    async def _fetch_rubygems_version(self, gem: str) -> Optional[str]:
        """Fetch version from RubyGems."""
        url = self.api_endpoints['rubygems'].format(gem=gem)
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('version')
        return None
    
    async def _fetch_packagist_version(self, package: str) -> Optional[str]:
        """Fetch version from Packagist."""
        url = self.api_endpoints['packagist'].format(package=package)
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('package', {}).get('versions', {}).get('dev-master', {}).get('version')
        return None
    
    async def _fetch_nuget_version(self, package: str) -> Optional[str]:
        """Fetch version from NuGet."""
        url = self.api_endpoints['nuget'].format(package=package)
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    versions = data.get('versions', [])
                    if versions:
                        return versions[-1]  # Latest version
        return None
    
    async def _fetch_github_version(self, repo: str) -> Optional[str]:
        """Fetch version from GitHub releases."""
        url = self.api_endpoints['github'].format(owner=repo.split('/')[0], repo=repo.split('/')[1])
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('tag_name', '').lstrip('v')
        return None
    
    async def update_versions(self, technologies: List[str] = None) -> Dict[str, str]:
        """Update versions for specified technologies or all technologies."""
        if technologies is None:
            technologies = list(self.technology_mappings.keys())
        
        updated_versions = {}
        
        for tech in technologies:
            try:
                latest_version = await self.fetch_latest_version(tech)
                if latest_version:
                    # Update the version in our database
                    if tech not in self.versions:
                        self.versions[tech] = {}
                    
                    self.versions[tech]['latest'] = latest_version
                    updated_versions[tech] = latest_version
                    
                    # If we don't have LTS or min_safe, set them based on latest
                    if 'lts' not in self.versions[tech]:
                        self.versions[tech]['lts'] = latest_version
                    if 'min_safe' not in self.versions[tech]:
                        self.versions[tech]['min_safe'] = latest_version
                        
            except Exception as e:
                print(f"Warning: Failed to update version for {tech}: {e}")
        
        # Save updated versions to cache
        self._save_cache()
        
        return updated_versions
    
    def get_version_info(self, technology: str) -> Dict[str, str]:
        """Get version information for a technology."""
        return self.versions.get(technology.lower(), {})
    
    def is_outdated(self, technology: str, version: str) -> Tuple[bool, str, str]:
        """
        Check if a technology version is outdated.
        
        Returns:
            Tuple of (is_outdated, latest_version, min_safe_version)
        """
        tech_lower = technology.lower()
        version_info = self.get_version_info(tech_lower)
        
        if not version_info:
            return False, "", ""
        
        latest = version_info.get('latest', '')
        min_safe = version_info.get('min_safe', '')
        
        if not latest or not version:
            return False, latest, min_safe
        
        # Compare versions
        is_outdated = self._version_compare(version, latest) < 0
        is_below_min_safe = self._version_compare(version, min_safe) < 0 if min_safe else False
        
        return is_outdated or is_below_min_safe, latest, min_safe
    
    def is_vulnerable(self, technology: str, version: str) -> bool:
        """Check if a technology version is vulnerable (below minimum safe version)."""
        tech_lower = technology.lower()
        version_info = self.get_version_info(tech_lower)
        
        if not version_info or not version:
            return False
        
        min_safe = version_info.get('min_safe', '')
        if not min_safe:
            return False
        
        return self._version_compare(version, min_safe) < 0
    
    def get_security_status(self, technology: str, version: str) -> Dict[str, Any]:
        """Get comprehensive security status for a technology version."""
        tech_lower = technology.lower()
        version_info = self.get_version_info(tech_lower)
        
        if not version_info or not version:
            return {
                'is_outdated': False,
                'is_vulnerable': False,
                'latest_version': '',
                'min_safe_version': '',
                'lts_version': '',
                'security_status': 'unknown'
            }
        
        latest = version_info.get('latest', '')
        min_safe = version_info.get('min_safe', '')
        lts = version_info.get('lts', '')
        
        is_outdated = self._version_compare(version, latest) < 0 if latest else False
        is_vulnerable = self._version_compare(version, min_safe) < 0 if min_safe else False
        
        # Determine security status
        if is_vulnerable:
            security_status = 'vulnerable'
        elif is_outdated:
            security_status = 'outdated'
        else:
            security_status = 'current'
        
        return {
            'is_outdated': is_outdated,
            'is_vulnerable': is_vulnerable,
            'latest_version': latest,
            'min_safe_version': min_safe,
            'lts_version': lts,
            'security_status': security_status
        }
    
    def _version_compare(self, version1: str, version2: str) -> int:
        """Compare two version strings. Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2."""
        try:
            # Clean version strings
            v1 = self._clean_version(version1)
            v2 = self._clean_version(version2)
            
            v1_parts = [int(x) for x in v1.split('.')]
            v2_parts = [int(x) for x in v2.split('.')]
            
            # Pad with zeros to make same length
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            for v1, v2 in zip(v1_parts, v2_parts):
                if v1 < v2:
                    return -1
                elif v1 > v2:
                    return 1
            return 0
        except (ValueError, AttributeError):
            return 0  # If can't compare, assume equal
    
    def _clean_version(self, version: str) -> str:
        """Clean version string for comparison."""
        if not version:
            return "0.0.0"
        
        # Remove common prefixes and suffixes
        version = version.strip().lstrip('vV').rstrip('-')
        
        # Handle special cases
        if version.lower() in ['latest', 'stable', 'current']:
            return "999.999.999"
        
        # Extract numeric parts
        import re
        parts = re.findall(r'\d+', version)
        if parts:
            return '.'.join(parts)
        
        return "0.0.0"
    
    def get_all_technologies(self) -> List[str]:
        """Get list of all supported technologies."""
        return list(self.versions.keys())
    
    def get_outdated_technologies(self, detected_technologies: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get list of outdated technologies from detected technologies."""
        outdated = []
        
        for tech_name, tech_info in detected_technologies.items():
            if isinstance(tech_info, dict) and 'version' in tech_info:
                version = tech_info['version']
                is_outdated, latest, min_safe = self.is_outdated(tech_name, version)
                
                if is_outdated:
                    security_status = self.get_security_status(tech_name, version)
                    outdated.append({
                        'name': tech_name,
                        'current_version': version,
                        'latest_version': latest,
                        'min_safe_version': min_safe,
                        'is_vulnerable': security_status['is_vulnerable'],
                        'security_status': security_status['security_status'],
                        'confidence': tech_info.get('confidence', 0.0),
                        'category': tech_info.get('category', '')
                    })
        
        return outdated


# Global instance
version_db = VersionDatabase()


def get_version_database() -> VersionDatabase:
    """Get the global version database instance."""
    return version_db
