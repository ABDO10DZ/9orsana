#!/usr/bin/env python3
import os
import sys
import json
import re
import shutil
import sqlite3
import argparse
import subprocess
import tempfile
import hashlib
import math
import difflib
import requests
import importlib
import inspect
import ast as py_ast
import networkx as nx
import numpy as np
from collections import defaultdict, deque
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
import matplotlib.cm as cm

# Configuration
CONFIDENCE_THRESHOLD = 75
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ENTROPY_THRESHOLD = 4.5
AI_ENDPOINT = "http://localhost:11434/api/generate"  # DeepSeek API endpoint
SELF_IMPROVE_THRESHOLD = 0.8  # Confidence threshold for self-updates

class UnifiedScanner:
    def __init__(self):
        # Core scanner state
        self.visited_files = set()
        self.vulns = []
        self.all_functions = {}
        self.all_calls = defaultdict(list)
        self.tainted_vars = set()
        self.call_graph = nx.DiGraph()
        self.data_flows = defaultdict(list)
        self.hook_map = defaultdict(set)
        self.behavior_profile = defaultdict(int)
        self.vuln_heatmap = defaultdict(int)
        
        # CMS state
        self.cms_type = None
        self.temp_dir = None
        self.work_dir = None
        
        # AI state
        self.ai_history = []
        self.self_improvements = []
        self.language_adapters = {
            'php': self.scan_php_file,
            'js': self.scan_js_file,
            'py': self.scan_python_file,
            'java': self.scan_java_file,
            'graphql': self.scan_graphql_file
        }
        
        # Vulnerability patterns
        self.patterns = self.load_vulnerability_patterns()

    def load_vulnerability_patterns(self):
        """Load vulnerability patterns with language-specific extensions"""
        patterns = {
            # PHP patterns
            'php': {
                'SQLi': r"mysql_query\s*\(.*?\$.*?\)",
                'LFI': r"(include|require)(_once)?\s*\(?\s*[\"']?\s*\$",
                'RCE': r"(system|exec|passthru|shell_exec)\s*\(.*?\$.*?\)",
                'XSS': r"echo\s*\$.+?;"
            },
            # JavaScript patterns
            'js': {
                'XSS': r"innerHTML\s*=\s*.+?\$",
                'SQLi': r"db\.query\(.*?\$.*?\)",
                'RCE': r"eval\(.*?\$.*?\)"
            },
            # Python patterns
            'py': {
                'SQLi': r"cursor\.execute\(.*?\+\s*str\(.*?\)",
                'RCE': r"subprocess\.run\(.*?shell=True.*?\)",
                'PathTraversal': r"open\(.*?\+\s*request\.args\['file'\]"
            },
            # GraphQL patterns
            'graphql': {
                'Injection': r"query\s*\{\s*user\(id:\s*\$.+?\)",
                'SensitiveData': r"query\s*\{\s*users\s*\{\s*password\s*\}\s*\}"
            }
        }
        return patterns

    def install_cms_plugin(self, cms_type, plugin_name):
        """Install CMS and plugin/theme using CLI tools"""
        self.cms_type = cms_type
        self.temp_dir = tempfile.mkdtemp(prefix="vuln_scanner_")
        print(f"[*] Created temporary directory: {self.temp_dir}")
        
        try:
            if cms_type == "WordPress":
                return self.install_wordpress(plugin_name)
            elif cms_type == "Joomla":
                return self.install_joomla(plugin_name)
            else:
                raise ValueError(f"Unsupported CMS: {cms_type}")
        except Exception as e:
            print(f"[!] Failed to install {cms_type} plugin: {e}")
            shutil.rmtree(self.temp_dir)
            sys.exit(1)

    def install_wordpress(self, plugin_name):
        """Install WordPress and plugin using WP-CLI"""
        print("[*] Installing WordPress...")
        self.work_dir = os.path.join(self.temp_dir, "wordpress")
        os.makedirs(self.work_dir)
        
        # Download WordPress
        subprocess.run(["wp", "core", "download", "--path=" + self.work_dir], check=True)
        
        # Create config
        subprocess.run([
            "wp", "config", "create", 
            "--path=" + self.work_dir,
            "--dbname=temp_db",
            "--dbuser=root",
            "--dbpass=pass",
            "--skip-check"
        ], check=True)
        
        # Install plugin
        print(f"[*] Installing plugin: {plugin_name}")
        if plugin_name.endswith(".zip") or "://" in plugin_name:
            subprocess.run([
                "wp", "plugin", "install", 
                plugin_name,
                "--path=" + self.work_dir,
                "--activate"
            ], check=True)
        else:
            subprocess.run([
                "wp", "plugin", "install", 
                plugin_name,
                "--path=" + self.work_dir,
                "--activate"
            ], check=True)
            
        plugin_path = os.path.join(self.work_dir, "wp-content", "plugins", plugin_name)
        if not os.path.exists(plugin_path):
            plugins = [d for d in os.listdir(os.path.join(self.work_dir, "wp-content", "plugins")) 
                      if d.startswith(plugin_name)]
            if plugins:
                plugin_path = os.path.join(self.work_dir, "wp-content", "plugins", plugins[0])
        
        return plugin_path

    def install_joomla(self, extension_name):
        """Install Joomla and extension using Joomla CLI"""
        print("[*] Installing Joomla...")
        self.work_dir = os.path.join(self.temp_dir, "joomla")
        os.makedirs(self.work_dir)
        
        # Download Joomla
        subprocess.run([
            "joomla", "site:download", 
            "--release=latest", 
            self.work_dir
        ], check=True)
        
        # Install extension
        print(f"[*] Installing extension: {extension_name}")
        if extension_name.endswith(".zip") or "://" in plugin_name:
            subprocess.run([
                "joomla", "extension:install",
                "file", extension_name,
                "--www=" + self.work_dir
            ], check=True)
        else:
            subprocess.run([
                "joomla", "extension:install",
                "package", extension_name,
                "--www=" + self.work_dir
            ], check=True)
        
        # Try to find installed extension
        ext_path = None
        for root, dirs, files in os.walk(os.path.join(self.work_dir, "components")):
            if extension_name in root:
                ext_path = root
                break
        
        if not ext_path:
            for root, dirs, files in os.walk(os.path.join(self.work_dir, "plugins")):
                if extension_name in root:
                    ext_path = root
                    break
        
        return ext_path

    def scan(self, path):
        """Main scanning workflow"""
        self.resolve_and_scan(path)
        self.analyze_exploit_chains()
        self.analyze_code_smells()
        self.detect_obfuscated_code()
        self.detect_sensitive_data()
        self.analyze_behavior_profile()
        self.analyze_trigger_surface()
        self.generate_vuln_heatmap()
        return self.vulns

    def resolve_and_scan(self, path):
        """Recursive file scanning with include resolution"""
        path = os.path.realpath(path)
        if path in self.visited_files or not os.path.isfile(path):
            return
        
        self.visited_files.add(path)
        print(f"[+] Scanning: {path}")
        
        # Detect language and scan
        file_ext = os.path.splitext(path)[1][1:].lower()
        scanner = self.language_adapters.get(file_ext, self.scan_generic_file)
        scanner(path)

    def scan_php_file(self, path):
        """Scan PHP file with advanced analysis"""
        # Core PHP scanning
        self.scan_generic_file(path)
        
        # AI-enhanced scanning
        if self.is_ai_available():
            self.ai_scan_file(path)

    def scan_generic_file(self, path):
        """Generic file scanning with pattern detection"""
        with open(path, 'r', errors='ignore') as f:
            content = f.read()
            
            # Language detection
            file_ext = os.path.splitext(path)[1][1:].lower()
            lang_patterns = self.patterns.get(file_ext, {})
            
            # Pattern-based scanning
            for vuln_type, pattern in lang_patterns.items():
                if re.search(pattern, content):
                    self.vulns.append({
                        'type': vuln_type,
                        'file': path,
                        'confidence': 80,
                        'description': f"Pattern detected: {pattern}"
                    })

    def scan_js_file(self, path):
        """Scan JavaScript files"""
        with open(path, 'r') as f:
            content = f.read()
            
            # Pattern scanning
            for vuln_type, pattern in self.patterns.get('js', {}).items():
                if re.search(pattern, content):
                    self.vulns.append({
                        'type': vuln_type,
                        'file': path,
                        'confidence': 75,
                        'description': f"JS pattern detected: {pattern}"
                    })
            
            # AI scanning if available
            if self.is_ai_available():
                self.ai_scan_file(path)

    def scan_python_file(self, path):
        """Scan Python files"""
        with open(path, 'r') as f:
            content = f.read()
            
            # Pattern scanning
            for vuln_type, pattern in self.patterns.get('py', {}).items():
                if re.search(pattern, content):
                    self.vulns.append({
                        'type': vuln_type,
                        'file': path,
                        'confidence': 85,
                        'description': f"Python pattern detected: {pattern}"
                    })
            
            # AST-based scanning
            try:
                tree = py_ast.parse(content)
                self.analyze_python_ast(tree, path)
            except SyntaxError:
                pass
            
            # AI scanning
            if self.is_ai_available():
                self.ai_scan_file(path)

    def scan_java_file(self, path):
        """Scan Java files"""
        with open(path, 'r') as f:
            content = f.read()
            
            # Basic pattern scanning
            if re.search(r"Runtime\.getRuntime\(\)\.exec\(.*?\)", content):
                self.vulns.append({
                    'type': 'RCE',
                    'file': path,
                    'confidence': 90,
                    'description': "Potential command execution in Java"
                })
            
            # AI scanning
            if self.is_ai_available():
                self.ai_scan_file(path)

    def scan_graphql_file(self, path):
        """Scan GraphQL files"""
        with open(path, 'r') as f:
            content = f.read()
            
            # Pattern scanning
            for vuln_type, pattern in self.patterns.get('graphql', {}).items():
                if re.search(pattern, content):
                    self.vulns.append({
                        'type': vuln_type,
                        'file': path,
                        'confidence': 85,
                        'description': f"GraphQL pattern detected: {pattern}"
                    })
            
            # AI scanning for complex vulnerabilities
            if self.is_ai_available():
                self.ai_scan_file(path)

    def analyze_python_ast(self, tree, path):
        """Analyze Python AST for vulnerabilities"""
        for node in py_ast.walk(tree):
            # SQL injection detection
            if isinstance(node, py_ast.Call) and isinstance(node.func, py_ast.Attribute):
                if node.func.attr == 'execute' and isinstance(node.func.value, py_ast.Name):
                    for arg in node.args:
                        if isinstance(arg, py_ast.BinOp) and isinstance(arg.op, py_ast.Add):
                            self.vulns.append({
                                'type': 'SQLi',
                                'file': path,
                                'confidence': 90,
                                'description': "Possible SQL injection with string concatenation"
                            })
            
            # Command injection detection
            if isinstance(node, py_ast.Call) and isinstance(node.func, py_ast.Attribute):
                if node.func.attr == 'run' and isinstance(node.func.value, py_ast.Name):
                    if node.func.value.id == 'subprocess':
                        for keyword in node.keywords:
                            if keyword.arg == 'shell' and isinstance(keyword.value, py_ast.NameConstant):
                                if keyword.value.value:
                                    self.vulns.append({
                                        'type': 'RCE',
                                        'file': path,
                                        'confidence': 95,
                                        'description': "Potential command injection with shell=True"
                                    })

    def is_ai_available(self):
        """Check if AI endpoint is available"""
        try:
            response = requests.get(AI_ENDPOINT.replace("/generate", ""), timeout=2)
            return response.status_code == 200
        except:
            return False

    def ai_scan_file(self, path):
        """Use AI to scan file for vulnerabilities"""
        try:
            with open(path, 'r') as f:
                content = f.read()
            
            # Create prompt
            prompt = {
                "model": "deepseek-coder",
                "prompt": f"Analyze the following code for security vulnerabilities:\n\n{content[:5000]}\n\nList any vulnerabilities found in JSON format with fields: type, description, confidence, and line_number. If no vulnerabilities, return empty list.",
                "format": "json",
                "stream": False
            }
            
            # Call AI API
            response = requests.post(AI_ENDPOINT, json=prompt)
            response.raise_for_status()
            result = response.json()
            
            # Process AI findings
            ai_findings = json.loads(result.get("response", "[]"))
            for finding in ai_findings:
                finding['file'] = path
                finding['source'] = 'AI'
                self.vulns.append(finding)
                
                # Record for self-improvement
                self.ai_history.append({
                    'file': path,
                    'vulnerability': finding,
                    'prompt': prompt['prompt'],
                    'response': result
                })
                
                # Check if we need to improve the scanner
                if finding.get('confidence', 0) > SELF_IMPROVE_THRESHOLD * 100:
                    self.consider_self_improvement(finding)
            
            return ai_findings
        except Exception as e:
            print(f"[!] AI scan failed for {path}: {e}")
            return []

    def consider_self_improvement(self, finding):
        """Consider improving the scanner based on AI findings"""
        vuln_type = finding['type']
        file_ext = os.path.splitext(finding['file'])[1][1:].lower()
        
        # Check if we already have a pattern for this vulnerability
        if vuln_type in self.patterns.get(file_ext, {}):
            return
        
        # Ask AI to create a detection pattern
        prompt = {
            "model": "deepseek-coder",
            "prompt": f"Create a regex pattern to detect '{vuln_type}' vulnerabilities in {file_ext.upper()} code based on this example:\n\n{finding['description']}\n\nReturn only the regex pattern.",
            "format": "text",
            "stream": False
        }
        
        try:
            response = requests.post(AI_ENDPOINT, json=prompt)
            response.raise_for_status()
            result = response.json()
            
            pattern = result.get("response", "").strip()
            if pattern and pattern.startswith('/') and pattern.endswith('/'):
                pattern = pattern[1:-1]
            
            if pattern:
                # Test the pattern
                if self.test_pattern(pattern, finding['file'], vuln_type):
                    # Add to patterns
                    if file_ext not in self.patterns:
                        self.patterns[file_ext] = {}
                    self.patterns[file_ext][vuln_type] = pattern
                    print(f"[*] Added new pattern for {vuln_type}: {pattern}")
                    
                    # Save self-improvement
                    self.self_improvements.append({
                        'vulnerability': vuln_type,
                        'language': file_ext,
                        'pattern': pattern,
                        'source_file': finding['file']
                    })
        except Exception as e:
            print(f"[!] Failed to create pattern for {vuln_type}: {e}")

    def test_pattern(self, pattern, file_path, vuln_type):
        """Test if a pattern correctly identifies a vulnerability"""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
                if re.search(pattern, content):
                    return True
        except:
            pass
        return False

    def self_improve_scanner(self):
        """Apply self-improvements to the scanner code"""
        if not self.self_improvements:
            return
        
        # Get current scanner code
        current_file = os.path.abspath(__file__)
        with open(current_file, 'r') as f:
            current_code = f.read()
        
        # Create updated patterns section
        patterns_section = "    patterns = {\n"
        for lang, lang_patterns in self.patterns.items():
            patterns_section += f"        '{lang}': {{\n"
            for vuln_type, pattern in lang_patterns.items():
                patterns_section += f"            '{vuln_type}': r\"{pattern}\",\n"
            patterns_section += "        },\n"
        patterns_section += "    }"
        
        # Update the code
        new_code = re.sub(
            r"patterns = \{.*?\}",
            patterns_section,
            current_code,
            flags=re.DOTALL
        )
        
        # Write updated code to temp file
        temp_file = tempfile.mktemp(suffix='.py')
        with open(temp_file, 'w') as f:
            f.write(new_code)
        
        # Test the updated scanner
        if self.test_updated_scanner(temp_file):
            # Replace current file
            shutil.move(temp_file, current_file)
            print("[*] Scanner successfully self-updated!")
            return True
        else:
            os.remove(temp_file)
            return False

    def test_updated_scanner(self, temp_file):
        """Test the updated scanner with a known vulnerability"""
        try:
            # Create test file with vulnerability
            test_file = tempfile.mktemp(suffix='.php')
            with open(test_file, 'w') as f:
                f.write("<?php\n$id = $_GET['id'];\necho \"SELECT * FROM users WHERE id = $id\";")
            
            # Import updated scanner
            spec = importlib.util.spec_from_file_location("updated_scanner", temp_file)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            scanner = module.UnifiedScanner()
            
            # Run scan
            findings = scanner.scan(test_file)
            
            # Check if vulnerability was detected
            for finding in findings:
                if finding['type'] == 'SQLi':
                    return True
        except Exception as e:
            print(f"[!] Self-update test failed: {e}")
        
        return False

    def detect_obfuscated_code(self, path):
        """Detect obfuscated code using entropy analysis"""
        with open(path, 'r', errors='ignore') as f:
            content = f.read()
            entropy = self.calculate_entropy(content)
            if entropy > ENTROPY_THRESHOLD:
                self.vulns.append({
                    'type': 'Obfuscated_Code',
                    'file': path,
                    'confidence': 80,
                    'description': f"High entropy code (possible obfuscation): {entropy:.2f}"
                })

    def calculate_entropy(self, text):
        """Calculate Shannon entropy of a text string"""
        if not text:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = float(text.count(chr(x))) / len(text)
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)
                
        return entropy

    def detect_sensitive_data(self, path):
        """Detect sensitive data in files"""
        sensitive_patterns = {
            "AWS Key": r"AKIA[0-9A-Z]{16}",
            "Secret Key": r"sk_(live|test)_[0-9a-zA-Z]{24}",
            "Database Password": r"['\"]db_pass['\"]\s*=>\s*['\"][^'\"]{8,}['\"]",
            "JWT Secret": r"['\"]jwt_secret['\"]\s*=>\s*['\"][^'\"]{20,}['\"]"
        }
        
        with open(path, 'r', errors='ignore') as f:
            content = f.read()
            for name, pattern in sensitive_patterns.items():
                if re.search(pattern, content):
                    self.vulns.append({
                        'type': 'Sensitive_Data',
                        'file': path,
                        'confidence': 95,
                        'description': f"Potential {name} exposure"
                    })

    def analyze_behavior_profile(self):
        """Analyze code behavior based on vulnerability findings"""
        behavior_counts = defaultdict(int)
        for vuln in self.vulns:
            behavior_counts[vuln['type']] += 1
        
        # Add to profile
        self.behavior_profile.update(behavior_counts)

    def analyze_trigger_surface(self):
        """Analyze vulnerability exposure"""
        exposed_count = sum(1 for vuln in self.vulns if vuln.get('confidence', 0) > 80)
        self.behavior_profile['exposed_vulnerabilities'] = exposed_count

    def generate_vuln_heatmap(self):
        """Generate vulnerability heatmap visualization"""
        if not self.vulns:
            return
            
        # Create file risk scores
        file_risks = defaultdict(int)
        for vuln in self.vulns:
            file_risks[vuln['file']] += vuln.get('confidence', 0) / 100
        
        # Generate visualization
        plt.figure(figsize=(12, 8))
        files = list(file_risks.keys())
        scores = [file_risks[file] for file in files]
        
        # Normalize scores
        max_score = max(scores) if scores else 1
        norm_scores = [s / max_score for s in scores]
        colors = cm.Reds(norm_scores)
        
        for i, file in enumerate(files):
            plt.barh(file, norm_scores[i], color=colors[i])
        
        plt.title('Vulnerability Heatmap')
        plt.xlabel('Risk Score')
        plt.tight_layout()
        plt.savefig('vulnerability_heatmap.png')
        print("[*] Generated vulnerability_heatmap.png")

    def analyze_exploit_chains(self):
        """Detect multi-step exploit chains"""
        # Group vulnerabilities by context
        vuln_chains = defaultdict(list)
        for vuln in self.vulns:
            key = (vuln['file'], vuln.get('context', ''))
            vuln_chains[key].append(vuln)
        
        # Find chains
        for key, vulns in vuln_chains.items():
            if len(vulns) > 1:
                chain_types = ', '.join({v['type'] for v in vulns})
                self.vulns.append({
                    'type': 'Chained_Vulnerability',
                    'file': key[0],
                    'confidence': 90,
                    'description': f"Chained vulnerabilities: {chain_types}",
                    'chain': [v['type'] for v in vulns]
                })

    def generate_report(self, output_file):
        """Generate comprehensive JSON report"""
        report = {
            "metadata": {
                "scanned_files": len(self.visited_files),
                "cms_type": self.cms_type,
                "behavior_profile": dict(self.behavior_profile),
                "self_improvements": self.self_improvements
            },
            "vulnerabilities": self.vulns,
            "files_scanned": list(self.visited_files)
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

    def cleanup(self):
        """Clean up temporary files"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
            print(f"[*] Cleaned up temporary directory: {self.temp_dir}")

def main():
    parser = argparse.ArgumentParser(
        description="Unified Vulnerability Scanner with AI and Self-Improvement",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--cms", choices=['WordPress', 'Joomla'], help="CMS type to scan")
    parser.add_argument("--plugin", help="Plugin/theme name to install and scan")
    parser.add_argument("--path", help="Direct path to scan (instead of installing)")
    parser.add_argument("-o", "--output", default="report.json", help="Output file name")
    parser.add_argument("--self-update", action="store_true", help="Enable self-updating capability")
    args = parser.parse_args()

    scanner = UnifiedScanner()
    
    # Install and scan CMS plugin
    if args.cms and args.plugin:
        scan_path = scanner.install_cms_plugin(args.cms, args.plugin)
        findings = scanner.scan(scan_path)
    # Scan direct path
    elif args.path:
        findings = scanner.scan(args.path)
    else:
        print("Please specify either --cms and --plugin or --path")
        sys.exit(1)
    
    # Apply self-improvements
    if args.self_update and scanner.self_improvements:
        scanner.self_improve_scanner()
    
    scanner.generate_report(args.output)
    scanner.cleanup()
    
    print(f"\n[✓] Scan completed. Results saved to {args.output}")
    print(f"    Files scanned: {len(scanner.visited_files)}")
    print(f"    Vulnerabilities found: {len(findings)}")
    print(f"    Self-improvements: {len(scanner.self_improvements)}")
    
    # Show behavior profile
    print("\nBehavior Profile:")
    for k, v in scanner.behavior_profile.items():
        print(f"  {k}: {v}")

if __name__ == "__main__":
    # Verify CLI tools
    try:
        subprocess.run(["wp", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["joomla", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print("Warning: WP-CLI or Joomla CLI not found. CMS installation disabled.")
    
    main()
