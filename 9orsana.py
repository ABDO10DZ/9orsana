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
DATABASE_FILE = "9orsana.db"  # SQLite database file
USER_INPUT_SOURCES = {'_GET', '_POST', '_REQUEST', '_COOKIE', '_SESSION', '_FILES', 'php://input'}
SENSITIVE_SINKS = {
    'mysql_query', 'mysqli_query', 'exec', 'system', 'passthru', 'shell_exec', 
    'eval', 'create_function', 'include', 'require', 'file_get_contents'
}

class _9orsanaScanner:
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
        self.code_smells = []
        self.include_graph = nx.DiGraph()
        
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
        
        # Initialize database
        self.db_conn = sqlite3.connect(DATABASE_FILE)
        self.init_database()

    def init_database(self):
        """Initialize SQLite database tables"""
        cursor = self.db_conn.cursor()
        
        # Create patterns table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            language TEXT NOT NULL,
            vuln_type TEXT NOT NULL,
            pattern TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create findings table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT NOT NULL,
            vuln_type TEXT NOT NULL,
            confidence INTEGER NOT NULL,
            description TEXT,
            source TEXT,
            context TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create self_improvements table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS self_improvements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vuln_type TEXT NOT NULL,
            language TEXT NOT NULL,
            pattern TEXT NOT NULL,
            source_file TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create code_smells table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS code_smells (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT NOT NULL,
            smell_type TEXT NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create includes table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS includes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_file TEXT NOT NULL,
            included_file TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create tainted_vars table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS tainted_vars (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT NOT NULL,
            variable TEXT NOT NULL,
            source TEXT NOT NULL,
            sinks TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        self.db_conn.commit()
        
        # Load patterns from database
        self.load_patterns_from_db()

    def load_patterns_from_db(self):
        """Load vulnerability patterns from database"""
        cursor = self.db_conn.cursor()
        cursor.execute("SELECT language, vuln_type, pattern FROM patterns")
        rows = cursor.fetchall()
        
        for row in rows:
            lang, vuln_type, pattern = row
            if lang not in self.patterns:
                self.patterns[lang] = {}
            self.patterns[lang][vuln_type] = pattern

    def save_pattern_to_db(self, language, vuln_type, pattern):
        """Save a new pattern to the database"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
        INSERT INTO patterns (language, vuln_type, pattern)
        VALUES (?, ?, ?)
        ''', (language, vuln_type, pattern))
        self.db_conn.commit()

    def save_finding_to_db(self, vuln):
        """Save vulnerability finding to database"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
        INSERT INTO findings (file_path, vuln_type, confidence, description, source)
        VALUES (?, ?, ?, ?, ?)
        ''', (
            vuln['file'],
            vuln['type'],
            vuln.get('confidence', 0),
            vuln.get('description', ''),
            vuln.get('source', 'scanner')
        ))
        self.db_conn.commit()

    def save_self_improvement_to_db(self, improvement):
        """Save self-improvement record to database"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
        INSERT INTO self_improvements (vuln_type, language, pattern, source_file)
        VALUES (?, ?, ?, ?)
        ''', (
            improvement['vulnerability'],
            improvement['language'],
            improvement['pattern'],
            improvement['source_file']
        ))
        self.db_conn.commit()

    def save_code_smell_to_db(self, smell):
        """Save code smell to database"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
        INSERT INTO code_smells (file_path, smell_type, description)
        VALUES (?, ?, ?)
        ''', (
            smell['file'],
            smell['type'],
            smell['description']
        ))
        self.db_conn.commit()

    def save_include_to_db(self, source, included):
        """Save include relationship to database"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
        INSERT INTO includes (source_file, included_file)
        VALUES (?, ?)
        ''', (source, included))
        self.db_conn.commit()

    def save_tainted_var_to_db(self, file_path, variable, source, sinks=None):
        """Save tainted variable to database"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
        INSERT INTO tainted_vars (file_path, variable, source, sinks)
        VALUES (?, ?, ?, ?)
        ''', (
            file_path,
            variable,
            source,
            json.dumps(sinks) if sinks else None
        ))
        self.db_conn.commit()

    def load_vulnerability_patterns(self):
        """Load vulnerability patterns with language-specific extensions"""
        patterns = {
            # PHP patterns
            'php': {
                'SQLi': r"mysql_query\s*\(.*?\$.*?\)",
                'LFI': r"(include|require)(_once)?\s*\(?\s*[\"']?\s*\$",
                'RCE': r"(system|exec|passthru|shell_exec)\s*\(.*?\$.*?\)",
                'XSS': r"echo\s*\$.+?;",
                'Unserialize': r"unserialize\s*\(.*?\$.*?\)",
                'XXE': r"libxml_disable_entity_loader\s*\(\s*false\s*\)",
                'Backdoor': r"(system|exec|shell_exec|passthru|eval|assert)\s*\(\s*(\$_(GET|POST|REQUEST|COOKIE)\s*\[.*?\]|php://input)",
                'SimpleBackdoor': r"\$_(GET|POST|REQUEST|COOKIE)\s*\[.*?\]\s*\)\s*;",
                'DynamicExecution': r"(eval|assert|create_function)\s*\(\s*\$",
                'DangerousFunction': r"(system|exec|shell_exec|passthru|eval|assert|popen|proc_open|pcntl_exec)\s*\("
            },
            # JavaScript patterns
            'js': {
                'XSS': r"innerHTML\s*=\s*.+?\$",
                'SQLi': r"db\.query\(.*?\$.*?\)",
                'RCE': r"eval\(.*?\$.*?\)",
                'PrototypePollution': r"__proto__|constructor\.prototype"
            },
            # Python patterns
            'py': {
                'SQLi': r"cursor\.execute\(.*?\+\s*str\(.*?\)",
                'RCE': r"subprocess\.run\(.*?shell=True.*?\)",
                'PathTraversal': r"open\(.*?\+\s*request\.args\['file'\]",
                'Pickle': r"pickle\.loads\("
            },
            # GraphQL patterns
            'graphql': {
                'Injection': r"query\s*\{\s*user\(id:\s*\$.+?\)",
                'SensitiveData': r"query\s*\{\s*users\s*\{\s*password\s*\}\s*\}",
                'Introspection': r"__schema|\s+__type\s*\{"
            }
        }
        return patterns

    def scan(self, path):
        """Main scanning workflow"""
        self.resolve_and_scan(path)
        self.analyze_include_graph()
        self.analyze_exploit_chains()
        self.analyze_code_smells()
        self.detect_obfuscated_code(path)
        self.detect_sensitive_data(path)
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
        # First do pattern-based scanning
        self.scan_generic_file(path)
    
        # Then do more sophisticated analysis
        with open(path, 'r', errors='ignore') as f:
            content = f.read()
        
            # Enhanced backdoor detection
            self.detect_php_backdoors(path, content)
        
            # Detect direct system/exec calls with user input
            if re.search(r"(system|exec|shell_exec|passthru)\s*\(\s*\$_([A-Z]+)\s*\[", content):
                self.vulns.append({
                    'type': 'RCE',
                    'file': path,
                    'confidence': 100,
                    'description': "Direct command execution with user input",
                    'source': 'pattern'
                })
                self.save_finding_to_db({
                    'type': 'RCE',
                    'file': path,
                    'confidence': 100,
                    'description': "Direct command execution with user input",
                    'source': 'pattern'
                })
    
        # AST-based analysis
        self.parse_php_ast(path)
    
        # AI-enhanced scanning
        if self.is_ai_available():
            self.ai_scan_file(path)


    def detect_php_backdoors(self, path, content):
        """Specialized detection for PHP backdoors"""
        # Pattern 1: system($_GET['cmd'])
        if re.search(r"system\s*\(\s*\$_([A-Z]+)\s*\[", content):
            self.vulns.append({
                'type': 'RCE',
                'file': path,
                'confidence': 100,
                'description': "Direct system() call with user input",
                'source': 'backdoor_detection'
            })
    
        # Pattern 2: eval($_POST['code'])
        if re.search(r"eval\s*\(\s*\$_([A-Z]+)\s*\[", content):
            self.vulns.append({
                'type': 'RCE',
                'file': path,
                'confidence': 100,
                'description': "Direct eval() call with user input",
                'source': 'backdoor_detection'
            })
    
        # Pattern 3: $_GET['a']($_GET['b'])
        if re.search(r"\$_([A-Z]+)\s*\[.*?\]\s*\(\s*\$_([A-Z]+)\s*\[", content):
            self.vulns.append({
                'type': 'RCE',
                'file': path,
                'confidence': 100,
                'description': "Dynamic function call with user input",
                'source': 'backdoor_detection'
            })
    
        # Pattern 4: obfuscated backdoors
        if re.search(r"(base64_decode|gzinflate|str_rot13)\s*\(\s*[\"'].*?[\"']\s*\)", content):
            self.vulns.append({
                'type': 'Obfuscated_Backdoor',
                'file': path,
                'confidence': 90,
                'description': "Possible obfuscated backdoor detected",
                'source': 'backdoor_detection'
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


    def parse_php_ast(self, path):
        """Parse PHP file using AST and extract includes, functions, and variables"""
        try:
            # Create AST parser script
            ast_script = """
            <?php
            require 'vendor/autoload.php';
            use PhpParser\\ParserFactory;
            use PhpParser\\NodeTraverser;
            use PhpParser\\NodeVisitor\\NameResolver;
            
            $code = file_get_contents($argv[1]);
            $parser = (new ParserFactory)->create(ParserFactory::PREFER_PHP7);
            $traverser = new NodeTraverser();
            $traverser->addVisitor(new NameResolver());
            
            try {
                $stmts = $parser->parse($code);
                $stmts = $traverser->traverse($stmts);
                $dumper = new PhpParser\\NodeDumper;
                echo $dumper->dump($stmts);
            } catch (Error $e) {
                echo "Parse error: ", $e->getMessage();
            }
            """
            
            # Write AST parser to temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.php', delete=False) as tmp_script:
                tmp_script.write(ast_script)
                tmp_script_path = tmp_script.name
            
            # Run AST parser
            result = subprocess.run(
                ['php', tmp_script_path, path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Process AST output
            ast_output = result.stdout
            self.process_php_ast(ast_output, path)
            
            # Clean up temp script
            os.unlink(tmp_script_path)
            
        except Exception as e:
            print(f"[!] PHP AST parsing failed for {path}: {e}")

    def process_php_ast(self, ast_output, path):
        """Process PHP AST output to extract includes and functions"""
        includes = []
        functions = []
        variables = []
        tainted_vars = []
        
        # Extract includes (simplified regex approach)
        include_pattern = r"Expr_Include\(.*?expr: Expr_ArrayDimFetch\(.*?var: Expr_Variable\(.*?name: (.*?)\).*?dim: Scalar_String\(.*?value: (.*?)\)"
        includes = re.findall(include_pattern, ast_output, re.DOTALL)
        
        # Process includes
        for include_type, include_path in includes:
            # Resolve relative paths
            if not os.path.isabs(include_path):
                include_path = os.path.join(os.path.dirname(path), include_path)
            
            # Normalize path
            include_path = os.path.normpath(include_path)
            
            # Add to include graph
            self.include_graph.add_edge(path, include_path)
            self.save_include_to_db(path, include_path)
            
            # Scan included file
            if os.path.exists(include_path):
                self.resolve_and_scan(include_path)
        
        # Extract function definitions
        func_pattern = r"Stmt_Function\(.*?name: (.*?)\)"
        functions = re.findall(func_pattern, ast_output)
        
        # Extract variable assignments
        var_pattern = r"Expr_Variable\(.*?name: (.*?)\)"
        variables = re.findall(var_pattern, ast_output)
        
        # Track user input sources
        user_input_vars = []
        for var in variables:
            if var in USER_INPUT_SOURCES:
                user_input_vars.append(var)
                self.tainted_vars.add(var)
                self.save_tainted_var_to_db(path, var, "user_input")
        
        # Extract function calls
        call_pattern = r"Expr_FuncCall\(.*?name: (.*?)\)"
        calls = re.findall(call_pattern, ast_output)
        
        # Analyze tainted data flow
        self.analyze_php_data_flow(path, variables, calls)

    def analyze_php_data_flow(self, path, variables, calls):
        """Analyze data flow from tainted sources to sensitive sinks"""
        # Track tainted variables through assignments
        assignment_pattern = r"Expr_Assign\(.*?var: Expr_Variable\(.*?name: (.*?)\).*?expr: Expr_Variable\(.*?name: (.*?)\)"
        assignments = re.findall(assignment_pattern, path)
        
        for target, source in assignments:
            if source in self.tainted_vars:
                self.tainted_vars.add(target)
                self.save_tainted_var_to_db(path, target, f"assignment from {source}")
        
        # Check for tainted variables in sensitive sinks
        for call in calls:
            if call in SENSITIVE_SINKS:
                # Check if any tainted variables are used in this call
                for var in self.tainted_vars:
                    if var in variables:
                        vuln_type = self.map_sink_to_vuln(call)
                        self.vulns.append({
                            'type': vuln_type,
                            'file': path,
                            'confidence': 95,
                            'description': f"Tainted variable '{var}' used in {call}",
                            'source': 'data_flow'
                        })
                        self.save_finding_to_db({
                            'type': vuln_type,
                            'file': path,
                            'confidence': 95,
                            'description': f"Tainted variable '{var}' used in {call}",
                            'source': 'data_flow'
                        })

    def map_sink_to_vuln(self, sink):
        """Map sensitive sink to vulnerability type"""
        vuln_map = {
            'mysql_query': 'SQLi',
            'mysqli_query': 'SQLi',
            'exec': 'RCE',
            'system': 'RCE',
            'passthru': 'RCE',
            'shell_exec': 'RCE',
            'eval': 'RCE',
            'create_function': 'RCE',
            'include': 'LFI',
            'require': 'LFI',
            'file_get_contents': 'FileDisclosure'
        }
        return vuln_map.get(sink, 'CodeExecution')

    def analyze_include_graph(self):
        """Analyze include relationships for potential vulnerabilities"""
        # Find circular includes
        try:
            cycles = list(nx.simple_cycles(self.include_graph))
            if cycles:
                for cycle in cycles:
                    self.vulns.append({
                        'type': 'CircularInclude',
                        'file': cycle[0],
                        'confidence': 80,
                        'description': f"Circular include detected: {' -> '.join(cycle)}"
                    })
        except nx.NetworkXNoCycle:
            pass
        
        # Find long include chains
        for path in self.include_graph.nodes:
            chain_length = len(nx.dag_longest_path(self.include_graph, path))
            if chain_length > 5:
                self.vulns.append({
                    'type': 'DeepIncludeChain',
                    'file': path,
                    'confidence': 70,
                    'description': f"Deep include chain detected: {chain_length} levels"
                })

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
                    vuln = {
                        'type': vuln_type,
                        'file': path,
                        'confidence': 80,
                        'description': f"Pattern detected: {pattern}",
                        'source': 'pattern'
                    }
                    self.vulns.append(vuln)
                    self.save_finding_to_db(vuln)
            
            # Detect PHP includes
            if file_ext == 'php':
                self.detect_php_includes(path, content)
    
    def detect_php_includes(self, path, content):
        """Detect PHP include/require statements and scan included files"""
        include_pattern = r"(include|include_once|require|require_once)\s*\(?\s*['\"](.*?)['\"]\)?;"
        matches = re.finditer(include_pattern, content)
        
        for match in matches:
            include_path = match.group(2)
            # Resolve relative paths
            if not os.path.isabs(include_path):
                include_path = os.path.join(os.path.dirname(path), include_path)
            
            # Normalize path
            include_path = os.path.normpath(include_path)
            
            # Add to include graph
            self.include_graph.add_edge(path, include_path)
            self.save_include_to_db(path, include_path)
            
            # Scan included file
            if os.path.exists(include_path):
                self.resolve_and_scan(include_path)

    def analyze_code_smells(self):
        """Detect code smells that indicate poor maintainability or potential vulnerabilities"""
        for file_path in self.visited_files:
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
                    
                    # Skip large files
                    if len(content) > MAX_FILE_SIZE:
                        continue
                    
                    # Language detection
                    file_ext = os.path.splitext(file_path)[1][1:].lower()
                    
                    # Analyze based on file type
                    if file_ext in ['php', 'js', 'py', 'java']:
                        self.detect_code_smells(file_path, content, file_ext)
                        
            except Exception as e:
                print(f"[!] Error analyzing code smells in {file_path}: {e}")

    def detect_code_smells(self, file_path, content, file_ext):
        """Detect specific code smells based on file type"""
        smells = []
        
        # Long Method/Function detection
        if file_ext == 'php':
            # Detect long functions in PHP
            function_pattern = r"function\s+\w+\s*\([^)]*\)\s*\{"
            matches = list(re.finditer(function_pattern, content))
            for i, match in enumerate(matches):
                start = match.start()
                end = content.find('}', start) + 1 if i == len(matches) - 1 else matches[i+1].start()
                function_body = content[start:end]
                lines = function_body.count('\n') + 1
                if lines > 50:
                    smells.append({
                        'type': 'LongFunction',
                        'file': file_path,
                        'description': f"Function {match.group()} has {lines} lines (recommended max: 50)"
                    })
        
        # High complexity detection
        if file_ext in ['py', 'js']:
            # Count control flow statements
            complexity_keywords = {
                'py': ['if', 'elif', 'else', 'for', 'while', 'try', 'except', 'finally'],
                'js': ['if', 'else', 'for', 'while', 'switch', 'case', 'try', 'catch', 'finally']
            }
            
            complexity_count = 0
            for keyword in complexity_keywords.get(file_ext, []):
                complexity_count += len(re.findall(r'\b' + keyword + r'\b', content))
            
            if complexity_count > 20:
                smells.append({
                    'type': 'HighComplexity',
                    'file': file_path,
                    'description': f"File has {complexity_count} control flow statements"
                })
        
        # Duplicated code detection
        if file_ext in ['php', 'js', 'py']:
            # Simple duplication detection (looking for repeated blocks)
            lines = content.splitlines()
            block_size = 5
            blocks = {}
            
            for i in range(len(lines) - block_size + 1):
                block = '\n'.join(lines[i:i+block_size])
                blocks.setdefault(block, []).append(i+1)
            
            for block, lines in blocks.items():
                if len(lines) > 1:
                    line_nums = ', '.join(map(str, lines))
                    smells.append({
                        'type': 'DuplicatedCode',
                        'file': file_path,
                        'description': f"Code duplication detected at lines: {line_nums}"
                    })
        
        # Save detected smells
        for smell in smells:
            self.code_smells.append(smell)
            self.save_code_smell_to_db(smell)

    # ... [rest of the methods remain largely the same, with database integration] ...

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
                self.save_finding_to_db(finding)
                
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
                    
                    # Save pattern to database
                    self.save_pattern_to_db(file_ext, vuln_type, pattern)
                    
                    # Save self-improvement
                    improvement = {
                        'vulnerability': vuln_type,
                        'language': file_ext,
                        'pattern': pattern,
                        'source_file': finding['file']
                    }
                    self.self_improvements.append(improvement)
                    self.save_self_improvement_to_db(improvement)
        except Exception as e:
            print(f"[!] Failed to create pattern for {vuln_type}: {e}")

    # ... [other methods like generate_report, cleanup, etc.] ...



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


    def detect_obfuscated_code(self,path):
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



def main():
    parser = argparse.ArgumentParser(
        description="_9orsana Vulnerability SourceCode Scanner with AI Capabilities and Self-Improvement",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--cms", choices=['WordPress', 'Joomla'], help="CMS type to scan")
    parser.add_argument("--plugin", help="Plugin/theme name to install and scan")
    parser.add_argument("--path", help="Direct path to scan (instead of installing)")
    parser.add_argument("-o", "--output", default="report.json", help="Output file name")
    parser.add_argument("--self-update", action="store_true", help="Enable self-updating capability")
    args = parser.parse_args()

    scanner = _9orsanaScanner()
    
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
