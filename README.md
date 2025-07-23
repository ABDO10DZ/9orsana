# 9orsana
### Key Innovations:

1. **9orsana Scanning Architecture**:
   - Single scanner for all languages and CMS platforms
   - Language-specific adapters (PHP, JS, Python, Java, GraphQL)
   - CMS auto-installation (WordPress/Joomla)

2. **DeepSeek AI Integration**:
   - Local API endpoint for vulnerability detection
   - AI-generated vulnerability reports
   - Context-aware scanning prompts

3. **Self-Improvement Capability**:
   - Pattern generation from AI findings
   - Automated scanner testing
   - Safe self-update mechanism
   - Continuous learning from scans

4. **Multi-Language Support**:
   - PHP (with CMS-specific enhancements)
   - JavaScript (client-side vulnerabilities)
   - Python (AST-based analysis)
   - Java (basic pattern matching)
   - GraphQL (query analysis)

5. **Advanced Features**:
   - Vulnerability chaining detection
   - Behavior profiling
   - Risk heatmap visualization
   - Entropy-based obfuscation detection
   - Sensitive data exposure scanning

### Installation Guide:

1. **Install Dependencies**:
```bash
# PHP scanning
sudo apt-get install php php-ast

# Python dependencies
pip install requests numpy scikit-learn matplotlib networkx

# WP-CLI
curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
chmod +x wp-cli.phar
sudo mv wp-cli.phar /usr/local/bin/wp

# Joomla CLI
wget https://github.com/joomlatools/joomlatools-console/releases/download/v1.6.0/joomla.phar
chmod +x joomla.phar
sudo mv joomla.phar /usr/local/bin/joomla

# DeepSeek (using Ollama)
curl https://ollama.ai/install.sh | sh
ollama run deepseek-coder
```

2. **Run the Scanner**:

**Scan WordPress plugin**:
```bash
python scanner.py --cms WordPress --plugin contact-form-7 -o report.json --self-update
```

**Scan local GraphQL API**:
```bash
python scanner.py --path ./graphql/schema.graphql -o graphql_report.json
```

**Scan Python web app**:
```bash
python scanner.py --path ./myapp --self-update
```

### Self-Improvement Process:

1. **Detection**:
   - AI finds vulnerability not covered by current patterns
   - Confidence exceeds threshold (80%)

2. **Pattern Generation**:
   - AI creates regex pattern for detection
   - Pattern tested on vulnerable file

3. **Scanner Update**:
   - Updated scanner tested with known vulnerability
   - If successful, scanner replaces itself
   - New pattern added to detection engine

### Sample Output:

```json
{
  "metadata": {
    "scanned_files": 27,
    "cms_type": "WordPress",
    "behavior_profile": {
      "SQLi": 2,
      "XSS": 3,
      "exposed_vulnerabilities": 4,
      "Obfuscated_Code": 1
    },
    "self_improvements": [
      {
        "vulnerability": "GraphQL_Injection",
        "language": "graphql",
        "pattern": "query\\s*\\{\\s*user\\(id:\\s*\\$.+?\\)",
        "source_file": "/plugins/myplugin/graphql/schema.graphql"
      }
    ]
  },
  "vulnerabilities": [
    {
      "type": "SQLi",
      "file": "/plugins/contact-form-7/includes/db.php",
      "line": 42,
      "confidence": 95,
      "description": "Unsafe SQL query construction with user input"
    },
    {
      "type": "GraphQL_Injection",
      "file": "/plugins/myplugin/graphql/schema.graphql",
      "confidence": 92,
      "description": "User input directly used in GraphQL query",
      "source": "AI"
    },
    {
      "type": "Chained_Vulnerability",
      "file": "/plugins/myplugin/upload.php",
      "confidence": 90,
      "description": "Chained vulnerabilities: File_Upload, LFI",
      "chain": ["File_Upload", "LFI"]
    }
  ],
  "files_scanned": [
    "/plugins/contact-form-7/contact-form-7.php",
    "/plugins/contact-form-7/includes/db.php",
    "/plugins/myplugin/graphql/schema.graphql",
    "/plugins/myplugin/upload.php"
  ]
}
```

### Visual Outputs:

1. **Vulnerability Heatmap**:
   - `vulnerability_heatmap.png` shows risk distribution
   - Redder bars indicate higher-risk files

2. **Behavior Profile**:
   - Vulnerability type distribution
   - Exposure risk assessment
   - Security posture summary

9orsana scanner combines all our previous capabilities with AI-powered detection and self-improvement, creating a powerful tool that evolves with each scan. The CMS integration and multi-language support make it versatile for various security assessment scenarios.
