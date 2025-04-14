# C++ SAST Vulnerability Scanner 🔍

A lightweight Python-based Static Application Security Testing (SAST) tool for analyzing C++ source code to detect common vulnerabilities.

---

## 🛡️ Detected Vulnerabilities

This tool currently detects the following types of security issues:

| Vulnerability Type           | Description                                                                 |
|-----------------------------|-----------------------------------------------------------------------------|
| ✅ Hardcoded Password        | Detects password or credential values hardcoded into the source code        |
| ✅ Buffer Overflow           | Detects use of unsafe functions like `strcpy`, `gets`                       |
| ✅ Dangerous Shell Commands  | Flags use of `rm -rf` and similar destructive commands                      |
| ✅ Command Injection         | Detects dynamic command constructions using `system`, `popen`, or `exec`    |
| ✅ Format String Vulnerability | Detects `printf(var)` patterns which may allow format string exploits       |
| ✅ Double Free               | Detects memory double freeing that can lead to undefined behavior           |
| ✅ Path Traversal            | Detects unsafe file access via variables like `fopen(getenv(...))`         |

---

## 📁 Files

### `main.py`
- Python script that analyzes `.cpp` files for security issues.
- Usage:
  ```bash
  python main.py test.cpp
