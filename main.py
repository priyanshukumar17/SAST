import re
import sys

class CppSASTAnalyzer:
    def __init__(self, code_line):
        self.lines = code_line
        self.issues = []

    def analyze(self):
        for lineno, line in enumerate(self.lines, start=1):
            self.check_hardcoded_passwords(line, lineno)
            self.check_sql_injection(line, lineno)
            self.check_buffer_overflow(line, lineno)
            self.check_command_injection(line, lineno)
            self.check_memory_safety(line, lineno)
            self.check_format_string(line, lineno)
            self.check_path_traversal(line, lineno)

    def check_hardcoded_passwords(self, line, lineno):
        if re.search(r'\b(pass(word|wd)?|pwd|psswd)\b\s*=\s*".+"', line, re.IGNORECASE):
            self.issues.append((lineno, "Hardcoded password", line.strip()))

    def check_sql_injection(self, line, lineno):
        if re.search(r'".*(SELECT|INSERT|UPDATE|DELETE|DROP).*"\s*\+', line, re.IGNORECASE):
            self.issues.append((lineno, "Possible SQL injection", line.strip()))

    def check_buffer_overflow(self, line, lineno):
        if re.search(r'\b(strcpy|gets)\s*\(', line):
            self.issues.append((lineno, "Possible buffer overflow", line.strip()))

    def check_command_injection(self, line, lineno):
        if re.search(r'\b(system|popen|exec)\s*\(.*\+\s*\w+', line):
            self.issues.append((lineno, "Possible command injection", line.strip()))
        if re.search(r'\b(system|popen|exec)\s*\(.*["\']\s*rm\s+(-rf|-r\b|--no-preserve-root)', line, re.IGNORECASE):
            self.issues.append((lineno, "Dangerous shell command (rm -rf)", line.strip()))

    def check_memory_safety(self, line, lineno):
        if re.search(r'\bfree\s*\(\s*\w+\s*\);.*\bfree\s*\(\s*\w+\s*\);', line):
            self.issues.append((lineno, "Double free vulnerability", line.strip()))
        if re.search(r'\bfree\s*\((\w+)\);\s*\1\s*=.*;', line):
            self.issues.append((lineno, "Use-after-free vulnerability", line.strip()))

    def check_format_string(self, line, lineno):
        if re.search(r'\bprintf\s*\(\s*\w+\s*\)', line):
            self.issues.append((lineno, "Format string vulnerability", line.strip()))

    def check_path_traversal(self, line, lineno):
        if re.search(r'\b(fopen|ifstream|ofstream)\s*\(\s*\w+', line):
            self.issues.append((lineno, "Possible path traversal", line.strip()))

    def report(self):
        if not self.issues:
            print("No vulnerabilities found.")
        for issue in self.issues:
            print(f"Issue on line {issue[0]}: [{issue[1]}] → {issue[2]}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 main.py <filename.cpp>")
        sys.exit(1)

    try:
        with open(sys.argv[1], "r", encoding="utf-8") as f:
            code_lines = f.readlines()
        analyzer = CppSASTAnalyzer(code_lines)
        analyzer.analyze()
        analyzer.report()
    except Exception as e:
        print(f"Error: {e}")
