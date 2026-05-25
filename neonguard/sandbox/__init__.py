"""
NeonGuard Sandbox Analyzer
===========================
Static analysis of Python code for dangerous patterns.
Does NOT execute code — performs AST + regex analysis.
"""

import ast
import re
import logging
from typing import Dict, Any, List

logger = logging.getLogger("neonguard.sandbox")

_DANGEROUS_IMPORTS = {
    "os": ("os module", "high"),
    "subprocess": ("subprocess module", "critical"),
    "sys": ("sys module", "medium"),
    "shutil": ("shutil module", "high"),
    "socket": ("socket module", "medium"),
    "ctypes": ("ctypes module", "critical"),
    "multiprocessing": ("multiprocessing module", "medium"),
    "threading": ("threading module", "low"),
    "importlib": ("importlib module", "high"),
    "pickle": ("pickle module (deserialization risk)", "high"),
    "marshal": ("marshal module", "high"),
    "pty": ("pty module (pseudo-terminal)", "high"),
    "signal": ("signal module", "medium"),
}

_DANGEROUS_CALLS = [
    (r"\beval\s*\(", "eval() call", "critical"),
    (r"\bexec\s*\(", "exec() call", "critical"),
    (r"\bcompile\s*\(", "compile() call", "high"),
    (r"\b__import__\s*\(", "__import__() call", "high"),
    (r"\bgetattr\s*\(.*__", "getattr with dunder", "medium"),
    (r"\bsetattr\s*\(", "setattr() call", "medium"),
    (r"\bdelattr\s*\(", "delattr() call", "medium"),
    (r"\bopen\s*\(", "open() file access", "low"),
    (r"\bos\.system\s*\(", "os.system() call", "critical"),
    (r"\bos\.popen\s*\(", "os.popen() call", "critical"),
    (r"\bos\.execv", "os.execv() call", "critical"),
    (r"\bsubprocess\.(call|run|Popen|check_output)\s*\(", "subprocess call", "critical"),
    (r"shell\s*=\s*True", "shell=True in subprocess", "critical"),
    (r"\b__builtins__", "Access to __builtins__", "high"),
    (r"\bglobals\s*\(\s*\)", "globals() access", "high"),
    (r"\blocals\s*\(\s*\)", "locals() access", "medium"),
    (r"\bvars\s*\(\s*\)", "vars() access", "medium"),
]

_INFINITE_LOOP_PATTERNS = [
    (r"while\s+True\s*:", "while True loop"),
    (r"while\s+1\s*:", "while 1 loop"),
    (r"for\s+\w+\s+in\s+iter\(int,\s*1\)", "iter-based infinite loop"),
]


class SafeRunner:
    """
    Static Python code safety analyzer.

    Does NOT execute the code. Uses AST parsing and regex
    to detect dangerous patterns before execution.

    Example:
        >>> runner = SafeRunner()
        >>> result = runner.analyze("import os; os.system('rm -rf /')")
        >>> print(result['safe'])    # False
        >>> print(result['risks'])   # List of detected risks
    """

    def analyze(self, code: str) -> Dict[str, Any]:
        """
        Analyze Python source code for security risks.

        Returns:
            {
                'safe': bool,
                'risks': list of risk dicts,
                'severity': str ('safe'|'low'|'medium'|'high'|'critical'),
                'summary': str,
            }
        """
        if not code or not code.strip():
            return self._safe_result("Empty code provided.")

        risks = []

        # 1. AST-based analysis
        try:
            tree = ast.parse(code)
            risks.extend(self._ast_analysis(tree))
        except SyntaxError as e:
            risks.append({
                "type": "syntax_error",
                "description": f"Code has syntax errors: {e}",
                "severity": "medium",
                "line": getattr(e, "lineno", None),
            })

        # 2. Regex-based analysis
        risks.extend(self._regex_analysis(code))

        # 3. Infinite loop detection
        risks.extend(self._loop_analysis(code))

        if not risks:
            return self._safe_result("No dangerous patterns found.")

        top_severity = self._top_severity(risks)
        return {
            "safe": False,
            "risks": risks,
            "severity": top_severity,
            "summary": self._summarize(risks, top_severity),
        }

    def _ast_analysis(self, tree: ast.AST) -> List[Dict]:
        risks = []
        for node in ast.walk(tree):
            # Import checks
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name.split(".")[0] for alias in node.names]
                elif node.module:
                    names = [node.module.split(".")[0]]

                for name in names:
                    if name in _DANGEROUS_IMPORTS:
                        desc, severity = _DANGEROUS_IMPORTS[name]
                        risks.append({
                            "type": "dangerous_import",
                            "description": f"Import of {desc}",
                            "module": name,
                            "severity": severity,
                            "line": getattr(node, "lineno", None),
                        })

            # Attribute access checks
            if isinstance(node, ast.Attribute):
                if node.attr.startswith("__") and node.attr.endswith("__"):
                    if node.attr in ("__class__", "__bases__", "__mro__", "__subclasses__"):
                        risks.append({
                            "type": "dunder_access",
                            "description": f"Access to {node.attr} (class introspection)",
                            "severity": "high",
                            "line": getattr(node, "lineno", None),
                        })

        return risks

    def _regex_analysis(self, code: str) -> List[Dict]:
        risks = []
        lines = code.splitlines()
        for line_num, line in enumerate(lines, 1):
            for pattern, desc, severity in _DANGEROUS_CALLS:
                if re.search(pattern, line):
                    risks.append({
                        "type": "dangerous_call",
                        "description": desc,
                        "severity": severity,
                        "line": line_num,
                        "snippet": line.strip()[:80],
                    })
        return risks

    def _loop_analysis(self, code: str) -> List[Dict]:
        risks = []
        for pattern, desc in _INFINITE_LOOP_PATTERNS:
            if re.search(pattern, code):
                # Check if there's a break statement somewhere
                if "break" not in code and "return" not in code:
                    risks.append({
                        "type": "infinite_loop",
                        "description": f"Possible infinite loop: {desc} (no break/return found)",
                        "severity": "high",
                        "line": None,
                    })
        return risks

    @staticmethod
    def _top_severity(risks: List[Dict]) -> str:
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "safe": 0}
        return max((r.get("severity", "low") for r in risks), key=lambda s: order.get(s, 0))

    @staticmethod
    def _summarize(risks: List[Dict], top_severity: str) -> str:
        count = len(risks)
        types = list(set(r["type"] for r in risks))
        return (
            f"Found {count} risk(s) with severity '{top_severity}'. "
            f"Categories: {', '.join(types)}."
        )

    @staticmethod
    def _safe_result(msg: str) -> Dict[str, Any]:
        return {"safe": True, "risks": [], "severity": "safe", "summary": msg}
