from dotenv import load_dotenv
load_dotenv()

import os
import re
import json
import ast
import hashlib
import uuid
import asyncio
import requests
from datetime import datetime
from typing import List, Dict, Any, Set, Tuple, Optional
from io import BytesIO
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, validator
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.lib import colors

import google.generativeai as genai


# ============================================================================
# API KEYS
# ============================================================================

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel("gemini-1.5-flash")
else:
    gemini_model = None

OPENROUTER_ENABLED = bool(OPENROUTER_API_KEY)

# ============================================================================
# APP SETUP
# ============================================================================

app = FastAPI(
    title="CRONOS – Advanced Intelligence Code Analyzer",
    version="7.0.0",
    description="Enterprise-grade Python static analysis: SonarQube + AI Semantic Reasoning + Execution Prediction"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "*",
        "https://cronoscodeanalyzer.vercel.app",
        "http://localhost:3000",
        "http://localhost:5500",
        "http://127.0.0.1:5500"
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
    max_age=3600
)

# ============================================================================
# STORAGE
# ============================================================================

REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

# In-memory store for instant report retrieval (report_id → result dict)
REPORT_STORE: Dict[str, Any] = {}

# Hash cache: semantic_hash → full analysis result
# Avoids re-analysing identical AST structure
HASH_CACHE: Dict[str, Any] = {}

# Thread pool for running sync analyzers inside async endpoints
_EXECUTOR = ThreadPoolExecutor(max_workers=4)

# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class Constraint(BaseModel):
    no_behavior_change: bool = Field(default=False)
    allow_boundary_change: bool = Field(default=False)

class AnalyzerResult(BaseModel):
    name: str
    findings: List[str]
    risk: int = Field(..., ge=0, le=100)
    details: Dict[str, Any] = Field(default_factory=dict)

class AnalyzeRequest(BaseModel):
    mode: str = Field(...)
    old_code: str = Field(default="")
    new_code: str = Field(default="")
    old_condition: str = Field(default="")
    new_condition: str = Field(default="")
    source_code: str = Field(default="")
    expected_output: str = Field(default="")
    constraints: Constraint = Field(default_factory=Constraint)
    technical_depth: str = Field(default="balanced", pattern="^(academic|balanced|simple)$")
    enable_deep_analysis: bool = Field(default=False)

    @validator('mode')
    def validate_mode(cls, v):
        if v.upper() not in ['CHANGE', 'COMPLIANCE']:
            raise ValueError("mode must be CHANGE or COMPLIANCE")
        return v.upper()

    def get_old_code(self) -> str:
        return self.old_code or self.old_condition

    def get_new_code(self) -> str:
        return self.new_code or self.new_condition

class CIAnalyzeRequest(BaseModel):
    old_code: str = Field(default="")
    new_code: str = Field(...)
    mode: str = Field(default="STRICT")

    @validator('mode')
    def validate_mode(cls, v):
        if v.upper() not in ['STRICT', 'BOUNDARY', 'CONTRACT']:
            return 'STRICT'
        return v.upper()

class FullAnalyzeRequest(BaseModel):
    old_code: str = Field(default="")
    new_code: str = Field(...)
    mode: str = Field(default="STRICT")

    @validator('mode')
    def validate_mode(cls, v):
        if v.upper() not in ['STRICT', 'BOUNDARY', 'CONTRACT']:
            return 'STRICT'
        return v.upper()

# ---------------------------------------------------------------------------
# Hash utility — three hashes used throughout v7
# ---------------------------------------------------------------------------

def compute_hashes(old_code: str, new_code: str) -> Dict[str, str]:
    """
    Generate:
      old_hash     = SHA256(old_code)
      new_hash     = SHA256(new_code)
      semantic_hash = SHA256(AST-dump of new_code)  — structure-only, ignores whitespace/comments
    """
    old_hash = hashlib.sha256(old_code.encode('utf-8')).hexdigest() if old_code.strip() else ""
    new_hash = hashlib.sha256(new_code.encode('utf-8')).hexdigest()

    try:
        tree = ast.parse(new_code)
        ast_repr = ast.dump(tree, indent=None)
        semantic_hash = hashlib.sha256(ast_repr.encode('utf-8')).hexdigest()
    except Exception:
        semantic_hash = new_hash  # fallback: same as content hash

    return {
        "old_hash": old_hash,
        "new_hash": new_hash,
        "semantic_hash": semantic_hash,
    }

# ============================================================================
# AST UTILITIES
# ============================================================================

def safe_ast(code: str) -> ast.AST:
    if not code or not code.strip():
        raise ValueError("Empty code provided")
    try:
        return ast.parse(code)
    except SyntaxError as e:
        raise ValueError(f"Syntax Error at line {e.lineno}: {e.msg}")
    except Exception as e:
        raise ValueError(f"AST Parse Error: {str(e)}")

def hash_source(code: str) -> str:
    return hashlib.sha256(code.encode('utf-8')).hexdigest()

def extract_identifiers(tree: ast.AST) -> Set[str]:
    identifiers = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            identifiers.add(node.id)
    return identifiers

def extract_function_names(tree: ast.AST) -> Set[str]:
    functions = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            functions.add(node.name)
    return functions

def extract_call_graph(tree: ast.AST) -> Dict[str, List[str]]:
    call_graph = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            current_function = node.name
            call_graph[current_function] = []
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    if isinstance(child.func, ast.Name):
                        call_graph[current_function].append(child.func.id)
                    elif isinstance(child.func, ast.Attribute):
                        call_graph[current_function].append(child.func.attr)
    return call_graph

def compute_control_flow_signature(tree: ast.AST) -> Dict[str, int]:
    signature = {'if': 0, 'for': 0, 'while': 0, 'try': 0, 'with': 0,
                 'return': 0, 'break': 0, 'continue': 0, 'raise': 0}
    for node in ast.walk(tree):
        if isinstance(node, ast.If): signature['if'] += 1
        elif isinstance(node, ast.For): signature['for'] += 1
        elif isinstance(node, ast.While): signature['while'] += 1
        elif isinstance(node, ast.Try): signature['try'] += 1
        elif isinstance(node, ast.With): signature['with'] += 1
        elif isinstance(node, ast.Return): signature['return'] += 1
        elif isinstance(node, ast.Break): signature['break'] += 1
        elif isinstance(node, ast.Continue): signature['continue'] += 1
        elif isinstance(node, ast.Raise): signature['raise'] += 1
    return signature

# ============================================================================
# RISK NORMALIZATION
# ============================================================================

def normalize_risk(raw_risk: int) -> int:
    if raw_risk <= 0: return 0
    elif raw_risk <= 20: return 20
    elif raw_risk <= 40: return 40
    elif raw_risk <= 60: return 60
    elif raw_risk <= 80: return 80
    else: return 100

def pass_fail_from_risk(risk: int) -> str:
    if risk <= 20: return "PASS"
    elif risk <= 50: return "WARN"
    else: return "FAIL"

def get_status(risk: int) -> str:
    return pass_fail_from_risk(risk)

# ============================================================================
# LAYER 2 — CODE QUALITY ANALYZER
# ============================================================================

class CodeQualityAnalyzer:
    """
    Detects code quality issues:
    - Unused variables, dead code, unreachable code
    - Excessive nesting, function complexity
    - Long functions (>50 lines), duplicate logic
    """

    def analyze(self, code: str) -> Tuple[int, List[Dict]]:
        issues = []
        try:
            tree = safe_ast(code)
        except ValueError as e:
            return 0, [{"type": "ParseError", "message": str(e), "severity": "high"}]

        # Unused variables
        issues.extend(self._detect_unused_variables(tree))

        # Excessive nesting
        issues.extend(self._detect_excessive_nesting(tree))

        # Function complexity & length
        issues.extend(self._detect_complex_functions(tree, lines))

        # Unreachable code (after return/raise)
        issues.extend(self._detect_unreachable_code(tree))

        # Duplicate logic patterns
        issues.extend(self._detect_duplicate_logic(tree))

        # Calculate quality score (100 = perfect, deduct per issue)
        deductions = {
            "critical": 15,
            "high": 10,
            "medium": 5,
            "low": 2
        }
        total_deduction = sum(deductions.get(i.get("severity", "low"), 2) for i in issues)
        quality_score = max(0, 100 - total_deduction)

        return quality_score, issues

    def _detect_unused_variables(self, tree: ast.AST) -> List[Dict]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                assigned = set()
                used = set()
                for child in ast.walk(node):
                    if isinstance(child, ast.Assign):
                        for t in child.targets:
                            if isinstance(t, ast.Name):
                                assigned.add(t.id)
                    elif isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                        used.add(child.id)
                unused = assigned - used - {'_'}
                for var in list(unused)[:3]:
                    issues.append({
                        "type": "UnusedVariable",
                        "message": f"Variable '{var}' in function '{node.name}' is assigned but never used",
                        "severity": "low",
                        "function": node.name
                    })
        return issues

    def _detect_excessive_nesting(self, tree: ast.AST) -> List[Dict]:
        issues = []

        def get_depth(node, current=0):
            max_d = current
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
                    max_d = max(max_d, get_depth(child, current + 1))
                else:
                    max_d = max(max_d, get_depth(child, current))
            return max_d

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                depth = get_depth(node)
                if depth > 4:
                    issues.append({
                        "type": "ExcessiveNesting",
                        "message": f"Function '{node.name}' has nesting depth of {depth} (max recommended: 4)",
                        "severity": "medium",
                        "function": node.name,
                        "depth": depth
                    })
        return issues

    def _detect_complex_functions(self, tree: ast.AST, lines: List[str]) -> List[Dict]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Cyclomatic complexity
                complexity = 1
                for child in ast.walk(node):
                    if isinstance(child, (ast.If, ast.For, ast.While, ast.ExceptHandler,
                                          ast.With, ast.Assert, ast.comprehension)):
                        complexity += 1
                    elif isinstance(child, ast.BoolOp):
                        complexity += len(child.values) - 1

                if complexity > 10:
                    issues.append({
                        "type": "HighComplexity",
                        "message": f"Function '{node.name}' has cyclomatic complexity of {complexity} (max: 10)",
                        "severity": "high",
                        "function": node.name,
                        "complexity": complexity
                    })

                # Long function
                start = node.lineno
                end = node.end_lineno if hasattr(node, 'end_lineno') else start
                length = end - start + 1
                if length > 50:
                    issues.append({
                        "type": "LongFunction",
                        "message": f"Function '{node.name}' is {length} lines long (max recommended: 50)",
                        "severity": "medium",
                        "function": node.name,
                        "lines": length
                    })
        return issues

    def _detect_unreachable_code(self, tree: ast.AST) -> List[Dict]:
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                body = node.body
                for i, stmt in enumerate(body[:-1]):
                    if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                        issues.append({
                            "type": "UnreachableCode",
                            "message": f"Unreachable code detected after '{type(stmt).__name__}' in function '{node.name}' at statement {i+1}",
                            "severity": "medium",
                            "function": node.name
                        })
                        break
        return issues

    def _detect_duplicate_logic(self, tree: ast.AST) -> List[Dict]:
        issues = []
        condition_map = defaultdict(list)
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                try:
                    cond_str = ast.unparse(node.test)
                    condition_map[cond_str].append(node.lineno if hasattr(node, 'lineno') else 0)
                except Exception:
                    pass

        for cond, lines in condition_map.items():
            if len(lines) > 1:
                issues.append({
                    "type": "DuplicateLogic",
                    "message": f"Condition '{cond[:60]}' appears {len(lines)} times — consider extracting to a function",
                    "severity": "low",
                    "lines": lines
                })
        return issues


# ============================================================================
# LAYER 3 — SECURITY ANALYZER
# ============================================================================

class SecurityAnalyzer:
    """
    Detects security vulnerabilities:
    - eval/exec usage, pickle.loads, subprocess without validation
    - Hardcoded passwords/keys, weak hashing, insecure random
    """

    DANGEROUS_CALLS = {
        'eval': ('critical', 'eval() executes arbitrary code — remote code execution risk'),
        'exec': ('critical', 'exec() executes arbitrary code — remote code execution risk'),
        'compile': ('high', 'compile() can be used to execute arbitrary code'),
        '__import__': ('high', '__import__() allows dynamic module loading'),
    }

    DANGEROUS_ATTRS = {
        'loads': ('pickle', 'critical', 'pickle.loads() can execute arbitrary code during deserialization'),
        'load': ('pickle', 'high', 'pickle.load() deserializes untrusted data'),
        'call': ('subprocess', 'high', 'subprocess.call() without shell=False can be exploited'),
        'Popen': ('subprocess', 'high', 'subprocess.Popen() requires input validation'),
        'system': ('os', 'high', 'os.system() executes shell commands — injection risk'),
    }

    WEAK_HASH_FUNCS = {'md5', 'sha1'}
    INSECURE_RANDOM = {'random', 'randint', 'choice', 'shuffle', 'seed'}

    PASSWORD_PATTERNS = [
        re.compile(r'(?:password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*["\'][^"\']{4,}["\']', re.IGNORECASE),
        re.compile(r'(?:password|passwd|pwd|secret)\s*=\s*["\'][^"\']*["\']', re.IGNORECASE),
    ]

    def analyze(self, code: str) -> Tuple[int, List[Dict]]:
        findings = []
        try:
            tree = safe_ast(code)
        except ValueError as e:
            return 100, [{"type": "ParseError", "message": str(e), "severity": "critical"}]

        # AST-based checks
        findings.extend(self._check_dangerous_calls(tree))
        findings.extend(self._check_dangerous_attrs(tree))
        findings.extend(self._check_weak_hashing(tree))
        findings.extend(self._check_insecure_random(tree))
        findings.extend(self._check_subprocess(tree))

        # Source-level checks
        findings.extend(self._check_hardcoded_secrets(code))

        # Compute security score
        severity_weights = {'critical': 30, 'high': 15, 'medium': 8, 'low': 3}
        total_penalty = sum(severity_weights.get(f.get('severity', 'low'), 3) for f in findings)
        security_score = max(0, 100 - total_penalty)

        return security_score, findings

    def _check_dangerous_calls(self, tree: ast.AST) -> List[Dict]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = None
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                if func_name and func_name in self.DANGEROUS_CALLS:
                    sev, msg = self.DANGEROUS_CALLS[func_name]
                    findings.append({
                        "type": "DangerousFunction",
                        "message": msg,
                        "function": func_name,
                        "severity": sev,
                        "cwe": "CWE-78" if func_name in ('eval', 'exec') else "CWE-94"
                    })
        return findings

    def _check_dangerous_attrs(self, tree: ast.AST) -> List[Dict]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                attr = node.func.attr
                if attr in self.DANGEROUS_ATTRS:
                    lib, sev, msg = self.DANGEROUS_ATTRS[attr]
                    findings.append({
                        "type": "DangerousMethod",
                        "message": msg,
                        "method": attr,
                        "severity": sev,
                        "cwe": "CWE-502" if lib == 'pickle' else "CWE-78"
                    })
        return findings

    def _check_weak_hashing(self, tree: ast.AST) -> List[Dict]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_str = ""
                if isinstance(node.func, ast.Attribute):
                    func_str = node.func.attr.lower()
                elif isinstance(node.func, ast.Name):
                    func_str = node.func.id.lower()
                if func_str in self.WEAK_HASH_FUNCS:
                    findings.append({
                        "type": "WeakHashing",
                        "message": f"Weak hash algorithm '{func_str.upper()}' detected — use SHA-256 or bcrypt for passwords",
                        "algorithm": func_str,
                        "severity": "high",
                        "cwe": "CWE-327"
                    })
        return findings

    def _check_insecure_random(self, tree: ast.AST) -> List[Dict]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                elif isinstance(node.func, ast.Name):
                    func_name = node.func.id
                if func_name in self.INSECURE_RANDOM:
                    # Check if it's from the random module (not secrets)
                    if isinstance(node.func, ast.Attribute):
                        if isinstance(node.func.value, ast.Name) and node.func.value.id == 'secrets':
                            continue
                    findings.append({
                        "type": "InsecureRandom",
                        "message": f"random.{func_name}() is not cryptographically secure — use secrets module for security-sensitive operations",
                        "function": func_name,
                        "severity": "medium",
                        "cwe": "CWE-338"
                    })
                    break  # Report once per code block
        return findings

    def _check_subprocess(self, tree: ast.AST) -> List[Dict]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                is_subprocess = False
                if isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == 'subprocess':
                        is_subprocess = True
                    elif node.func.attr in ('call', 'run', 'Popen', 'check_output'):
                        is_subprocess = True

                if is_subprocess:
                    # Check for shell=True
                    for kw in node.keywords:
                        if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            findings.append({
                                "type": "SubprocessShellTrue",
                                "message": "subprocess called with shell=True — command injection risk. Use shell=False with list arguments",
                                "severity": "critical",
                                "cwe": "CWE-78"
                            })
        return findings

    def _check_hardcoded_secrets(self, code: str) -> List[Dict]:
        findings = []
        for pattern in self.PASSWORD_PATTERNS:
            matches = pattern.findall(code)
            for match in matches[:2]:  # Limit to 2 findings
                findings.append({
                    "type": "HardcodedSecret",
                    "message": f"Potential hardcoded credential detected: '{match[:50]}...' — use environment variables",
                    "severity": "critical",
                    "cwe": "CWE-798"
                })
        return findings


# ============================================================================
# LAYER 4 — EXECUTION OUTCOME PREDICTOR
# ============================================================================

class ExecutionPredictor:
    """
    Simulates execution WITHOUT running code.
    Analyzes AST to predict possible outputs, return values,
    control flow branches, authentication logic outcomes.
    """

    def predict(self, code: str) -> Dict[str, Any]:
        try:
            tree = safe_ast(code)
        except ValueError as e:
            return {
                "possible_outputs": ["Parse error — prediction unavailable"],
                "return_values": [],
                "print_outputs": [],
                "branches": [],
                "state_changes": [],
                "exceptions": [],
                "auth_outcomes": [],
                "confidence": 0.0,
                "execution_paths": 1,
                "error": str(e)
            }

        possible_outputs = []
        return_values = []
        branches = []
        print_outputs = []
        auth_outcomes = []
        state_changes = []
        exceptions = []

        # Walk AST and extract predictions
        self._extract_returns(tree, return_values)
        self._extract_prints(tree, print_outputs)
        self._extract_branches(tree, branches)
        self._extract_auth_logic(tree, auth_outcomes)
        self._extract_state_changes(tree, state_changes)
        self._extract_exceptions(tree, exceptions)

        possible_outputs.extend(return_values[:5])
        possible_outputs.extend(print_outputs[:3])
        possible_outputs.extend(auth_outcomes[:3])

        if not possible_outputs:
            possible_outputs = ["No explicit outputs detected (side-effects only)"]

        # Confidence based on how much we could analyze
        total_nodes = sum(1 for _ in ast.walk(tree))
        analyzable = len(return_values) + len(print_outputs) + len(branches)
        confidence = min(0.95, 0.5 + (analyzable / max(total_nodes, 1)) * 0.5)
        confidence = round(confidence, 2)

        return {
            "possible_outputs": list(dict.fromkeys(possible_outputs)),
            "return_values": return_values[:8],
            "print_outputs": print_outputs[:5],
            "branches": branches[:8],
            "state_changes": state_changes[:6],
            "exceptions": exceptions[:5],
            "auth_outcomes": auth_outcomes,
            "confidence": confidence,
            "execution_paths": len(branches) + 1
        }

    def _extract_returns(self, tree: ast.AST, results: List):
        for node in ast.walk(tree):
            if isinstance(node, ast.Return) and node.value is not None:
                try:
                    val = ast.unparse(node.value)
                    # Simplify string literals
                    if isinstance(node.value, ast.Constant):
                        results.append(f'→ returns: {repr(node.value.value)}')
                    elif isinstance(node.value, ast.Name):
                        results.append(f'→ returns variable: {node.value.id}')
                    elif isinstance(node.value, ast.Dict):
                        results.append('→ returns: dict object')
                    elif isinstance(node.value, ast.List):
                        results.append('→ returns: list object')
                    else:
                        results.append(f'→ returns: {val[:60]}')
                except Exception:
                    pass

    def _extract_prints(self, tree: ast.AST, results: List):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = None
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                if func_name == 'print' and node.args:
                    try:
                        arg = node.args[0]
                        if isinstance(arg, ast.Constant):
                            results.append(f'prints: {repr(arg.value)[:60]}')
                        elif isinstance(arg, ast.JoinedStr):
                            results.append('prints: f-string (dynamic content)')
                        else:
                            results.append(f'prints: {ast.unparse(arg)[:60]}')
                    except Exception:
                        pass

    def _extract_branches(self, tree: ast.AST, results: List):
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                try:
                    cond = ast.unparse(node.test)
                    then_returns = [
                        ast.unparse(n.value) if n.value else "None"
                        for n in ast.walk(ast.Module(body=node.body, type_ignores=[]))
                        if isinstance(n, ast.Return)
                    ]
                    else_returns = []
                    if node.orelse:
                        else_returns = [
                            ast.unparse(n.value) if n.value else "None"
                            for n in ast.walk(ast.Module(body=node.orelse, type_ignores=[]))
                            if isinstance(n, ast.Return)
                        ]

                    branch = {
                        "condition": cond[:80],
                        "true_path": then_returns[:2] if then_returns else ["continues"],
                        "false_path": else_returns[:2] if else_returns else ["continues / falls through"]
                    }
                    results.append(branch)
                except Exception:
                    pass

    def _extract_auth_logic(self, tree: ast.AST, results: List):
        auth_keywords = {'admin', 'role', 'permission', 'authenticated', 'authorized',
                         'login', 'logout', 'token', 'access', 'grant', 'deny', 'banned'}

        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                try:
                    cond = ast.unparse(node.test).lower()
                    if any(kw in cond for kw in auth_keywords):
                        for child in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                            if isinstance(child, ast.Return) and isinstance(child.value, ast.Constant):
                                results.append(f'Auth path (if {cond[:40]}): returns {repr(child.value.value)}')
                        if node.orelse:
                            for child in ast.walk(ast.Module(body=node.orelse, type_ignores=[])):
                                if isinstance(child, ast.Return) and isinstance(child.value, ast.Constant):
                                    results.append(f'Auth fallback: returns {repr(child.value.value)}')
                except Exception:
                    pass

    def _extract_state_changes(self, tree: ast.AST, results: List):
        """Detect assignments that mutate state (counters, flags, lists)."""
        for node in ast.walk(tree):
            # AugAssign: x += 1, x -= 1, attempts += 1
            if isinstance(node, ast.AugAssign):
                try:
                    target = ast.unparse(node.target)
                    op = type(node.op).__name__
                    val = ast.unparse(node.value)
                    results.append(f'State mutation: {target} {op}= {val}')
                except Exception:
                    pass
            # Regular assign with numeric literal (flag/counter reset)
            elif isinstance(node, ast.Assign):
                try:
                    for t in node.targets:
                        if isinstance(t, ast.Name) and isinstance(node.value, ast.Constant):
                            v = node.value.value
                            if isinstance(v, (int, float, bool)):
                                results.append(f'State set: {t.id} = {v}')
                except Exception:
                    pass

    def _extract_exceptions(self, tree: ast.AST, results: List):
        """Detect raise statements and risky patterns."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Raise):
                try:
                    if node.exc is not None:
                        results.append(f'Raises: {ast.unparse(node.exc)[:60]}')
                    else:
                        results.append('Re-raises current exception')
                except Exception:
                    pass
            # Detect division — potential ZeroDivisionError
            elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)):
                try:
                    if isinstance(node.right, ast.Constant) and node.right.value == 0:
                        results.append('Risk: division by zero constant detected')
                    else:
                        results.append(f'Potential ZeroDivisionError: {ast.unparse(node)[:50]}')
                except Exception:
                    pass


# ============================================================================
# LAYER 4b — BEHAVIOR SIMULATOR
# ============================================================================

class BehaviorSimulator:
    """
    Compares old_code vs new_code behavior at semantic level.
    Detects behavioral changes without executing code.
    """

    def compare(self, old_code: str, new_code: str) -> Dict[str, Any]:
        if not old_code.strip():
            return {
                "changed": False,
                "summary": "No old code provided — baseline comparison unavailable",
                "changes": [],
                "behavior_score": 100
            }

        try:
            old_tree = safe_ast(old_code)
            new_tree = safe_ast(new_code)
        except ValueError as e:
            return {
                "changed": True,
                "summary": f"Parse error during comparison: {str(e)}",
                "changes": [],
                "behavior_score": 50
            }

        changes = []
        behavior_score = 100

        # Compare return values
        old_returns = self._get_return_values(old_tree)
        new_returns = self._get_return_values(new_tree)
        if old_returns != new_returns:
            added = [r for r in new_returns if r not in old_returns]
            removed = [r for r in old_returns if r not in new_returns]
            if added or removed:
                changes.append({
                    "category": "ReturnValue",
                    "description": f"Return values changed — removed: {removed[:3]}, added: {added[:3]}",
                    "impact": "high"
                })
                behavior_score -= 20

        # Compare assignments (key variable values)
        old_assigns = self._get_key_assignments(old_tree)
        new_assigns = self._get_key_assignments(new_tree)
        for var in set(old_assigns) & set(new_assigns):
            if old_assigns[var] != new_assigns[var]:
                changes.append({
                    "category": "VariableValue",
                    "description": f"Variable '{var}' value changed: {old_assigns[var]} → {new_assigns[var]} — may alter runtime behavior",
                    "impact": "medium"
                })
                behavior_score -= 10

        # Compare conditions
        old_conds = self._get_conditions(old_tree)
        new_conds = self._get_conditions(new_tree)
        added_conds = [c for c in new_conds if c not in old_conds]
        removed_conds = [c for c in old_conds if c not in new_conds]
        if added_conds or removed_conds:
            changes.append({
                "category": "ControlFlow",
                "description": f"Conditions changed — may alter execution paths",
                "removed": removed_conds[:3],
                "added": added_conds[:3],
                "impact": "high"
            })
            behavior_score -= 15

        # Compare function signatures
        old_sigs = self._get_function_signatures(old_tree)
        new_sigs = self._get_function_signatures(new_tree)
        for func in set(old_sigs) & set(new_sigs):
            if old_sigs[func] != new_sigs[func]:
                changes.append({
                    "category": "FunctionSignature",
                    "description": f"Function '{func}' signature changed: {old_sigs[func]} → {new_sigs[func]}",
                    "impact": "high"
                })
                behavior_score -= 20

        behavior_changed = len(changes) > 0
        behavior_score = max(0, behavior_score)

        if changes:
            summary_parts = [c['description'] for c in changes[:3]]
            summary = "; ".join(summary_parts)
        else:
            summary = "No behavioral changes detected — functionally equivalent code"

        return {
            "changed": behavior_changed,
            "summary": summary,
            "changes": changes,
            "behavior_score": behavior_score
        }

    def _get_return_values(self, tree: ast.AST) -> List[str]:
        results = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Return):
                try:
                    results.append(ast.unparse(node.value) if node.value else "None")
                except Exception:
                    pass
        return results

    def _get_key_assignments(self, tree: ast.AST) -> Dict[str, str]:
        assigns = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        try:
                            assigns[target.id] = ast.unparse(node.value)
                        except Exception:
                            pass
        return assigns

    def _get_conditions(self, tree: ast.AST) -> List[str]:
        conds = []
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                try:
                    conds.append(ast.unparse(node.test))
                except Exception:
                    pass
        return conds

    def _get_function_signatures(self, tree: ast.AST) -> Dict[str, str]:
        sigs = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                try:
                    args = [arg.arg for arg in node.args.args]
                    sigs[node.name] = str(args)
                except Exception:
                    pass
        return sigs


# ============================================================================
# LAYER 1 — CHANGE ANALYZER (unchanged from v5)
# ============================================================================

class ChangeAnalyzer:
    def analyze(self, old: str, new: str, constraints: Optional[Constraint] = None) -> Tuple[List[AnalyzerResult], int, Dict[str, Any]]:
        if constraints is None:
            constraints = Constraint()

        if not old.strip() or not new.strip():
            return [], 0, {"error": "Empty code provided"}

        try:
            old_ast = safe_ast(old)
            new_ast = safe_ast(new)
        except ValueError as e:
            return [AnalyzerResult(name="ParseError", findings=[str(e)], risk=20, details={"error": str(e)})], 20, {"parse_error": True}

        old_hash = hash_source(old)
        new_hash = hash_source(new)

        if old_hash == new_hash:
            return [], 0, {"semantic_diff": False, "old_hash": old_hash, "new_hash": new_hash, "ast_changed": False, "conclusion": "No changes detected"}

        old_ast_dump = ast.dump(old_ast)
        new_ast_dump = ast.dump(new_ast)
        ast_changed = old_ast_dump != new_ast_dump

        old_nodes = self._extract_node_types(old_ast)
        new_nodes = self._extract_node_types(new_ast)

        findings: List[AnalyzerResult] = []
        risk_scores: List[int] = []
        change_details: Dict[str, Any] = {}

        operator_risk, operator_findings, operator_details = self._analyze_operators(old, new, old_nodes, new_nodes)
        if operator_risk > 0:
            findings.extend(operator_findings); risk_scores.append(operator_risk); change_details.update(operator_details)

        function_risk, function_findings, function_details = self._analyze_functions(old_nodes, new_nodes)
        if function_risk > 0:
            findings.extend(function_findings); risk_scores.append(function_risk); change_details.update(function_details)

        loop_risk, loop_findings, loop_details = self._analyze_loops(old_nodes, new_nodes)
        if loop_risk > 0:
            findings.extend(loop_findings); risk_scores.append(loop_risk); change_details.update(loop_details)

        import_risk, import_findings, import_details = self._analyze_imports(old_nodes, new_nodes)
        if import_risk > 0:
            findings.extend(import_findings); risk_scores.append(import_risk); change_details.update(import_details)

        datatype_risk, datatype_findings, datatype_details = self._analyze_datatypes(old_nodes, new_nodes)
        if datatype_risk > 0:
            findings.extend(datatype_findings); risk_scores.append(datatype_risk); change_details.update(datatype_details)

        control_risk, control_findings, control_details = self._analyze_control_flow(old_nodes, new_nodes)
        if control_risk > 0:
            findings.extend(control_findings); risk_scores.append(control_risk); change_details.update(control_details)

        scope_risk, scope_findings, scope_details = self._analyze_variable_scope(old_nodes, new_nodes)
        if scope_risk > 0:
            findings.extend(scope_findings); risk_scores.append(scope_risk); change_details.update(scope_details)

        if ast_changed and not risk_scores:
            structural_risk, structural_findings, structural_details = self._analyze_structural(old_ast, new_ast, old_nodes, new_nodes)
            if structural_risk > 0:
                findings.extend(structural_findings); risk_scores.append(structural_risk); change_details.update(structural_details)

        final_risk = max(risk_scores) if risk_scores else 0
        original_risk = final_risk

        if constraints.no_behavior_change:
            if ast_changed and final_risk > 0:
                if final_risk < 60:
                    final_risk = 60
                    findings.append(AnalyzerResult(
                        name="ConstraintViolation",
                        findings=[f"STRICT MODE VIOLATION: no_behavior_change=True but semantic changes detected (original risk: {original_risk}, enforced: {final_risk})"],
                        risk=60,
                        details={"constraint": "no_behavior_change", "violated": True, "original_risk": original_risk, "enforced_risk": final_risk}
                    ))

        if constraints.allow_boundary_change and change_details.get('boundary_changes'):
            if not constraints.no_behavior_change or final_risk == original_risk:
                if final_risk == 10:
                    final_risk = 5

        signals = {
            "semantic_diff": ast_changed, "old_hash": old_hash, "new_hash": new_hash,
            "ast_changed": ast_changed, "old_code": old, "new_code": new,
            "categories_analyzed": len([r for r in risk_scores if r > 0]),
            "total_findings": len(findings),
            "risk_breakdown": {
                "operator": operator_risk, "function": function_risk, "loop": loop_risk,
                "import": import_risk, "datatype": datatype_risk, "control_flow": control_risk, "scope": scope_risk
            },
            **change_details
        }

        return findings, final_risk, signals

    def _extract_node_types(self, tree: ast.AST) -> Dict[str, Any]:
        nodes = {
            'compare_ops': [], 'bool_ops': [], 'functions': [], 'calls': [],
            'loops': [], 'returns': [], 'constants': [], 'names': [], 'imports': [],
            'attributes': [], 'assignments': [], 'if_nodes': [], 'try_nodes': [],
            'breaks': 0, 'continues': 0, 'global_vars': [], 'nonlocal_vars': []
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Compare):
                for op in node.ops: nodes['compare_ops'].append(type(op).__name__)
            elif isinstance(node, ast.BoolOp):
                nodes['bool_ops'].append(type(node.op).__name__)
            elif isinstance(node, ast.FunctionDef):
                nodes['functions'].append({'name': node.name, 'args': [arg.arg for arg in node.args.args],
                    'defaults': len(node.args.defaults), 'returns': ast.unparse(node.returns) if node.returns else None,
                    'decorators': [ast.unparse(d) for d in node.decorator_list]})
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name): nodes['calls'].append(node.func.id)
                elif isinstance(node.func, ast.Attribute): nodes['calls'].append(node.func.attr)
            elif isinstance(node, ast.For):
                li = {'type': 'For'}
                if hasattr(node, 'target'): li['target'] = ast.unparse(node.target)
                if hasattr(node, 'iter'): li['iter'] = ast.unparse(node.iter)
                nodes['loops'].append(li)
            elif isinstance(node, ast.While):
                li = {'type': 'While'}
                if hasattr(node, 'test'): li['test'] = ast.unparse(node.test)
                nodes['loops'].append(li)
            elif isinstance(node, ast.Return):
                nodes['returns'].append(ast.unparse(node.value) if node.value else "None")
            elif isinstance(node, ast.Constant):
                nodes['constants'].append({'type': type(node.value).__name__, 'value': str(node.value)[:50]})
            elif isinstance(node, ast.Name): nodes['names'].append(node.id)
            elif isinstance(node, ast.Import):
                for alias in node.names: nodes['imports'].append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                nodes['imports'].append(node.module if node.module else 'relative_import')
            elif isinstance(node, ast.Attribute): nodes['attributes'].append(node.attr)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name): nodes['assignments'].append(target.id)
            elif isinstance(node, ast.If):
                if hasattr(node, 'test'): nodes['if_nodes'].append(ast.unparse(node.test))
            elif isinstance(node, ast.Try): nodes['try_nodes'].append('try_except')
            elif isinstance(node, ast.Break): nodes['breaks'] += 1
            elif isinstance(node, ast.Continue): nodes['continues'] += 1
            elif isinstance(node, ast.Global): nodes['global_vars'].extend(node.names)
            elif isinstance(node, ast.Nonlocal): nodes['nonlocal_vars'].extend(node.names)
        return nodes

    def _analyze_operators(self, old_code, new_code, old_nodes, new_nodes):
        findings = []; risk = 0; details = {}
        old_compare = old_nodes['compare_ops']; new_compare = new_nodes['compare_ops']
        old_bool = old_nodes['bool_ops']; new_bool = new_nodes['bool_ops']
        boundary_changes = []
        if ('Gt' in old_compare and 'GtE' in new_compare) or ('GtE' in old_compare and 'Gt' in new_compare):
            boundary_changes.append('> ↔ >='); risk = max(risk, 10)
        if ('Lt' in old_compare and 'LtE' in new_compare) or ('LtE' in old_compare and 'Lt' in new_compare):
            boundary_changes.append('< ↔ <='); risk = max(risk, 10)
        if boundary_changes:
            findings.append(AnalyzerResult(name="ConditionShift", findings=[f"Boundary operator adjustment: {', '.join(boundary_changes)}"], risk=10, details={'change_type': 'boundary_adjustment', 'changes': boundary_changes}))
            details['boundary_changes'] = boundary_changes
        equality_changes = []
        if 'Eq' in old_compare and 'NotEq' in new_compare: equality_changes.append('== → !='); risk = max(risk, 80)
        if 'NotEq' in old_compare and 'Eq' in new_compare: equality_changes.append('!= → =='); risk = max(risk, 80)
        if equality_changes:
            findings.append(AnalyzerResult(name="ConditionShift", findings=[f"Equality operator inversion: {', '.join(equality_changes)}"], risk=80, details={'change_type': 'equality_inversion', 'changes': equality_changes}))
            details['equality_changes'] = equality_changes
        logical_changes = []
        if 'And' in old_bool and 'Or' in new_bool: logical_changes.append('AND → OR'); risk = max(risk, 95)
        if 'Or' in old_bool and 'And' in new_bool: logical_changes.append('OR → AND'); risk = max(risk, 95)
        if logical_changes:
            findings.append(AnalyzerResult(name="ConditionShift", findings=[f"Critical logical operator change: {', '.join(logical_changes)}"], risk=95, details={'change_type': 'logical_inversion', 'changes': logical_changes}))
            details['logical_changes'] = logical_changes
        if set(old_compare) != set(new_compare) and not boundary_changes and not equality_changes:
            old_set = set(old_compare); new_set = set(new_compare)
            removed = old_set - new_set; added = new_set - old_set
            if removed or added:
                risk = max(risk, 45)
                findings.append(AnalyzerResult(name="ConditionShift", findings=["Comparison operator modified"], risk=45, details={'removed': list(removed), 'added': list(added)}))
                details['operator_changes'] = {'removed': list(removed), 'added': list(added)}
        return risk, findings, details

    def _analyze_functions(self, old_nodes, new_nodes):
        findings = []; risk = 0; details = {}
        old_funcs = {f['name']: f for f in old_nodes['functions']}
        new_funcs = {f['name']: f for f in new_nodes['functions']}
        old_calls = set(old_nodes['calls']); new_calls = set(new_nodes['calls'])
        old_names = set(old_funcs.keys()); new_names = set(new_funcs.keys())
        if len(old_funcs) == len(new_funcs) == 1 and old_names != new_names:
            findings.append(AnalyzerResult(name="ConditionShift", findings=[f"Function renamed: {list(old_names)[0]} → {list(new_names)[0]}"], risk=35, details={'change_type': 'function_rename'}))
            details['function_rename'] = True; risk = max(risk, 35)
        else:
            added_funcs = new_names - old_names; removed_funcs = old_names - new_names
            if added_funcs and len(added_funcs) == len(removed_funcs) and len(added_funcs) <= 2:
                findings.append(AnalyzerResult(name="ConditionShift", findings=["Functions renamed or swapped — review call sites"], risk=35, details={'change_type': 'function_swap'}))
                details['function_swap'] = True; risk = max(risk, 35)
            elif added_funcs:
                findings.append(AnalyzerResult(name="ConditionShift", findings=[f"New functions added: {', '.join(list(added_funcs)[:3])}"], risk=30, details={'change_type': 'functions_added'}))
                risk = max(risk, 30)
            if removed_funcs and not details.get('function_swap'):
                findings.append(AnalyzerResult(name="ConditionShift", findings=[f"Functions removed: {', '.join(list(removed_funcs)[:3])}"], risk=70, details={'change_type': 'functions_removed'}))
                risk = max(risk, 70)
        for func_name in old_names.intersection(new_names):
            old_func = old_funcs[func_name]; new_func = new_funcs[func_name]
            if old_func['args'] != new_func['args'] or old_func['defaults'] != new_func['defaults']:
                findings.append(AnalyzerResult(name="ConditionShift", findings=[f"Function '{func_name}' signature changed"], risk=65, details={'change_type': 'function_signature_change'}))
                risk = max(risk, 65)
            if old_func['returns'] != new_func['returns']:
                findings.append(AnalyzerResult(name="ConditionShift", findings=[f"Function '{func_name}' return type changed"], risk=60, details={'change_type': 'return_type_change'}))
                risk = max(risk, 60)
        if old_calls != new_calls:
            added = new_calls - old_calls; removed = old_calls - new_calls
            if added or removed:
                findings.append(AnalyzerResult(name="ConditionShift", findings=[f"Function call patterns changed (removed: {list(removed)[:3]}, added: {list(added)[:3]})"], risk=60, details={'change_type': 'call_pattern_change', 'added_calls': list(added)[:5], 'removed_calls': list(removed)[:5]}))
                details['call_changes'] = {'added': list(added), 'removed': list(removed)}
                risk = max(risk, 60)
        return risk, findings, details

    def _analyze_loops(self, old_nodes, new_nodes):
        findings = []; risk = 0; details = {}
        old_loops = old_nodes['loops']; new_loops = new_nodes['loops']
        old_types = [l['type'] for l in old_loops]; new_types = [l['type'] for l in new_loops]
        old_breaks = old_nodes.get('breaks', 0); new_breaks = new_nodes.get('breaks', 0)
        old_continues = old_nodes.get('continues', 0); new_continues = new_nodes.get('continues', 0)
        if len(old_loops) != len(new_loops):
            findings.append(AnalyzerResult(name="ConditionShift", findings=[f"Loop count changed: {len(old_loops)} → {len(new_loops)}"], risk=40, details={'change_type': 'loop_count_change'}))
            details['loop_count_change'] = True; risk = max(risk, 40)
        if 'For' in old_types and 'While' in new_types and 'For' not in new_types:
            findings.append(AnalyzerResult(name="ConditionShift", findings=["Loop type changed: FOR → WHILE"], risk=70, details={'change_type': 'loop_type_for_to_while'}))
            risk = max(risk, 70)
        if 'While' in old_types and 'For' in new_types and 'While' not in new_types:
            findings.append(AnalyzerResult(name="ConditionShift", findings=["Loop type changed: WHILE → FOR"], risk=70, details={'change_type': 'loop_type_while_to_for'}))
            risk = max(risk, 70)
        for i, (old_loop, new_loop) in enumerate(zip(old_loops, new_loops)):
            if old_loop['type'] == new_loop['type']:
                if old_loop['type'] == 'For' and old_loop.get('iter') != new_loop.get('iter'):
                    findings.append(AnalyzerResult(name="ConditionShift", findings=["FOR loop range modified"], risk=45, details={}))
                    risk = max(risk, 45)
                if old_loop['type'] == 'While' and old_loop.get('test') != new_loop.get('test'):
                    findings.append(AnalyzerResult(name="ConditionShift", findings=["WHILE loop condition modified"], risk=50, details={}))
                    risk = max(risk, 50)
        if old_breaks != new_breaks or old_continues != new_continues:
            findings.append(AnalyzerResult(name="ConditionShift", findings=[f"Loop control statements changed: break({old_breaks}→{new_breaks}), continue({old_continues}→{new_continues})"], risk=40, details={}))
            risk = max(risk, 40)
        return risk, findings, details

    def _analyze_imports(self, old_nodes, new_nodes):
        findings = []; risk = 0; details = {}
        old_imports = set(old_nodes['imports']); new_imports = set(new_nodes['imports'])
        added = new_imports - old_imports; removed = old_imports - new_imports
        if added:
            findings.append(AnalyzerResult(name="ConditionShift", findings=[f"New dependencies added: {', '.join(list(added)[:3])}"], risk=25, details={'imports_added': list(added)}))
            details['imports_added'] = list(added); risk = max(risk, 25)
        if removed:
            findings.append(AnalyzerResult(name="ConditionShift", findings=[f"Dependencies removed: {', '.join(list(removed)[:3])}"], risk=55, details={'imports_removed': list(removed)}))
            details['imports_removed'] = list(removed); risk = max(risk, 55)
        return risk, findings, details

    def _analyze_datatypes(self, old_nodes, new_nodes):
        findings = []; risk = 0; details = {}
        old_type_set = {c['type'] for c in old_nodes['constants']}
        new_type_set = {c['type'] for c in new_nodes['constants']}
        type_changes = []
        if 'int' in old_type_set and 'float' in new_type_set: type_changes.append('int → float')
        if 'float' in old_type_set and 'int' in new_type_set: type_changes.append('float → int (precision loss)')
        if type_changes:
            findings.append(AnalyzerResult(name="ConditionShift", findings=[f"Data type changes: {', '.join(type_changes)}"], risk=50, details={'datatype_changes': type_changes}))
            details['datatype_changes'] = type_changes; risk = max(risk, 50)
        old_returns = [r for r in old_nodes['returns'] if r and r != "None"]
        new_returns = [r for r in new_nodes['returns'] if r and r != "None"]
        if set(old_returns) != set(new_returns):
            findings.append(AnalyzerResult(name="ConditionShift", findings=["Return values changed"], risk=55, details={}))
            details['return_changes'] = True; risk = max(risk, 55)
        return risk, findings, details

    def _analyze_control_flow(self, old_nodes, new_nodes):
        findings = []; risk = 0; details = {}
        old_ifs = len(old_nodes['if_nodes']); new_ifs = len(new_nodes['if_nodes'])
        old_trys = len(old_nodes['try_nodes']); new_trys = len(new_nodes['try_nodes'])
        if old_ifs != new_ifs:
            findings.append(AnalyzerResult(name="ConditionShift", findings=[f"Conditional branches changed: {old_ifs} → {new_ifs} if statements"], risk=40, details={}))
            details['if_change'] = True; risk = max(risk, 40)
        if old_trys != new_trys:
            findings.append(AnalyzerResult(name="ConditionShift", findings=[f"Exception handling changed: {old_trys} → {new_trys} try blocks"], risk=35, details={}))
            details['try_change'] = True; risk = max(risk, 35)
        return risk, findings, details

    def _analyze_variable_scope(self, old_nodes, new_nodes):
        findings = []; risk = 0; details = {}
        old_globals = set(old_nodes.get('global_vars', [])); new_globals = set(new_nodes.get('global_vars', []))
        if old_globals != new_globals:
            added_globals = new_globals - old_globals; removed_globals = old_globals - new_globals
            if added_globals or removed_globals:
                findings.append(AnalyzerResult(name="ConditionShift", findings=[f"Global variable scope changed — added: {list(added_globals) or 'none'}, removed: {list(removed_globals) or 'none'}"], risk=50, details={}))
                details['global_scope_change'] = True; risk = max(risk, 50)
        old_nonlocals = set(old_nodes.get('nonlocal_vars', [])); new_nonlocals = set(new_nodes.get('nonlocal_vars', []))
        if old_nonlocals != new_nonlocals:
            findings.append(AnalyzerResult(name="ConditionShift", findings=["Nonlocal variable scope changed"], risk=45, details={}))
            details['nonlocal_scope_change'] = True; risk = max(risk, 45)
        return risk, findings, details

    def _analyze_structural(self, old_ast, new_ast, old_nodes, new_nodes):
        findings = []; risk = 0; details = {}
        old_names = set(old_nodes['names']); new_names = set(new_nodes['names'])
        if old_names != new_names:
            if abs(len(old_names) - len(new_names)) <= 2:
                findings.append(AnalyzerResult(name="ConditionShift", findings=["Variable names changed — likely cosmetic refactoring"], risk=5, details={'change_type': 'variable_rename'}))
                details['variable_rename'] = True; risk = max(risk, 5)
            else:
                findings.append(AnalyzerResult(name="ConditionShift", findings=["Significant variable structure changes"], risk=40, details={'change_type': 'variable_structure_change'}))
                details['variable_structure_change'] = True; risk = max(risk, 40)
        old_assigns = set(old_nodes['assignments']); new_assigns = set(new_nodes['assignments'])
        if old_assigns != new_assigns and not details.get('variable_rename'):
            findings.append(AnalyzerResult(name="ConditionShift", findings=["Assignment patterns changed"], risk=30, details={}))
            details['assignment_change'] = True; risk = max(risk, 30)
        if risk == 0 and ast.dump(old_ast) != ast.dump(new_ast):
            findings.append(AnalyzerResult(name="ConditionShift", findings=["Minor structural changes — likely cosmetic"], risk=5, details={'change_type': 'cosmetic_change'}))
            details['cosmetic_change'] = True; risk = 5
        return risk, findings, details


# ============================================================================
# COMPLIANCE ANALYZER (unchanged from v5)
# ============================================================================

class ComplianceAnalyzer:
    def analyze(self, code: str, expected: str) -> Tuple[List[AnalyzerResult], int, Dict[str, Any]]:
        try:
            tree = safe_ast(code)
        except ValueError as e:
            return [AnalyzerResult(name="ParseError", findings=[str(e)], risk=20, details={"error": str(e)})], 20, {"parse_error": True}

        src_hash = hash_source(code)
        if not expected.strip():
            return [], 0, {"semantic_similarity": 1.0, "invariant_broken": False, "source_hash": src_hash, "comparison_method": "no_contract_specified"}

        identifiers = extract_identifiers(tree)
        function_names = extract_function_names(tree)
        call_graph = extract_call_graph(tree)
        control_flow_sig = compute_control_flow_signature(tree)
        constants = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant):
                constants.add(str(node.value).lower())

        expected_lower = expected.lower()
        expected_words = set(expected_lower.split())
        identifier_match = identifiers.intersection(expected_words)
        function_match = function_names.intersection(expected_words)
        constant_match = constants.intersection(expected_words)
        MIN_SIMILARITY_FLOOR = 0.2
        all_matches = identifier_match.union(function_match).union(constant_match)
        weighted_score = len(function_match) * 3.0 + len(identifier_match) * 1.0 + len(constant_match) * 0.5
        max_possible_score = len(expected_words) * 3.0
        similarity = min(weighted_score / max_possible_score, 1.0) if max_possible_score > 0 else 0.0
        if len(expected_words) <= 3 and len(all_matches) == 0:
            similarity = max(similarity, MIN_SIMILARITY_FLOOR)

        if similarity >= 0.7: risk = 0
        elif similarity >= 0.5: risk = 20
        elif similarity >= 0.3: risk = 40
        elif similarity >= 0.1: risk = 60
        else: risk = 80

        findings = []
        if risk > 0:
            findings.append(AnalyzerResult(name="ContractViolation", findings=[f"Expected behavior alignment: {similarity*100:.1f}% — code may not fully implement specification"], risk=risk, details={"similarity_score": round(similarity, 3)}))

        return findings, risk, {
            "semantic_similarity": similarity, "invariant_broken": risk > 50, "source_hash": src_hash,
            "comparison_method": "ast_structural_weighted_match",
            "identifiers_in_code": sorted(list(identifiers))[:15],
            "functions_in_code": sorted(list(function_names)),
            "control_flow_signature": control_flow_sig,
            "similarity_percentage": round(similarity * 100, 2)
        }


# ============================================================================
# UNIFIED INTELLIGENCE SCORE
# ============================================================================

def compute_overall_score(risk_score: int, quality_score: int, security_score: int, behavior_score: int) -> int:
    """
    Weighted combination of all four scores.
    risk_score: inverted (100 - risk) = safety score
    """
    safety = max(0, 100 - risk_score)
    overall = int(
        safety * 0.30 +
        quality_score * 0.25 +
        security_score * 0.30 +
        behavior_score * 0.15
    )
    return max(0, min(100, overall))


# ============================================================================
# AI CALLS
# ============================================================================

def call_gemini(prompt: str) -> Tuple[str, str]:
    if not gemini_model:
        raise Exception("Gemini not configured")
    try:
        r = gemini_model.generate_content(prompt)
        return r.text.strip(), "Gemini"
    except Exception as e:
        raise Exception(f"Gemini API Error: {str(e)}")

def call_openrouter(prompt: str) -> Tuple[str, str]:
    try:
        r = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENROUTER_API_KEY}", "Content-Type": "application/json"},
            json={"model": "mistralai/mistral-7b-instruct", "messages": [{"role": "user", "content": prompt}], "temperature": 0.2, "max_tokens": 700},
            timeout=30
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"], "OpenRouter"
    except Exception as e:
        raise Exception(f"OpenRouter API Error: {str(e)}")

def ai(prompt: str) -> Tuple[str, str]:
    if gemini_model:
        try:
            return call_gemini(prompt)
        except Exception as e:
            print(f"⚠️ Gemini failed: {e}")
    if OPENROUTER_ENABLED:
        try:
            return call_openrouter(prompt)
        except Exception as e:
            print(f"⚠️ OpenRouter failed: {e}")
    return ("AI analysis unavailable. Please check API keys.", "None")


# ============================================================================
# AI PROMPTS
# ============================================================================

def technical_prompt(mode: str, signals: Dict, findings: List, risk: int, depth: str = "balanced") -> str:
    if depth == "academic":
        return f"""You are a senior static analysis engineer presenting to academic peers.
Context: Mode={mode}, Risk={risk}
Findings: {json.dumps([f.dict() if hasattr(f, 'dict') else f for f in findings], indent=2)}
Explain using formal terminology: AST parsing, semantic analysis, CFG, DFA, invariants.
Keep response under 150 words."""
    elif depth == "simple":
        return f"""You are a code reviewer explaining to a developer.
Mode={mode}, Risk={risk}, Changes detected: {len(findings)}
Explain what changed, what could go wrong, why it matters.
Keep under 100 words. Be direct."""
    else:
        return f"""You are a senior static analysis engineer.
Context: Mode={mode}, Risk={risk}
Findings: {json.dumps([f.dict() if hasattr(f, 'dict') else f for f in findings], indent=2)}
Explain what technically caused the issue, which assumption was violated, why risk score is justified.
Keep under 120 words."""

def human_prompt(findings: List, risk: int) -> str:
    return f"""You are explaining to a non-technical stakeholder.
Findings: {len(findings)} issues detected, Risk Score: {risk}/100
Explain what can go wrong, why it matters, what level of attention is needed.
Keep under 100 words."""

def comprehensive_analysis_prompt(old_code: str, new_code: str) -> str:
    return f"""You are an expert Python static analysis engine.
OLD CODE:
{old_code}
NEW CODE:
{new_code}
Perform comprehensive comparison. Analyze: operators, control flow, functions, imports, data types, variables, AST structure.
For each change: category, old vs new, risk (LOW/MEDIUM/HIGH), impact.
Return overall risk score 0-100 with justification. Keep under 300 words."""

def compliance_solution_prompt(hash_code: str, expected: str, risk: int) -> str:
    return f"""You are a software architect. Code Hash: {hash_code}, Expected: {expected}, Risk: {risk}
What should be verified, tested, and changed? Keep high-level and actionable. Under 120 words."""

def semantic_explanation_prompt(old_code: str, new_code: str, findings: List, risk: int,
                                quality_score: int, security_score: int,
                                hashes: Optional[Dict] = None,
                                execution_prediction: Optional[Dict] = None) -> str:
    """
    v7 enriched prompt — passes all structured context so AI can give
    technical_explanation, human_explanation, risk_reasoning, behavioral_impact.
    AI must NOT influence risk score.
    """
    hash_block = ""
    if hashes:
        hash_block = f"""
Code Integrity Hashes:
  old_hash      : {hashes.get('old_hash', 'N/A')[:24]}...
  new_hash      : {hashes.get('new_hash', 'N/A')[:24]}...
  semantic_hash : {hashes.get('semantic_hash', 'N/A')[:24]}...
"""

    pred_block = ""
    if execution_prediction and execution_prediction.get("possible_outputs"):
        outs = execution_prediction.get("possible_outputs", [])[:5]
        exc  = execution_prediction.get("exceptions", [])[:3]
        conf = execution_prediction.get("confidence", 0)
        pred_block = f"""
Execution Prediction (AST-simulated, confidence {conf}):
  Possible outputs : {outs}
  Exception risks  : {exc}
"""

    return f"""You are CRONOS v7 — an enterprise static analysis intelligence engine.
Your role is EXPLANATION ONLY. You must NOT change or influence any numeric score.

STRUCTURED CONTEXT:
══════════════════════════════════════════════
Risk Score    : {risk}/100
Quality Score : {quality_score}/100
Security Score: {security_score}/100
Findings Count: {len(findings)}
{hash_block}{pred_block}
OLD CODE:
{old_code[:600]}

NEW CODE:
{new_code[:600]}
══════════════════════════════════════════════

Respond with EXACTLY this JSON structure (no markdown, no extra keys):
{{
  "technical_explanation": "2-3 sentences using AST/semantic analysis terminology",
  "human_explanation": "2-3 sentences for a non-technical stakeholder, no jargon",
  "risk_reasoning": "1-2 sentences justifying the risk score",
  "behavioral_impact": "1-2 sentences on runtime/user-facing impact"
}}"""


def parse_ai_explanation(raw: str) -> Dict[str, str]:
    """
    Parse the structured JSON the AI is asked to return.
    Falls back to putting the whole response in technical_explanation.
    """
    try:
        # Strip markdown fences if present
        clean = raw.strip()
        if clean.startswith("```"):
            clean = "\n".join(clean.split("\n")[1:])
        if clean.endswith("```"):
            clean = "\n".join(clean.split("\n")[:-1])
        parsed = json.loads(clean.strip())
        return {
            "technical_explanation": str(parsed.get("technical_explanation", "")),
            "human_explanation":     str(parsed.get("human_explanation", "")),
            "risk_reasoning":        str(parsed.get("risk_reasoning", "")),
            "behavioral_impact":     str(parsed.get("behavioral_impact", "")),
        }
    except Exception:
        return {
            "technical_explanation": raw[:500],
            "human_explanation":     "Analysis completed. Please review technical findings.",
            "risk_reasoning":        "",
            "behavioral_impact":     "",
        }




def run_full_analysis(old_code: str, new_code: str, mode: str = "STRICT") -> Dict[str, Any]:
    """
    Runs all 5 intelligence layers and merges results into unified report.
    """
    report_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat() + "Z"

    # Build constraints
    if mode == "STRICT":
        constraints = Constraint(no_behavior_change=True, allow_boundary_change=False)
    elif mode == "BOUNDARY":
        constraints = Constraint(no_behavior_change=False, allow_boundary_change=True)
    else:
        constraints = Constraint(no_behavior_change=False, allow_boundary_change=False)

    # LAYER 1 — Risk Analysis
    if old_code.strip():
        change_analyzer = ChangeAnalyzer()
        risk_findings, raw_risk, risk_signals = change_analyzer.analyze(old_code, new_code, constraints)
    else:
        compliance_analyzer = ComplianceAnalyzer()
        risk_findings, raw_risk, risk_signals = compliance_analyzer.analyze(new_code, "")

    risk_score = normalize_risk(raw_risk)
    status = get_status(risk_score)
    risk_summary = [f.findings[0] for f in risk_findings[:5]] if risk_findings else ["No risk issues detected"]

    # LAYER 2 — Code Quality
    quality_analyzer = CodeQualityAnalyzer()
    quality_score, quality_issues = quality_analyzer.analyze(new_code)

    # LAYER 3 — Security
    security_analyzer = SecurityAnalyzer()
    security_score, security_findings = security_analyzer.analyze(new_code)

    # LAYER 4 — Execution Prediction
    predictor = ExecutionPredictor()
    execution_prediction = predictor.predict(new_code)

    # LAYER 4b — Behavior Simulation
    simulator = BehaviorSimulator()
    behavior = simulator.compare(old_code, new_code)
    behavior_score = behavior.get("behavior_score", 100)

    # LAYER 5 — Unified Score
    overall_score = compute_overall_score(raw_risk, quality_score, security_score, behavior_score)

    # AI Semantic Explanation
    try:
        semantic_explanation, ai_provider = ai(semantic_explanation_prompt(
            old_code, new_code, risk_findings, risk_score, quality_score, security_score
        ))
    except Exception:
        semantic_explanation = "AI explanation unavailable."
        ai_provider = "None"

    return {
        # Core (backward-compatible)
        "risk": risk_score,
        "status": status,
        "mode": mode,

        # New scores
        "quality_score": quality_score,
        "security_score": security_score,
        "overall_score": overall_score,
        "behavior_score": behavior_score,

        # Execution prediction
        "execution_prediction": {
            "possible_outputs": execution_prediction.get("possible_outputs", []),
            "return_values": execution_prediction.get("return_values", []),
            "branches": execution_prediction.get("branches", []),
            "confidence": execution_prediction.get("confidence", 0.0),
            "execution_paths": execution_prediction.get("execution_paths", 1)
        },

        # Behavior simulation
        "behavior": {
            "changed": behavior.get("changed", False),
            "summary": behavior.get("summary", ""),
            "changes": behavior.get("changes", [])
        },

        # Findings
        "summary": risk_summary,
        "risk_findings": [f.dict() for f in risk_findings],
        "quality_findings": quality_issues,
        "security_findings": security_findings,

        # AI explanation
        "semantic_explanation": semantic_explanation,
        "ai_provider": ai_provider,

        # Metadata
        "metadata": risk_signals,
        "report_id": report_id,
        "timestamp": timestamp
    }


# ============================================================================
# PDF GENERATION
# ============================================================================

def generate_professional_pdf(data: Dict) -> BytesIO:
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    y = height - 0.5*inch

    c.setFont("Helvetica-Bold", 20)
    c.drawString(0.5*inch, y, "CRONOS Intelligence Analysis Report")
    y -= 0.3*inch
    c.setFont("Helvetica", 10)
    c.drawString(0.5*inch, y, f"Generated: {data.get('timestamp', 'N/A')}")
    y -= 0.4*inch

    c.setFont("Helvetica-Bold", 14)
    c.drawString(0.5*inch, y, "Analysis Summary")
    y -= 0.25*inch
    c.setFont("Helvetica", 11)
    metadata = [
        f"Mode: {data.get('mode', data.get('mode', 'N/A'))}",
        f"Status: {data.get('status', 'N/A')}",
        f"Risk Score: {data.get('risk_score', data.get('risk', 0))}/100",
        f"Quality Score: {data.get('quality_score', 'N/A')}/100",
        f"Security Score: {data.get('security_score', 'N/A')}/100",
        f"Overall Score: {data.get('overall_score', 'N/A')}/100",
        f"Report ID: {data.get('report_id', 'N/A')}"
    ]
    for item in metadata:
        c.drawString(0.75*inch, y, item)
        y -= 0.2*inch

    y -= 0.2*inch
    c.setFont("Helvetica-Bold", 14)
    c.drawString(0.5*inch, y, "Key Findings")
    y -= 0.25*inch
    c.setFont("Helvetica", 10)
    findings = data.get('analyzer_findings', data.get('risk_findings', []))
    if findings:
        for i, finding in enumerate(findings[:8], 1):
            finding_text = finding.get('findings', ['No description'])[0]
            risk_score = finding.get('risk', 0)
            words = finding_text.split()
            lines = []; current_line = []
            for word in words:
                test_line = ' '.join(current_line + [word])
                if c.stringWidth(test_line, "Helvetica", 10) < (width - 1.5*inch):
                    current_line.append(word)
                else:
                    if current_line: lines.append(' '.join(current_line))
                    current_line = [word]
            if current_line: lines.append(' '.join(current_line))
            c.drawString(0.75*inch, y, f"• {lines[0]}")
            y -= 0.18*inch
            for line in lines[1:]:
                c.drawString(0.95*inch, y, line); y -= 0.18*inch
            c.setFont("Helvetica-Oblique", 9)
            c.drawString(0.95*inch, y, f"Risk: {risk_score}/100"); y -= 0.25*inch
            c.setFont("Helvetica", 10)
            if y < 1*inch:
                c.showPage(); y = height - 0.5*inch
    else:
        c.drawString(0.75*inch, y, "• No issues detected"); y -= 0.3*inch

    # Security findings
    sec_findings = data.get('security_findings', [])
    if sec_findings:
        if y < 3*inch: c.showPage(); y = height - 0.5*inch
        y -= 0.2*inch
        c.setFont("Helvetica-Bold", 14)
        c.drawString(0.5*inch, y, "Security Findings")
        y -= 0.25*inch
        c.setFont("Helvetica", 10)
        for sf in sec_findings[:5]:
            msg = sf.get('message', '')[:100]
            sev = sf.get('severity', 'unknown')
            c.drawString(0.75*inch, y, f"• [{sev.upper()}] {msg}")
            y -= 0.2*inch
            if y < 1*inch: c.showPage(); y = height - 0.5*inch

    if y < 3*inch: c.showPage(); y = height - 0.5*inch
    y -= 0.2*inch
    c.setFont("Helvetica-Bold", 14)
    c.drawString(0.5*inch, y, "Technical / Semantic Explanation")
    y -= 0.25*inch
    c.setFont("Helvetica", 9)
    tech = (data.get('semantic_explanation') or data.get('technical_explanation', 'No explanation available'))[:600]
    words = tech.split(); lines = []; current_line = []
    for word in words:
        test_line = ' '.join(current_line + [word])
        if c.stringWidth(test_line, "Helvetica", 9) < (width - 1.5*inch):
            current_line.append(word)
        else:
            if current_line: lines.append(' '.join(current_line))
            current_line = [word]
    if current_line: lines.append(' '.join(current_line))
    for line in lines[:20]:
        c.drawString(0.75*inch, y, line); y -= 0.15*inch
        if y < 0.5*inch: break

    c.setFont("Helvetica-Oblique", 8)
    c.drawString(0.5*inch, 0.5*inch, "CRONOS v6.0.0 - Advanced Intelligence Code Analysis")
    c.drawString(width - 2*inch, 0.5*inch, "Page 1")
    c.save()
    buffer.seek(0)
    return buffer


# ============================================================================
# ENDPOINTS — ORIGINAL (PRESERVED)
# ============================================================================

@app.post("/analyze")
async def analyze(req: AnalyzeRequest):
    """
    Main analysis endpoint. Supports CHANGE and COMPLIANCE modes.
    Now additionally returns quality_score, security_score, overall_score.
    """
    mode = req.mode
    report_id = str(uuid.uuid4())

    try:
        if mode == "CHANGE":
            old_code = req.get_old_code()
            new_code = req.get_new_code()
            if not old_code.strip():
                raise HTTPException(400, "old_code is required for CHANGE mode")
            if not new_code.strip():
                raise HTTPException(400, "new_code is required for CHANGE mode")

            analyzer = ChangeAnalyzer()
            findings, raw_risk, signals = analyzer.analyze(old_code, new_code, req.constraints)
            risk = normalize_risk(raw_risk)
            status = pass_fail_from_risk(risk)

            # New intelligence layers
            quality_score, quality_issues = CodeQualityAnalyzer().analyze(new_code)
            security_score, security_findings = SecurityAnalyzer().analyze(new_code)
            behavior = BehaviorSimulator().compare(old_code, new_code)
            overall_score = compute_overall_score(risk, quality_score, security_score, behavior.get("behavior_score", 100))

            if req.enable_deep_analysis:
                try:
                    tech, provider = ai(comprehensive_analysis_prompt(old_code, new_code))
                except Exception:
                    tech, provider = ai(technical_prompt(mode, signals, findings, risk, req.technical_depth))
            else:
                tech, provider = ai(technical_prompt(mode, signals, findings, risk, req.technical_depth))

            try:
                human, _ = ai(human_prompt(findings, risk))
            except Exception:
                human = "Analysis completed. Please review technical findings."

            result = {
                "mode": "CHANGE",
                "status": status,
                "risk_score": risk,
                "quality_score": quality_score,
                "security_score": security_score,
                "overall_score": overall_score,
                "analyzer_findings": [f.dict() for f in findings],
                "quality_findings": quality_issues,
                "security_findings": security_findings,
                "behavior": {"changed": behavior["changed"], "summary": behavior["summary"]},
                "semantic_signals": signals,
                "technical_explanation": tech,
                "human_explanation": human,
                "ai_provider": provider,
                "technical_depth": req.technical_depth,
                "deep_analysis_enabled": req.enable_deep_analysis,
                "constraints_applied": req.constraints.dict(),
                "report_id": report_id,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }

        elif mode == "COMPLIANCE":
            if not req.source_code.strip():
                raise HTTPException(400, "source_code is required for COMPLIANCE mode")
            analyzer = ComplianceAnalyzer()
            findings, raw_risk, signals = analyzer.analyze(req.source_code, req.expected_output)
            risk = normalize_risk(raw_risk)
            status = pass_fail_from_risk(risk)

            quality_score, quality_issues = CodeQualityAnalyzer().analyze(req.source_code)
            security_score, security_findings = SecurityAnalyzer().analyze(req.source_code)
            overall_score = compute_overall_score(risk, quality_score, security_score, 100)

            try:
                tech, provider = ai(technical_prompt(mode, signals, findings, risk, req.technical_depth))
                solution, _ = ai(compliance_solution_prompt(signals["source_hash"], req.expected_output, risk))
            except Exception:
                tech = "Analysis completed."; solution = "Verify code matches expected behavior."; provider = "None"

            result = {
                "mode": "COMPLIANCE",
                "status": status,
                "risk_score": risk,
                "quality_score": quality_score,
                "security_score": security_score,
                "overall_score": overall_score,
                "analyzer_findings": [f.dict() for f in findings],
                "quality_findings": quality_issues,
                "security_findings": security_findings,
                "semantic_signals": signals,
                "technical_explanation": tech,
                "ai_solution": solution,
                "ai_provider": provider,
                "technical_depth": req.technical_depth,
                "deep_analysis_enabled": req.enable_deep_analysis,
                "report_id": report_id,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        else:
            raise HTTPException(400, f"Invalid mode '{mode}'")

        with open(f"{REPORT_DIR}/{report_id}.json", "w", encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        return result

    except ValueError as e:
        raise HTTPException(400, f"Validation error: {str(e)}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Internal analysis error: {str(e)}")


@app.get("/analyze_ci")
async def analyze_ci_get():
    return JSONResponse(status_code=200, content={
        "status": "OK",
        "message": "POST-only endpoint. Send JSON body with old_code, new_code, mode.",
        "example": {"old_code": "x > 10", "new_code": "x >= 10", "mode": "STRICT"}
    })


@app.post("/analyze_ci")
async def analyze_ci(request: Request):
    """CI/CD optimized endpoint. Now includes quality_score, security_score, overall_score."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={
            "status": "FAIL", "risk": 100, "findings_count": 1,
            "summary": ["Invalid or missing JSON body"],
            "pass": False, "warn": False, "fail": True,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })

    old_code = body.get("old_code", "")
    new_code = body.get("new_code", "")
    mode = str(body.get("mode", "STRICT")).upper()

    if not new_code:
        return JSONResponse(status_code=400, content={
            "status": "FAIL", "risk": 100, "findings_count": 1,
            "summary": ["new_code is required"],
            "pass": False, "warn": False, "fail": True,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })

    if mode not in ["STRICT", "BOUNDARY", "CONTRACT"]:
        mode = "STRICT"

    try:
        if mode == "STRICT":
            constraints = Constraint(no_behavior_change=True, allow_boundary_change=False)
        elif mode == "BOUNDARY":
            constraints = Constraint(no_behavior_change=False, allow_boundary_change=True)
        else:
            constraints = Constraint(no_behavior_change=False, allow_boundary_change=False)

        if not old_code.strip():
            analyzer = ComplianceAnalyzer()
            findings, raw_risk, metadata = analyzer.analyze(new_code, "")
        else:
            analyzer = ChangeAnalyzer()
            findings, raw_risk, metadata = analyzer.analyze(old_code, new_code, constraints)

        risk = normalize_risk(raw_risk)
        status = get_status(risk)

        # New: quality and security
        quality_score, _ = CodeQualityAnalyzer().analyze(new_code)
        security_score, _ = SecurityAnalyzer().analyze(new_code)
        behavior = BehaviorSimulator().compare(old_code, new_code)
        overall_score = compute_overall_score(risk, quality_score, security_score, behavior.get("behavior_score", 100))

        summary = [f.findings[0] for f in findings[:5]] if findings else ["No issues detected"]

        response = {
            "risk": risk,
            "status": status,
            "mode": mode,
            "findings_count": len(findings),
            "summary": summary,
            "quality_score": quality_score,
            "security_score": security_score,
            "overall_score": overall_score,
            "behavior_changed": behavior.get("changed", False),
            "behavior_summary": behavior.get("summary", ""),
            "pass": status == "PASS",
            "warn": status == "WARN",
            "fail": status == "FAIL",
            "metadata": metadata,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        return JSONResponse(content=response, status_code=200)

    except Exception as e:
        return JSONResponse(status_code=500, content={
            "status": "FAIL", "risk": 100, "findings_count": 1,
            "summary": [f"Analysis error: {str(e)}"],
            "pass": False, "warn": False, "fail": True,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })


# ============================================================================
# NEW ENDPOINT — /analyze_full
# ============================================================================

@app.post("/analyze_full")
async def analyze_full(req: FullAnalyzeRequest):
    """
    Full intelligence report combining all 5 layers:
    - Layer 1: Static Risk Analysis
    - Layer 2: Code Quality Analysis
    - Layer 3: Security Vulnerability Detection
    - Layer 4: Execution Outcome Prediction + Behavior Simulation
    - Layer 5: AI Semantic Explanation

    Input: { "old_code": "...", "new_code": "...", "mode": "STRICT|BOUNDARY|CONTRACT" }
    """
    try:
        result = run_full_analysis(req.old_code, req.new_code, req.mode)

        # Save report
        report_id = result.get("report_id", str(uuid.uuid4()))
        with open(f"{REPORT_DIR}/{report_id}.json", "w", encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        return result

    except Exception as e:
        raise HTTPException(500, f"Full analysis error: {str(e)}")


# ============================================================================
# REPORT ENDPOINTS
# ============================================================================

@app.get("/report/json/{report_id}")
async def download_json(report_id: str):
    path = f"{REPORT_DIR}/{report_id}.json"
    if not os.path.exists(path):
        raise HTTPException(404, f"Report not found: {report_id}")
    with open(path, encoding='utf-8') as f:
        return JSONResponse(content=json.load(f), headers={"Content-Disposition": f'attachment; filename="cronos_report_{report_id}.json"'})

@app.get("/report/pdf/{report_id}")
async def download_pdf(report_id: str):
    json_path = f"{REPORT_DIR}/{report_id}.json"
    if not os.path.exists(json_path):
        raise HTTPException(404, f"Report not found: {report_id}")
    with open(json_path, encoding='utf-8') as f:
        data = json.load(f)
    buffer = generate_professional_pdf(data)
    return StreamingResponse(buffer, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="cronos_report_{report_id}.pdf"'})


# ============================================================================
# HEALTH CHECK
# ============================================================================

@app.get("/")
async def health():
    return {
        "status": "ok",
        "service": "CRONOS v6.0.0 — Advanced Intelligence Code Analyzer",
        "description": "SonarQube + GitHub Advanced Security + Semantic Execution Predictor",
        "intelligence_layers": {
            "layer_1": "Static Risk Analysis (AST-based change detection)",
            "layer_2": "Code Quality Analysis (complexity, dead code, nesting)",
            "layer_3": "Security Vulnerability Detection (OWASP, CWE)",
            "layer_4": "Execution Outcome Prediction (AST simulation)",
            "layer_5": "AI Semantic Explanation (Gemini/OpenRouter)"
        },
        "features": {
            "gemini": gemini_model is not None,
            "openrouter": OPENROUTER_ENABLED,
            "analyzers": ["ChangeAnalyzer", "ComplianceAnalyzer", "CodeQualityAnalyzer", "SecurityAnalyzer", "ExecutionPredictor", "BehaviorSimulator"],
            "modes": ["STRICT", "BOUNDARY", "CONTRACT"],
            "analysis_levels": ["BASIC (/analyze_ci)", "ADVANCED (/analyze)", "FULL (/analyze_full)"]
        },
        "endpoints": {
            "POST /analyze": "Advanced analysis (CHANGE/COMPLIANCE) + quality + security scores",
            "POST /analyze_ci": "CI/CD fast analysis — all scores included",
            "POST /analyze_full": "Full 5-layer intelligence report",
            "GET /analyze_ci": "Health check / usage info",
            "GET /report/json/{id}": "Download JSON report",
            "GET /report/pdf/{id}": "Download PDF report"
        },
        "score_system": {
            "risk_score": "0-100 (lower = safer)",
            "quality_score": "0-100 (higher = better quality)",
            "security_score": "0-100 (higher = more secure)",
            "behavior_score": "0-100 (higher = less behavioral change)",
            "overall_score": "0-100 (weighted combination of all)"
        }
    }


@app.on_event("startup")
async def startup_event():
    print("=" * 80)
    print("✅ CRONOS v6.0.0 — ADVANCED INTELLIGENCE CODE ANALYZER")
    print("=" * 80)
    print(f"📁 Report directory: {REPORT_DIR}")
    print(f"🤖 Gemini: {'✅ Enabled' if gemini_model else '❌ Disabled'}")
    print(f"🤖 OpenRouter: {'✅ Enabled' if OPENROUTER_ENABLED else '❌ Disabled'}")
    print()
    print("🧠 INTELLIGENCE LAYERS:")
    print("  ✓ Layer 1 — Static Risk Analysis (AST change detection)")
    print("  ✓ Layer 2 — Code Quality Analysis (complexity, dead code)")
    print("  ✓ Layer 3 — Security Vulnerability Detection (CWE/OWASP)")
    print("  ✓ Layer 4 — Execution Outcome Prediction (AST simulation)")
    print("  ✓ Layer 5 — AI Semantic Explanation (Gemini/OpenRouter)")
    print()
    print("🚀 ENDPOINTS:")
    print("  • POST /analyze       — Advanced analysis")
    print("  • POST /analyze_ci    — CI/CD optimized")
    print("  • POST /analyze_full  — Full 5-layer intelligence report")
    print("  • GET  /analyze_ci    — Health check")
    print("  • GET  /report/json/{id} — JSON download")
    print("  • GET  /report/pdf/{id}  — PDF download")
    print()
    print("🎓 READY FOR PRODUCTION — SonarQube + Security + Execution Prediction")
    print("=" * 80)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 10000)))
