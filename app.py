from dotenv import load_dotenv
load_dotenv()

import os
import re
import json
import ast
import hashlib
import uuid
import asyncio
import sqlite3
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

# ============================================================================
# API KEYS
# NOTE: google-generativeai SDK intentionally removed.
# Gemini is called via the pure REST API using `requests`.
# ============================================================================

GEMINI_API_KEY     = os.getenv("GEMINI_API_KEY")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_ENABLED = bool(OPENROUTER_API_KEY)

_GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models"
    "/gemini-1.5-flash:generateContent"
)

# ============================================================================
# APP SETUP
# ============================================================================

app = FastAPI(
    title="CRONOS — Enterprise Intelligence Code Analyzer",
    version="8.0.0",
    description="Enterprise-grade: SonarQube + CodeQL + Snyk + Copilot Intelligence"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
    max_age=3600,
)

# ============================================================================
# ZERO CODE RETENTION CONSTANTS
# ============================================================================

REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

REPORT_STORE: Dict[str, Any] = {}
HASH_CACHE:   Dict[str, Any] = {}
_EXECUTOR = ThreadPoolExecutor(max_workers=6)

# ============================================================================
# DATABASE
# ============================================================================

DB_PATH = os.getenv("CRONOS_DB_PATH", "cronos.db")

def _db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def _init_db() -> None:
    with _db_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id             TEXT PRIMARY KEY,
                repo           TEXT NOT NULL DEFAULT '',
                file           TEXT NOT NULL DEFAULT '',
                timestamp      TEXT NOT NULL,
                risk_score     INTEGER NOT NULL DEFAULT 0,
                security_score INTEGER NOT NULL DEFAULT 0,
                overall_score  INTEGER NOT NULL DEFAULT 0,
                severity       TEXT NOT NULL DEFAULT 'SAFE',
                old_hash       TEXT NOT NULL DEFAULT '',
                new_hash       TEXT NOT NULL DEFAULT '',
                semantic_hash  TEXT NOT NULL DEFAULT '',
                mode           TEXT NOT NULL DEFAULT 'STRICT',
                status         TEXT NOT NULL DEFAULT 'PASS'
            )
        """)
        conn.commit()

# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class Constraint(BaseModel):
    no_behavior_change:    bool = Field(default=False)
    allow_boundary_change: bool = Field(default=False)

class AnalyzerResult(BaseModel):
    name:     str
    findings: List[str]
    risk:     int = Field(..., ge=0, le=100)
    details:  Dict[str, Any] = Field(default_factory=dict)

class AnalyzeRequest(BaseModel):
    mode:             str   = Field(...)
    old_code:         str   = Field(default="")
    new_code:         str   = Field(default="")
    old_condition:    str   = Field(default="")
    new_condition:    str   = Field(default="")
    source_code:      str   = Field(default="")
    expected_output:  str   = Field(default="")
    constraints:      Constraint = Field(default_factory=Constraint)
    technical_depth:  str   = Field(default="balanced", pattern="^(academic|balanced|simple)$")
    enable_deep_analysis: bool = Field(default=False)

    @validator('mode')
    def validate_mode(cls, v):
        if v.upper() not in ['CHANGE', 'COMPLIANCE']:
            raise ValueError("mode must be CHANGE or COMPLIANCE")
        return v.upper()

    def get_old_code(self) -> str: return self.old_code or self.old_condition
    def get_new_code(self) -> str: return self.new_code or self.new_condition

class FullAnalyzeRequest(BaseModel):
    old_code: str = Field(default="")
    new_code: str = Field(default="")
    mode:     str = Field(default="STRICT")
    repo:     str = Field(default="")
    file:     str = Field(default="")

    @validator('mode')
    def validate_mode(cls, v):
        allowed = ['STRICT', 'BOUNDARY', 'CONTRACT']
        return v.upper() if v.upper() in allowed else 'STRICT'

class RealtimeAnalyzeRequest(BaseModel):
    code:     str = Field(...)
    filename: str = Field(default="unknown.py")

# ============================================================================
# HASH ENGINE
# ============================================================================

class HashEngine:
    """SHA256 + semantic (AST-structural) hashing."""

    @staticmethod
    def sha256(code: str) -> str:
        return hashlib.sha256(code.encode("utf-8")).hexdigest()

    @staticmethod
    def semantic(code: str) -> str:
        try:
            tree = ast.parse(code)
            return hashlib.sha256(ast.dump(tree, indent=None).encode("utf-8")).hexdigest()
        except Exception:
            return HashEngine.sha256(code)

    @staticmethod
    def compute(old_code: str, new_code: str) -> Dict[str, str]:
        return {
            "old_hash":      HashEngine.sha256(old_code) if old_code.strip() else "",
            "new_hash":      HashEngine.sha256(new_code),
            "semantic_hash": HashEngine.semantic(new_code),
        }

# ============================================================================
# SEVERITY ENGINE
# ============================================================================

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_LOW      = "LOW"
SEVERITY_SAFE     = "SAFE"

class RiskEngine:
    """Risk scoring, severity classification, security scoring."""

    SEVERITY_EMOJI = {
        SEVERITY_CRITICAL: "🔴",
        SEVERITY_HIGH:     "🟠",
        SEVERITY_MEDIUM:   "🟡",
        SEVERITY_LOW:      "🔵",
        SEVERITY_SAFE:     "🟢",
    }

    @staticmethod
    def normalize(raw: int) -> int:
        if raw <= 0:   return 0
        if raw <= 20:  return 20
        if raw <= 40:  return 40
        if raw <= 60:  return 60
        if raw <= 80:  return 80
        return 100

    @staticmethod
    def status(risk: int) -> str:
        if risk <= 20: return "PASS"
        if risk <= 50: return "WARN"
        return "FAIL"

    @staticmethod
    def classify_severity(
        risk_score: int,
        security_score: int,
        behavior_changed: bool,
        execution_prediction: Dict[str, Any],
    ) -> str:
        exceptions     = execution_prediction.get("exceptions", []) if execution_prediction else []
        exception_risk = len(exceptions) > 0

        if risk_score >= 80 or security_score <= 30:
            return SEVERITY_CRITICAL
        if risk_score >= 60 or security_score <= 50 or (behavior_changed and exception_risk):
            return SEVERITY_HIGH
        if risk_score >= 40 or security_score <= 70 or behavior_changed:
            return SEVERITY_MEDIUM
        if risk_score >= 20 or security_score <= 85:
            return SEVERITY_LOW
        return SEVERITY_SAFE

    @staticmethod
    def overall(risk: int, quality: int, security: int, behavior: int) -> int:
        safety = max(0, 100 - risk)
        return max(0, min(100, int(
            safety   * 0.30 +
            quality  * 0.25 +
            security * 0.30 +
            behavior * 0.15
        )))

# ============================================================================
# AST UTILITIES
# ============================================================================

def _safe_ast(code: str) -> ast.AST:
    if not code or not code.strip():
        raise ValueError("Empty code")
    try:
        return ast.parse(code)
    except SyntaxError as e:
        raise ValueError(f"Syntax Error line {e.lineno}: {e.msg}")
    except Exception as e:
        raise ValueError(f"AST Error: {e}")

def _hash_src(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()

def _identifiers(tree: ast.AST) -> Set[str]:
    return {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}

def _functions(tree: ast.AST) -> Set[str]:
    return {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}

def _call_graph(tree: ast.AST) -> Dict[str, List[str]]:
    g = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            g[node.name] = [
                (c.func.id if isinstance(c.func, ast.Name) else c.func.attr)
                for c in ast.walk(node) if isinstance(c, ast.Call)
                and isinstance(c.func, (ast.Name, ast.Attribute))
            ]
    return g

def _cf_sig(tree: ast.AST) -> Dict[str, int]:
    sig = {k: 0 for k in ('if','for','while','try','with','return','break','continue','raise')}
    for n in ast.walk(tree):
        t = type(n).__name__.lower()
        if t in sig: sig[t] += 1
    return sig

# ============================================================================
# INTELLIGENCE ENGINE
# ============================================================================

class IntelligenceEngine:
    """AST comparison, semantic diff, behavior change detection."""

    def analyze_change(
        self, old: str, new: str, constraints: Optional[Constraint] = None
    ) -> Tuple[List[AnalyzerResult], int, Dict[str, Any]]:
        if constraints is None:
            constraints = Constraint()
        if not old.strip() or not new.strip():
            return [], 0, {"error": "Empty code"}
        try:
            oa = _safe_ast(old); na = _safe_ast(new)
        except ValueError as e:
            return [AnalyzerResult(name="ParseError", findings=[str(e)], risk=20)], 20, {}

        oh = _hash_src(old); nh = _hash_src(new)
        if oh == nh:
            return [], 0, {"semantic_diff": False, "old_hash": oh, "new_hash": nh, "ast_changed": False}

        ast_changed = ast.dump(oa) != ast.dump(na)
        on = self._nodes(oa); nn = self._nodes(na)
        findings: List[AnalyzerResult] = []; risks: List[int] = []; details: Dict = {}

        for fn in (self._ops, self._funcs, self._loops, self._imports, self._types, self._cf, self._scope):
            r, f, d = fn(old, new, on, nn) if fn == self._ops else fn(on, nn)
            if r > 0:
                findings.extend(f); risks.append(r); details.update(d)

        if ast_changed and not risks:
            r, f, d = self._structural(oa, na, on, nn)
            if r > 0:
                findings.extend(f); risks.append(r); details.update(d)

        final = max(risks) if risks else 0
        orig  = final

        if constraints.no_behavior_change and ast_changed and 0 < final < 60:
            final = 60
            findings.append(AnalyzerResult(
                name="ConstraintViolation",
                findings=[f"STRICT: behavior changed (orig={orig}, enforced={final})"],
                risk=60,
            ))
        if constraints.allow_boundary_change and details.get("boundary_changes") and final == 10:
            final = 5

        return findings, final, {
            "semantic_diff": ast_changed, "old_hash": oh, "new_hash": nh,
            "ast_changed": ast_changed,
            "categories_analyzed": len([r for r in risks if r > 0]),
            "total_findings": len(findings),
            "risk_breakdown": {
                "operator": 0, "function": 0, "loop": 0,
                "import": 0, "datatype": 0, "control_flow": 0, "scope": 0,
            },
            **details,
        }

    def analyze_compliance(self, code: str, expected: str) -> Tuple[List[AnalyzerResult], int, Dict[str, Any]]:
        try:
            tree = _safe_ast(code)
        except ValueError as e:
            return [AnalyzerResult(name="ParseError", findings=[str(e)], risk=20)], 20, {}
        src_hash = _hash_src(code)
        if not expected.strip():
            return [], 0, {"semantic_similarity": 1.0, "source_hash": src_hash}
        idf  = _identifiers(tree); fns = _functions(tree)
        consts = {str(n.value).lower() for n in ast.walk(tree) if isinstance(n, ast.Constant)}
        ew   = set(expected.lower().split())
        wscore = len(fns & ew) * 3.0 + len(idf & ew) * 1.0 + len(consts & ew) * 0.5
        sim  = min(wscore / max(len(ew) * 3.0, 1), 1.0)
        risk = (0 if sim >= 0.7 else 20 if sim >= 0.5 else 40 if sim >= 0.3 else 60 if sim >= 0.1 else 80)
        findings = []
        if risk > 0:
            findings.append(AnalyzerResult(
                name="ContractViolation",
                findings=[f"Alignment: {sim*100:.1f}%"],
                risk=risk,
            ))
        return findings, risk, {"semantic_similarity": sim, "source_hash": src_hash}

    def compare_behavior(self, old: str, new: str) -> Dict[str, Any]:
        if not old.strip():
            return {"changed": False, "summary": "No baseline", "changes": [], "behavior_score": 100}
        try:
            oa = _safe_ast(old); na = _safe_ast(new)
        except:
            return {"changed": True, "summary": "Parse error", "changes": [], "behavior_score": 50}
        changes = []; score = 100
        or_ = self._returns(oa); nr_ = self._returns(na)
        if or_ != nr_:
            changes.append({"category": "ReturnValue", "description": "Returns changed", "impact": "high"})
            score -= 20
        oc = self._conds(oa); nc = self._conds(na)
        if set(oc) != set(nc):
            changes.append({"category": "ControlFlow", "description": "Conditions changed", "impact": "high"})
            score -= 15
        os_ = self._sigs(oa); ns_ = self._sigs(na)
        for fn in set(os_) & set(ns_):
            if os_[fn] != ns_[fn]:
                changes.append({"category": "FunctionSignature", "description": f"'{fn}' signature changed", "impact": "high"})
                score -= 20
        return {
            "changed": bool(changes),
            "summary": "; ".join(c["description"] for c in changes[:3]) or "No behavioral changes",
            "changes": changes,
            "behavior_score": max(0, score),
        }

    # ── Node type extraction ──────────────────────────────────────────────────
    def _nodes(self, tree: ast.AST) -> Dict:
        n = {
            'compare_ops': [], 'bool_ops': [], 'functions': [], 'calls': [],
            'loops': [], 'returns': [], 'constants': [], 'names': [], 'imports': [],
            'attributes': [], 'assignments': [], 'if_nodes': [], 'try_nodes': [],
            'breaks': 0, 'continues': 0, 'global_vars': [], 'nonlocal_vars': [],
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Compare):
                for op in node.ops: n['compare_ops'].append(type(op).__name__)
            elif isinstance(node, ast.BoolOp):
                n['bool_ops'].append(type(node.op).__name__)
            elif isinstance(node, ast.FunctionDef):
                n['functions'].append({
                    'name': node.name,
                    'args': [a.arg for a in node.args.args],
                    'defaults': len(node.args.defaults),
                    'returns': ast.unparse(node.returns) if node.returns else None,
                })
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name): n['calls'].append(node.func.id)
                elif isinstance(node.func, ast.Attribute): n['calls'].append(node.func.attr)
            elif isinstance(node, ast.For):
                n['loops'].append({'type': 'For', 'iter': ast.unparse(node.iter) if hasattr(node, 'iter') else ''})
            elif isinstance(node, ast.While):
                n['loops'].append({'type': 'While', 'test': ast.unparse(node.test) if hasattr(node, 'test') else ''})
            elif isinstance(node, ast.Return):
                n['returns'].append(ast.unparse(node.value) if node.value else "None")
            elif isinstance(node, ast.Constant):
                n['constants'].append({'type': type(node.value).__name__, 'value': str(node.value)[:50]})
            elif isinstance(node, ast.Name): n['names'].append(node.id)
            elif isinstance(node, ast.Import):
                for a in node.names: n['imports'].append(a.name)
            elif isinstance(node, ast.ImportFrom):
                n['imports'].append(node.module or 'relative_import')
            elif isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name): n['assignments'].append(t.id)
            elif isinstance(node, ast.If):
                n['if_nodes'].append(ast.unparse(node.test))
            elif isinstance(node, ast.Try): n['try_nodes'].append('try')
            elif isinstance(node, ast.Break): n['breaks'] += 1
            elif isinstance(node, ast.Continue): n['continues'] += 1
            elif isinstance(node, ast.Global): n['global_vars'].extend(node.names)
            elif isinstance(node, ast.Nonlocal): n['nonlocal_vars'].extend(node.names)
        return n

    def _returns(self, tree):
        r = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Return):
                try: r.append(ast.unparse(n.value) if n.value else "None")
                except: pass
        return r

    def _conds(self, tree):
        c = []
        for n in ast.walk(tree):
            if isinstance(n, ast.If):
                try: c.append(ast.unparse(n.test))
                except: pass
        return c

    def _sigs(self, tree):
        s = {}
        for n in ast.walk(tree):
            if isinstance(n, ast.FunctionDef):
                try: s[n.name] = str([a.arg for a in n.args.args])
                except: pass
        return s

    # ── Analyzer sub-routines ────────────────────────────────────────────────
    def _ops(self, old_code, new_code, on, nn):
        f = []; r = 0; d = {}
        oc = on['compare_ops']; nc = nn['compare_ops']
        ob = on['bool_ops'];    nb = nn['bool_ops']
        bc = []
        if ('Gt' in oc and 'GtE' in nc) or ('GtE' in oc and 'Gt' in nc): bc.append('> ↔ >='); r = max(r, 10)
        if ('Lt' in oc and 'LtE' in nc) or ('LtE' in oc and 'Lt' in nc): bc.append('< ↔ <='); r = max(r, 10)
        if bc:
            f.append(AnalyzerResult(name="ConditionShift", findings=[f"Boundary: {', '.join(bc)}"], risk=10))
            d['boundary_changes'] = bc
        if 'Eq' in oc and 'NotEq' in nc: f.append(AnalyzerResult(name="ConditionShift", findings=["== → !="], risk=80)); r = max(r, 80)
        if 'NotEq' in oc and 'Eq' in nc: f.append(AnalyzerResult(name="ConditionShift", findings=["!= → =="], risk=80)); r = max(r, 80)
        if 'And' in ob and 'Or' in nb:   f.append(AnalyzerResult(name="ConditionShift", findings=["AND → OR"], risk=95)); r = max(r, 95)
        if 'Or' in ob and 'And' in nb:   f.append(AnalyzerResult(name="ConditionShift", findings=["OR → AND"], risk=95)); r = max(r, 95)
        return r, f, d

    def _funcs(self, on, nn):
        f = []; r = 0; d = {}
        of = {x['name']: x for x in on['functions']}
        nf = {x['name']: x for x in nn['functions']}
        added = set(nf) - set(of); removed = set(of) - set(nf)
        if removed:
            f.append(AnalyzerResult(name="ConditionShift", findings=[f"Functions removed: {list(removed)[:3]}"], risk=70))
            r = max(r, 70)
        elif added:
            f.append(AnalyzerResult(name="ConditionShift", findings=[f"Functions added: {list(added)[:3]}"], risk=30))
            r = max(r, 30)
        for fn in set(of) & set(nf):
            if of[fn]['args'] != nf[fn]['args']:
                f.append(AnalyzerResult(name="ConditionShift", findings=[f"'{fn}' signature changed"], risk=65)); r = max(r, 65)
        oc = set(on['calls']); nc = set(nn['calls'])
        if oc != nc:
            f.append(AnalyzerResult(name="ConditionShift", findings=["Call patterns changed"], risk=60)); r = max(r, 60)
        return r, f, d

    def _loops(self, on, nn):
        f = []; r = 0; d = {}
        if len(on['loops']) != len(nn['loops']):
            f.append(AnalyzerResult(name="ConditionShift", findings=["Loop count changed"], risk=40)); r = 40
        ot = [l['type'] for l in on['loops']]; nt = [l['type'] for l in nn['loops']]
        if 'For' in ot and 'While' in nt and 'For' not in nt:
            f.append(AnalyzerResult(name="ConditionShift", findings=["FOR→WHILE"], risk=70)); r = 70
        if 'While' in ot and 'For' in nt and 'While' not in nt:
            f.append(AnalyzerResult(name="ConditionShift", findings=["WHILE→FOR"], risk=70)); r = 70
        return r, f, d

    def _imports(self, on, nn):
        f = []; r = 0; d = {}
        oi = set(on['imports']); ni = set(nn['imports'])
        added = ni - oi; removed = oi - ni
        if added:
            f.append(AnalyzerResult(name="ConditionShift", findings=[f"Imports added: {list(added)[:3]}"], risk=25))
            d['imports_added'] = list(added); r = max(r, 25)
        if removed:
            f.append(AnalyzerResult(name="ConditionShift", findings=[f"Imports removed: {list(removed)[:3]}"], risk=55))
            d['imports_removed'] = list(removed); r = max(r, 55)
        return r, f, d

    def _types(self, on, nn):
        f = []; r = 0; d = {}
        ot = {c['type'] for c in on['constants']}; nt = {c['type'] for c in nn['constants']}
        if 'int' in ot and 'float' in nt:
            f.append(AnalyzerResult(name="ConditionShift", findings=["int→float"], risk=50)); r = 50
        if 'float' in ot and 'int' in nt:
            f.append(AnalyzerResult(name="ConditionShift", findings=["float→int (precision loss)"], risk=50)); r = 50
        return r, f, d

    def _cf(self, on, nn):
        f = []; r = 0; d = {}
        if len(on['if_nodes']) != len(nn['if_nodes']):
            f.append(AnalyzerResult(name="ConditionShift", findings=["Branch count changed"], risk=40)); r = 40
        if len(on['try_nodes']) != len(nn['try_nodes']):
            f.append(AnalyzerResult(name="ConditionShift", findings=["Try-block count changed"], risk=35)); r = max(r, 35)
        return r, f, d

    def _scope(self, on, nn):
        f = []; r = 0; d = {}
        if set(on.get('global_vars', [])) != set(nn.get('global_vars', [])):
            f.append(AnalyzerResult(name="ConditionShift", findings=["Global scope changed"], risk=50)); r = 50
        return r, f, d

    def _structural(self, oa, na, on, nn):
        f = []; r = 0; d = {}
        if set(on['names']) != set(nn['names']):
            f.append(AnalyzerResult(name="ConditionShift", findings=["Variable names changed"], risk=5)); r = 5
        elif ast.dump(oa) != ast.dump(na):
            f.append(AnalyzerResult(name="ConditionShift", findings=["Cosmetic changes"], risk=5)); r = 5
        return r, f, d

# ============================================================================
# CODE QUALITY ANALYZER
# ============================================================================

class CodeQualityAnalyzer:
    def analyze(self, code: str) -> Tuple[int, List[Dict]]:
        issues = []
        try:
            tree = _safe_ast(code)
        except ValueError as e:
            return 0, [{"type": "ParseError", "message": str(e), "severity": "high"}]
        issues.extend(self._unused(tree))
        issues.extend(self._nesting(tree))
        issues.extend(self._complexity(tree))
        issues.extend(self._unreachable(tree))
        issues.extend(self._dupes(tree))
        deduct = {"critical": 15, "high": 10, "medium": 5, "low": 2}
        return max(0, 100 - sum(deduct.get(i.get("severity", "low"), 2) for i in issues)), issues

    def _unused(self, tree):
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                assigned = set(); used = set()
                for child in ast.walk(node):
                    if isinstance(child, ast.Assign):
                        for t in child.targets:
                            if isinstance(t, ast.Name): assigned.add(t.id)
                    elif isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                        used.add(child.id)
                for v in list(assigned - used - {'_'})[:3]:
                    issues.append({"type": "UnusedVariable", "message": f"'{v}' unused in '{node.name}'", "severity": "low"})
        return issues

    def _nesting(self, tree):
        issues = []
        def depth(node, cur=0):
            d = cur
            for ch in ast.iter_child_nodes(node):
                if isinstance(ch, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
                    d = max(d, depth(ch, cur + 1))
                else:
                    d = max(d, depth(ch, cur))
            return d
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                d = depth(node)
                if d > 4:
                    issues.append({"type": "ExcessiveNesting", "message": f"'{node.name}' depth={d}", "severity": "medium"})
        return issues

    def _complexity(self, tree):
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                cc = 1
                for ch in ast.walk(node):
                    if isinstance(ch, (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.With, ast.Assert)):
                        cc += 1
                    elif isinstance(ch, ast.BoolOp):
                        cc += len(ch.values) - 1
                if cc > 10:
                    issues.append({"type": "HighComplexity", "message": f"'{node.name}' CC={cc}", "severity": "high"})
                length = (getattr(node, 'end_lineno', node.lineno) - node.lineno + 1)
                if length > 50:
                    issues.append({"type": "LongFunction", "message": f"'{node.name}' {length} lines", "severity": "medium"})
        return issues

    def _unreachable(self, tree):
        issues = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for i, stmt in enumerate(node.body[:-1]):
                    if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                        issues.append({"type": "UnreachableCode", "message": f"Unreachable after {type(stmt).__name__} in '{node.name}'", "severity": "medium"})
                        break
        return issues

    def _dupes(self, tree):
        issues = []; cm = defaultdict(list)
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                try:
                    cond = ast.unparse(node.test)
                    cm[cond].append(getattr(node, 'lineno', 0))
                except: pass
        for cond, lines in cm.items():
            if len(lines) > 1:
                issues.append({"type": "DuplicateLogic", "message": f"'{cond[:60]}' appears {len(lines)}x", "severity": "low"})
        return issues

# ============================================================================
# SECURITY ANALYZER
# ============================================================================

class SecurityAnalyzer:
    DANGEROUS_CALLS = {
        'eval':       ('critical', 'eval() — RCE risk',          'CWE-78'),
        'exec':       ('critical', 'exec() — RCE risk',          'CWE-78'),
        'compile':    ('high',     'compile() — arbitrary code', 'CWE-94'),
        '__import__': ('high',     'Dynamic import',             'CWE-94'),
    }
    DANGEROUS_ATTRS = {
        'loads':  ('critical', 'pickle.loads() — deserialization RCE', 'CWE-502'),
        'load':   ('high',     'pickle.load() — untrusted data',       'CWE-502'),
        'system': ('high',     'os.system() — shell injection',        'CWE-78'),
        'Popen':  ('high',     'subprocess.Popen() — injection risk',  'CWE-78'),
    }
    WEAK_HASH    = {'md5', 'sha1'}
    INSECURE_RNG = {'random', 'randint', 'choice', 'shuffle', 'seed'}
    SECRET_PAT   = [
        re.compile(r'(?:password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*["\'][^"\']{4,}["\']', re.I),
    ]

    def analyze(self, code: str) -> Tuple[int, List[Dict]]:
        findings = []
        try:
            tree = _safe_ast(code)
        except ValueError as e:
            return 100, [{"type": "ParseError", "message": str(e), "severity": "critical"}]
        findings.extend(self._dangerous_calls(tree))
        findings.extend(self._dangerous_attrs(tree))
        findings.extend(self._weak_hash(tree))
        findings.extend(self._insecure_rng(tree))
        findings.extend(self._subprocess(tree))
        findings.extend(self._secrets(code))
        weights = {'critical': 30, 'high': 15, 'medium': 8, 'low': 3}
        return max(0, 100 - sum(weights.get(f.get('severity', 'low'), 3) for f in findings)), findings

    def _dangerous_calls(self, tree):
        f = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
                nm = n.func.id
                if nm in self.DANGEROUS_CALLS:
                    sev, msg, cwe = self.DANGEROUS_CALLS[nm]
                    f.append({"type": "DangerousFunction", "message": msg, "function": nm, "severity": sev, "cwe": cwe})
        return f

    def _dangerous_attrs(self, tree):
        f = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                attr = n.func.attr
                if attr in self.DANGEROUS_ATTRS:
                    sev, msg, cwe = self.DANGEROUS_ATTRS[attr]
                    f.append({"type": "DangerousMethod", "message": msg, "method": attr, "severity": sev, "cwe": cwe})
        return f

    def _weak_hash(self, tree):
        f = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                nm = ""
                if isinstance(n.func, ast.Attribute): nm = n.func.attr.lower()
                elif isinstance(n.func, ast.Name): nm = n.func.id.lower()
                if nm in self.WEAK_HASH:
                    f.append({"type": "WeakHashing", "message": f"{nm.upper()} — use SHA-256/bcrypt", "severity": "high", "cwe": "CWE-327"})
        return f

    def _insecure_rng(self, tree):
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                nm = ""
                if isinstance(n.func, ast.Attribute): nm = n.func.attr
                elif isinstance(n.func, ast.Name): nm = n.func.id
                if nm in self.INSECURE_RNG:
                    if isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and n.func.value.id == 'secrets':
                        continue
                    return [{"type": "InsecureRandom", "message": f"random.{nm}() — use secrets module", "severity": "medium", "cwe": "CWE-338"}]
        return []

    def _subprocess(self, tree):
        f = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                is_sp = False
                if isinstance(n.func, ast.Attribute):
                    if (isinstance(n.func.value, ast.Name) and n.func.value.id == 'subprocess') or n.func.attr in ('call', 'run', 'Popen', 'check_output'):
                        is_sp = True
                if is_sp:
                    for kw in n.keywords:
                        if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            f.append({"type": "SubprocessShellTrue", "message": "shell=True — command injection risk", "severity": "critical", "cwe": "CWE-78"})
        return f

    def _secrets(self, code):
        f = []
        for pat in self.SECRET_PAT:
            for m in pat.findall(code)[:2]:
                f.append({"type": "HardcodedSecret", "message": f"Credential: '{m[:50]}...' — use env vars", "severity": "critical", "cwe": "CWE-798"})
        return f

# ============================================================================
# EXECUTION PREDICTOR
# ============================================================================

class ExecutionPredictor:
    def predict(self, code: str) -> Dict[str, Any]:
        try:
            tree = _safe_ast(code)
        except ValueError as e:
            return {"possible_outputs": ["Parse error"], "return_values": [], "print_outputs": [],
                    "branches": [], "state_changes": [], "exceptions": [], "auth_outcomes": [],
                    "confidence": 0.0, "execution_paths": 1}
        rets = []; prints = []; branches = []; auth = []; states = []; excs = []
        self._rets(tree, rets); self._prints(tree, prints); self._branches(tree, branches)
        self._auth(tree, auth); self._states(tree, states); self._excs(tree, excs)
        outputs = list(dict.fromkeys(rets[:5] + prints[:3] + auth[:3])) or ["No explicit outputs"]
        total = sum(1 for _ in ast.walk(tree))
        conf  = round(min(0.95, 0.5 + (len(rets) + len(prints) + len(branches)) / max(total, 1) * 0.5), 2)
        return {
            "possible_outputs": outputs,
            "return_values": rets[:8],
            "print_outputs": prints[:5],
            "branches": branches[:8],
            "state_changes": states[:6],
            "exceptions": excs[:5],
            "auth_outcomes": auth,
            "confidence": conf,
            "execution_paths": len(branches) + 1,
        }

    def _rets(self, tree, r):
        for n in ast.walk(tree):
            if isinstance(n, ast.Return) and n.value:
                try:
                    if isinstance(n.value, ast.Constant): r.append(f'→ returns: {repr(n.value.value)}')
                    elif isinstance(n.value, ast.Name):   r.append(f'→ returns var: {n.value.id}')
                    elif isinstance(n.value, ast.Dict):   r.append('→ returns: dict')
                    elif isinstance(n.value, ast.List):   r.append('→ returns: list')
                    else: r.append(f'→ returns: {ast.unparse(n.value)[:60]}')
                except: pass

    def _prints(self, tree, r):
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'print' and n.args:
                try:
                    a = n.args[0]
                    if isinstance(a, ast.Constant): r.append(f'prints: {repr(a.value)[:60]}')
                    elif isinstance(a, ast.JoinedStr): r.append('prints: f-string')
                    else: r.append(f'prints: {ast.unparse(a)[:60]}')
                except: pass

    def _branches(self, tree, r):
        for n in ast.walk(tree):
            if isinstance(n, ast.If):
                try:
                    cond = ast.unparse(n.test)
                    tr = [ast.unparse(x.value) if x.value else "None" for x in ast.walk(ast.Module(body=n.body, type_ignores=[])) if isinstance(x, ast.Return)]
                    er = [ast.unparse(x.value) if x.value else "None" for x in ast.walk(ast.Module(body=n.orelse, type_ignores=[])) if isinstance(x, ast.Return)] if n.orelse else []
                    r.append({"condition": cond[:80], "true_path": tr[:2] or ["continues"], "false_path": er[:2] or ["falls through"]})
                except: pass

    def _auth(self, tree, r):
        kw = {'admin','role','permission','authenticated','authorized','login','logout','token','access','grant','deny'}
        for n in ast.walk(tree):
            if isinstance(n, ast.If):
                try:
                    cond = ast.unparse(n.test).lower()
                    if any(k in cond for k in kw):
                        for ch in ast.walk(ast.Module(body=n.body, type_ignores=[])):
                            if isinstance(ch, ast.Return) and isinstance(ch.value, ast.Constant):
                                r.append(f'Auth: if {cond[:40]}: returns {repr(ch.value.value)}')
                except: pass

    def _states(self, tree, r):
        for n in ast.walk(tree):
            if isinstance(n, ast.AugAssign):
                try: r.append(f'State: {ast.unparse(n.target)} {type(n.op).__name__}= {ast.unparse(n.value)}')
                except: pass
            elif isinstance(n, ast.Assign):
                try:
                    for t in n.targets:
                        if isinstance(t, ast.Name) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, (int, float, bool)):
                            r.append(f'State: {t.id} = {n.value.value}')
                except: pass

    def _excs(self, tree, r):
        for n in ast.walk(tree):
            if isinstance(n, ast.Raise):
                try: r.append(f'Raises: {ast.unparse(n.exc)[:60]}' if n.exc else 'Re-raises')
                except: pass
            elif isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Div, ast.FloorDiv, ast.Mod)):
                try:
                    if isinstance(n.right, ast.Constant) and n.right.value == 0:
                        r.append('Risk: division by zero')
                    else:
                        r.append(f'Potential ZeroDivisionError: {ast.unparse(n)[:50]}')
                except: pass

# ============================================================================
# AI EXPLAINER
# ============================================================================

def _call_gemini(prompt: str) -> Tuple[str, str]:
    if not GEMINI_API_KEY:
        raise Exception("GEMINI_API_KEY not set")
    resp = requests.post(
        _GEMINI_URL,
        params={"key": GEMINI_API_KEY},
        headers={"Content-Type": "application/json"},
        json={
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 700}
        },
        timeout=30,
    )
    resp.raise_for_status()
    text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
    return text.strip(), "Gemini"


def _call_openrouter(prompt: str) -> Tuple[str, str]:
    if not OPENROUTER_API_KEY:
        raise Exception("OPENROUTER_API_KEY not set")
    resp = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json"
        },
        json={
            "model": "deepseek/deepseek-chat",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "max_tokens": 700
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"], "OpenRouter"


def _ai(prompt: str) -> Tuple[str, str]:
    """Call AI provider with fallback. Never raises — returns empty string on total failure."""
    if GEMINI_API_KEY:
        try:
            return _call_gemini(prompt)
        except Exception as e:
            print(f"⚠️ Gemini failed: {e}")
    if OPENROUTER_API_KEY:
        try:
            return _call_openrouter(prompt)
        except Exception as e:
            print(f"⚠️ OpenRouter failed: {e}")
    return "", "None"


class AIExplainer:
    """Generates structured AI explanations for code analysis results."""

    def explain(
        self,
        old_code: str,
        new_code: str,
        findings: List[AnalyzerResult],
        risk_score: int,
        quality_score: int,
        security_score: int,
        hashes: Dict[str, str],
        exec_summary: Dict[str, Any],
        mode: str = "STRICT",
    ) -> Dict[str, Any]:
        """
        Generate 4-field AI explanation. Never raises — returns safe defaults on failure.
        """
        findings_text = "; ".join(
            f.findings[0] for f in findings[:5]
        ) if findings else "No specific findings"

        exec_outputs = exec_summary.get("possible_outputs", [])
        exec_exceptions = exec_summary.get("exceptions", [])
        exec_confidence = exec_summary.get("confidence", 0)

        prompt = f"""You are CRONOS, an enterprise code intelligence engine.

Mode: {mode}
Risk Score: {risk_score}/100
Quality Score: {quality_score}/100
Security Score: {security_score}/100
Findings: {findings_text}
Execution Outputs: {exec_outputs[:3]}
Exception Risks: {exec_exceptions[:3]}
Execution Confidence: {exec_confidence}
Old Code Hash: {hashes.get('old_hash', 'N/A')}
New Code Hash: {hashes.get('new_hash', 'N/A')}

Respond ONLY as a JSON object with exactly these 4 keys:
{{
  "technical_explanation": "...",
  "human_explanation": "...",
  "risk_reasoning": "...",
  "behavioral_impact": "..."
}}

Each value must be a single string of 2-4 sentences.
Do not include markdown, code blocks, or extra keys."""

        try:
            raw, provider = _ai(prompt)
            parsed = self._parse_json(raw)
            return {
                "technical_explanation": parsed.get("technical_explanation", self._fallback_tech(risk_score, findings_text, mode)),
                "human_explanation":     parsed.get("human_explanation",     self._fallback_human(risk_score, mode)),
                "risk_reasoning":        parsed.get("risk_reasoning",        self._fallback_reason(risk_score, quality_score, security_score)),
                "behavioral_impact":     parsed.get("behavioral_impact",     self._fallback_impact(findings_text)),
                "ai_provider":           provider,
            }
        except Exception as e:
            print(f"⚠️ AIExplainer.explain failed: {e}")
            return self._safe_defaults(risk_score, quality_score, security_score, findings_text, mode)

    def realtime_explain(
        self,
        code: str,
        security_findings: List[Dict],
        risk_score: int,
        security_score: int,
    ) -> Dict[str, Any]:
        """Lightweight realtime explanation for IDE plugin. Never raises."""
        findings_text = "; ".join(
            f.get("message", "") for f in security_findings[:3]
        ) if security_findings else "No security findings"

        prompt = f"""You are CRONOS realtime code intelligence.

Risk Score: {risk_score}/100
Security Score: {security_score}/100
Security Findings: {findings_text}

Respond ONLY as a JSON object:
{{
  "technical_explanation": "...",
  "human_explanation": "...",
  "risk_reasoning": "...",
  "behavioral_impact": "..."
}}

Each value: 1-2 sentences. No markdown, no extra keys."""

        try:
            raw, provider = _ai(prompt)
            parsed = self._parse_json(raw)
            return {
                "technical_explanation": parsed.get("technical_explanation", self._fallback_tech(risk_score, findings_text, "REALTIME")),
                "human_explanation":     parsed.get("human_explanation",     self._fallback_human(risk_score, "REALTIME")),
                "risk_reasoning":        parsed.get("risk_reasoning",        self._fallback_reason(risk_score, 100, security_score)),
                "behavioral_impact":     parsed.get("behavioral_impact",     self._fallback_impact(findings_text)),
                "ai_provider":           provider,
            }
        except Exception as e:
            print(f"⚠️ AIExplainer.realtime_explain failed: {e}")
            return self._safe_defaults(risk_score, 100, security_score, findings_text, "REALTIME")

    def _parse_json(self, raw: str) -> Dict:
        """Parse AI JSON response robustly — strips markdown fences."""
        if not raw:
            return {}
        text = raw.strip()
        # Strip markdown code fences
        text = re.sub(r'^```(?:json)?\s*', '', text, flags=re.MULTILINE)
        text = re.sub(r'\s*```$', '', text, flags=re.MULTILINE)
        text = text.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Attempt to extract first {...} block
            m = re.search(r'\{.*\}', text, re.DOTALL)
            if m:
                try:
                    return json.loads(m.group(0))
                except:
                    pass
        return {}

    # ── Fallback strings (no AI required) ────────────────────────────────────
    def _fallback_tech(self, risk: int, findings: str, mode: str) -> str:
        return (
            f"[{mode}] CRONOS AST analysis detected risk score {risk}/100. "
            f"Key findings: {findings[:200]}. "
            "Static analysis completed using IntelligenceEngine, SecurityAnalyzer, and CodeQualityAnalyzer."
        )

    def _fallback_human(self, risk: int, mode: str) -> str:
        if risk >= 80:
            return f"[{mode}] This change is HIGH RISK and should not be merged without a full review. Critical issues were detected that may break functionality or introduce security vulnerabilities."
        if risk >= 60:
            return f"[{mode}] This change carries significant risk. Review all findings carefully before merging."
        if risk >= 40:
            return f"[{mode}] This change has moderate risk. Some issues were found that should be addressed."
        if risk >= 20:
            return f"[{mode}] This change is low risk but has minor issues worth reviewing."
        return f"[{mode}] This change appears safe. No significant issues detected."

    def _fallback_reason(self, risk: int, quality: int, security: int) -> str:
        return (
            f"Risk score {risk}/100 derived from: security score {security}/100, "
            f"quality score {quality}/100. "
            "Score computed via weighted combination: safety 30%, security 30%, quality 25%, behavior 15%."
        )

    def _fallback_impact(self, findings: str) -> str:
        if not findings or findings == "No specific findings":
            return "No behavioral changes detected. The code change appears semantically equivalent to the baseline."
        return (
            f"The following changes may affect runtime behavior: {findings[:300]}. "
            "Review execution paths carefully before deploying."
        )

    def _safe_defaults(self, risk: int, quality: int, security: int, findings: str, mode: str) -> Dict:
        return {
            "technical_explanation": self._fallback_tech(risk, findings, mode),
            "human_explanation":     self._fallback_human(risk, mode),
            "risk_reasoning":        self._fallback_reason(risk, quality, security),
            "behavioral_impact":     self._fallback_impact(findings),
            "ai_provider":           "None",
        }

# ============================================================================
# PR COMMENT FORMATTER
# ============================================================================

class PRCommentFormatter:
    """Generates GitHub PR comment markdown and posts it via API."""

    @staticmethod
    def format(analysis: Dict[str, Any]) -> str:
        sev    = analysis.get("severity", "UNKNOWN")
        risk   = analysis.get("risk_score", analysis.get("risk", 0))
        sec    = analysis.get("security_score", "N/A")
        ovr    = analysis.get("overall_score", "N/A")
        qual   = analysis.get("quality_score", "N/A")
        status = analysis.get("status", "UNKNOWN")
        mode   = analysis.get("mode", "N/A")
        beh    = analysis.get("behavior", {})
        beh_c  = beh.get("changed", False)
        beh_s  = beh.get("summary", "")
        ep     = analysis.get("execution_prediction", {})
        outs   = ep.get("possible_outputs", [])[:3]
        excs   = ep.get("exceptions", [])[:3]
        tech   = analysis.get("technical_explanation", "")
        human  = analysis.get("human_explanation", "")
        reason = analysis.get("risk_reasoning", "")
        impact = analysis.get("behavioral_impact", "")
        rid    = analysis.get("report_id", "")

        hashes = (
            f"old: `{analysis.get('old_hash','N/A')[:16]}…`  "
            f"new: `{analysis.get('new_hash','N/A')[:16]}…`  "
            f"semantic: `{analysis.get('semantic_hash','N/A')[:16]}…`"
        )

        emoji    = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "SAFE": "🟢"}.get(sev, "⚪")
        beh_line = "✅ No behavior change" if not beh_c else f"⚠️ **YES** — {beh_s}"
        out_md   = "\n".join(f"- `{o}`" for o in outs) if outs else "_No explicit outputs_"
        exc_md   = "\n".join(f"- ⚠️ `{e}`" for e in excs) if excs else "_None detected_"

        return f"""## {emoji} CRONOS Intelligence Report — {sev}

| Metric | Score |
|---|---|
| Mode | **{mode}** |
| Risk Score | **{risk}/100** |
| Security Score | **{sec}/100** |
| Quality Score | **{qual}/100** |
| Overall Score | **{ovr}/100** |
| Status | **{status}** |
| Severity | **{sev}** |

### 🔑 Hashes
{hashes}

### 🔄 Behavior Change Detection
{beh_line}

### ⚡ Execution Prediction
**Possible Outputs:**
{out_md}

**Exception Risks:**
{exc_md}

### 🧠 Technical Explanation
> {tech[:500] if tech else "_Unavailable_"}

### 💬 Human Explanation
> {human[:500] if human else "_Unavailable_"}

### 📊 Risk Reasoning
> {reason[:400] if reason else "_Unavailable_"}

### 🔁 Behavioral Impact
> {impact[:400] if impact else "_Unavailable_"}

---
*Report ID: `{rid}`* | *Powered by [CRONOS](https://github.com/cythonvijay/cronos-action)*
"""

    @staticmethod
    def post(token: str, owner: str, repo: str, pr_number: int, analysis: Dict) -> Optional[Dict]:
        body    = PRCommentFormatter.format(analysis)
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        }
        url  = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
        try:
            resp = requests.post(url, headers=headers, json={"body": body}, timeout=30)
            if resp.status_code in (200, 201):
                return resp.json()
            print(f"[CRONOS] PR comment failed: {resp.status_code} {resp.text[:200]}")
        except Exception as e:
            print(f"[CRONOS] PR comment exception: {e}")
        return None

# ============================================================================
# GITHUB CHECK RUNS / ANNOTATIONS
# ============================================================================

def _sev_to_level(sev: str) -> str:
    return {"CRITICAL": "failure", "HIGH": "failure", "MEDIUM": "warning", "LOW": "notice", "SAFE": "notice"}.get(sev.upper(), "warning")

def create_check_run(token: str, owner: str, repo: str, sha: str, analysis: Dict, filename: str) -> Optional[Dict]:
    sev        = analysis.get("severity", "UNKNOWN")
    risk       = analysis.get("risk_score", 0)
    status     = analysis.get("status", "PASS")
    conclusion = "success" if status == "PASS" else "failure" if status == "FAIL" else "neutral"
    level      = _sev_to_level(sev)

    annotations = []
    for f in analysis.get("risk_findings", [])[:5]:
        msgs = f.get("findings", [])
        annotations.append({"path": filename, "start_line": 1, "end_line": 1,
                             "annotation_level": level,
                             "message": f"[CRONOS Risk] {msgs[0] if msgs else 'Issue detected'}",
                             "title": f"Risk: {f.get('name', 'Finding')}"})
    for sf in analysis.get("security_findings", [])[:5]:
        sl  = _sev_to_level(sf.get("severity", "medium"))
        cwe = sf.get("cwe", "")
        annotations.append({"path": filename, "start_line": 1, "end_line": 1,
                             "annotation_level": sl,
                             "message": f"[CRONOS Security] {sf.get('message','')[:200]}",
                             "title": f"Security: {sf.get('type','Vuln')}{' ('+cwe+')' if cwe else ''}"})
    for exc in analysis.get("execution_prediction", {}).get("exceptions", [])[:3]:
        annotations.append({"path": filename, "start_line": 1, "end_line": 1,
                             "annotation_level": "warning",
                             "message": f"[CRONOS Execution] {exc}",
                             "title": "Execution Risk"})

    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"}
    payload = {
        "name":       "CRONOS Intelligence",
        "head_sha":   sha,
        "status":     "completed",
        "conclusion": conclusion,
        "output": {
            "title":   f"CRONOS — {sev} | Risk {risk}/100 | {status}",
            "summary": (
                f"**Severity:** {sev}  \n"
                f"**Risk:** {risk}/100  \n"
                f"**Security:** {analysis.get('security_score','N/A')}/100  \n"
                f"**Overall:** {analysis.get('overall_score','N/A')}/100"
            ),
            "text": (
                f"### Technical\n{analysis.get('technical_explanation','N/A')[:800]}\n\n"
                f"### Human\n{analysis.get('human_explanation','N/A')[:800]}\n\n"
                f"### Risk Reasoning\n{analysis.get('risk_reasoning','N/A')[:400]}\n\n"
                f"### Behavioral Impact\n{analysis.get('behavioral_impact','N/A')[:400]}"
            ),
            "annotations": annotations[:50],
        },
    }
    url = f"https://api.github.com/repos/{owner}/{repo}/check-runs"
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        if resp.status_code in (200, 201):
            return resp.json()
        print(f"[CRONOS] Check run failed: {resp.status_code}")
    except Exception as e:
        print(f"[CRONOS] Check run exception: {e}")
    return None

# ============================================================================
# METADATA STORE (zero code retention)
# ============================================================================

class MetadataStore:
    """SQLite-backed store. NEVER stores source code."""

    @staticmethod
    def save(report_id: str, repo: str, file: str, timestamp: str,
             risk_score: int, security_score: int, overall_score: int,
             severity: str, old_hash: str, new_hash: str, semantic_hash: str,
             mode: str, status: str) -> None:
        try:
            with _db_conn() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO reports VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (report_id, repo, file, timestamp, risk_score, security_score,
                     overall_score, severity, old_hash, new_hash, semantic_hash, mode, status),
                )
                conn.commit()
        except Exception as e:
            print(f"⚠️ MetadataStore.save: {e}")

    @staticmethod
    def history(repo: str, limit: int = 100) -> List[Dict]:
        try:
            with _db_conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM reports WHERE repo=? ORDER BY timestamp DESC LIMIT ?", (repo, limit)
                ).fetchall()
            return [dict(r) for r in rows]
        except: return []

    @staticmethod
    def trend(repo: str, limit: int = 30) -> Dict:
        h = MetadataStore.history(repo, limit)
        if not h: return {"repo": repo, "entries": [], "averages": {}}
        entries = [{"timestamp": r["timestamp"], "risk_score": r["risk_score"],
                    "security_score": r["security_score"], "overall_score": r["overall_score"],
                    "severity": r["severity"], "file": r["file"]} for r in h]
        n = len(entries)
        return {
            "repo": repo, "entries": entries, "count": n,
            "averages": {
                "risk_score":     round(sum(e["risk_score"]     for e in entries) / n, 1),
                "security_score": round(sum(e["security_score"] for e in entries) / n, 1),
                "overall_score":  round(sum(e["overall_score"]  for e in entries) / n, 1),
            },
        }

    @staticmethod
    def summary() -> Dict:
        try:
            with _db_conn() as conn:
                total = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
                sevs  = {r["severity"]: r["cnt"] for r in
                         conn.execute("SELECT severity, COUNT(*) as cnt FROM reports GROUP BY severity").fetchall()}
                avg   = conn.execute("SELECT AVG(risk_score) r, AVG(security_score) s, AVG(overall_score) o FROM reports").fetchone()
            return {"total_reports": total, "severity_counts": sevs,
                    "averages": {"risk_score": round(avg["r"] or 0, 1), "security_score": round(avg["s"] or 0, 1), "overall_score": round(avg["o"] or 0, 1)}}
        except: return {"total_reports": 0, "severity_counts": {}, "averages": {}}

    @staticmethod
    def recent(limit: int = 20) -> List[Dict]:
        try:
            with _db_conn() as conn:
                return [dict(r) for r in conn.execute("SELECT * FROM reports ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()]
        except: return []

    @staticmethod
    def high_risk(threshold: int = 60, limit: int = 50) -> List[Dict]:
        try:
            with _db_conn() as conn:
                return [dict(r) for r in conn.execute(
                    "SELECT * FROM reports WHERE risk_score>=? ORDER BY risk_score DESC, timestamp DESC LIMIT ?",
                    (threshold, limit)).fetchall()]
        except: return []

# ============================================================================
# CORE ANALYSIS RUNNER
# ============================================================================

_intel = IntelligenceEngine()
_qual  = CodeQualityAnalyzer()
_sec   = SecurityAnalyzer()
_pred  = ExecutionPredictor()
_ai_ex = AIExplainer()


async def run_full_analysis(
    old_code: str, new_code: str, mode: str = "STRICT",
    repo: str = "", file: str = "",
) -> Dict[str, Any]:
    loop      = asyncio.get_event_loop()
    report_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat() + "Z"

    # 1. Hashes — always computed first
    hashes        = HashEngine.compute(old_code, new_code)
    old_hash      = hashes["old_hash"]
    new_hash      = hashes["new_hash"]
    semantic_hash = hashes["semantic_hash"]

    # 2. Cache check (scores only — no source code retained in cache)
    cache_key = f"{semantic_hash}:{mode}"
    if cache_key in HASH_CACHE:
        scores = HASH_CACHE[cache_key]
        cached = {
            "status":          RiskEngine.status(scores["risk_score"]),
            "risk":            scores["risk_score"],
            "risk_score":      scores["risk_score"],
            "quality_score":   scores["quality_score"],
            "security_score":  scores["security_score"],
            "overall_score":   scores["overall_score"],
            "severity":        scores["severity"],
            "mode":            mode,
            "old_hash":        old_hash,
            "new_hash":        new_hash,
            "semantic_hash":   semantic_hash,
            # Cached responses still include placeholder explanations
            "technical_explanation": f"[{mode}] Cached result. Risk: {scores['risk_score']}/100, Severity: {scores['severity']}.",
            "human_explanation":     f"[{mode}] This analysis was retrieved from cache based on matching semantic hash.",
            "risk_reasoning":        f"Risk score {scores['risk_score']} from previous identical analysis.",
            "behavioral_impact":     "See cached findings for behavioral details.",
            "ai_provider":           "Cache",
            "execution_prediction":  {"possible_outputs": [], "exceptions": [], "confidence": 0.0, "execution_paths": 1},
            "behavior":              {"changed": False, "summary": "Cached result", "changes": []},
            "risk_findings":         [],
            "quality_findings":      [],
            "security_findings":     [],
            "summary":               ["Cached result"],
            "findings_count":        0,
            "pass":   RiskEngine.status(scores["risk_score"]) == "PASS",
            "warn":   RiskEngine.status(scores["risk_score"]) == "WARN",
            "fail":   RiskEngine.status(scores["risk_score"]) == "FAIL",
            "report_id":   report_id,
            "timestamp":   timestamp,
            "cache_hit":   True,
            "download_urls": {
                "json":  f"/report/json/{report_id}",
                "pdf":   f"/report/pdf/{report_id}",
                "store": f"/report/store/{report_id}",
            },
        }
        REPORT_STORE[report_id] = cached
        return cached

    # 3. Mode-specific constraints
    constraints = {
        "STRICT":   Constraint(no_behavior_change=True,  allow_boundary_change=False),
        "BOUNDARY": Constraint(no_behavior_change=False, allow_boundary_change=True),
        "CONTRACT": Constraint(no_behavior_change=False, allow_boundary_change=False),
    }.get(mode, Constraint(no_behavior_change=False, allow_boundary_change=False))

    # 4. Parallel analysis layers
    def _risk():
        if old_code.strip():
            return _intel.analyze_change(old_code, new_code, constraints)
        return _intel.analyze_compliance(new_code, "")

    def _quality():    return _qual.analyze(new_code)
    def _security():   return _sec.analyze(new_code)
    def _prediction(): return _pred.predict(new_code)
    def _behavior():   return _intel.compare_behavior(old_code, new_code)

    (risk_res, qual_res, sec_res, pred_res, beh_res) = await asyncio.gather(
        loop.run_in_executor(_EXECUTOR, _risk),
        loop.run_in_executor(_EXECUTOR, _quality),
        loop.run_in_executor(_EXECUTOR, _security),
        loop.run_in_executor(_EXECUTOR, _prediction),
        loop.run_in_executor(_EXECUTOR, _behavior),
    )

    risk_findings, raw_risk, risk_signals = risk_res
    quality_score,  quality_issues        = qual_res
    security_score, sec_findings          = sec_res
    exec_pred                             = pred_res
    behavior                              = beh_res

    risk_score     = RiskEngine.normalize(raw_risk)
    status         = RiskEngine.status(risk_score)
    behavior_score = behavior.get("behavior_score", 100)
    overall_score  = RiskEngine.overall(raw_risk, quality_score, security_score, behavior_score)
    severity       = RiskEngine.classify_severity(risk_score, security_score, behavior.get("changed", False), exec_pred)

    # 5. AI explanation — always runs, never crashes pipeline
    def _explain():
        return _ai_ex.explain(
            old_code, new_code, risk_findings, risk_score,
            quality_score, security_score, hashes,
            {
                "possible_outputs": exec_pred.get("possible_outputs", []),
                "exceptions":       exec_pred.get("exceptions", []),
                "confidence":       exec_pred.get("confidence", 0),
            },
            mode=mode,
        )

    ai_fields = await loop.run_in_executor(_EXECUTOR, _explain)

    # 6. Assemble result — ZERO CODE RETENTION
    result = {
        "status":     status,
        "risk":       risk_score,
        "risk_score": risk_score,
        "mode":       mode,
        "quality_score":  quality_score,
        "security_score": security_score,
        "overall_score":  overall_score,
        "behavior_score": behavior_score,
        "severity":       severity,
        # Hashes always present
        "old_hash":      old_hash,
        "new_hash":      new_hash,
        "semantic_hash": semantic_hash,
        # Full AI explanations always present
        "technical_explanation": ai_fields.get("technical_explanation", ""),
        "human_explanation":     ai_fields.get("human_explanation", ""),
        "risk_reasoning":        ai_fields.get("risk_reasoning", ""),
        "behavioral_impact":     ai_fields.get("behavioral_impact", ""),
        "ai_provider":           ai_fields.get("ai_provider", "None"),
        # Execution prediction
        "execution_prediction": {
            "possible_outputs": exec_pred.get("possible_outputs", []),
            "return_values":    exec_pred.get("return_values", []),
            "print_outputs":    exec_pred.get("print_outputs", []),
            "branches":         exec_pred.get("branches", []),
            "state_changes":    exec_pred.get("state_changes", []),
            "exceptions":       exec_pred.get("exceptions", []),
            "auth_outcomes":    exec_pred.get("auth_outcomes", []),
            "confidence":       exec_pred.get("confidence", 0.0),
            "execution_paths":  exec_pred.get("execution_paths", 1),
        },
        # Behavior
        "behavior": {
            "changed": behavior.get("changed", False),
            "summary": behavior.get("summary", ""),
            "changes": behavior.get("changes", []),
        },
        # Findings
        "summary":          [f.findings[0] for f in risk_findings[:5]] if risk_findings else ["No issues"],
        "findings_count":   len(risk_findings),
        "risk_findings":    [f.dict() for f in risk_findings],
        "quality_findings": quality_issues,
        "security_findings": sec_findings,
        # Gate flags
        "pass": status == "PASS",
        "warn": status == "WARN",
        "fail": status == "FAIL",
        # Metadata
        "metadata":    risk_signals,
        "report_id":   report_id,
        "timestamp":   timestamp,
        "cache_hit":   False,
        "download_urls": {
            "json":  f"/report/json/{report_id}",
            "pdf":   f"/report/pdf/{report_id}",
            "store": f"/report/store/{report_id}",
        },
    }

    # 7. Cache scores only (no source code)
    HASH_CACHE[cache_key] = {
        "risk_score":     risk_score,
        "severity":       severity,
        "overall_score":  overall_score,
        "quality_score":  quality_score,
        "security_score": security_score,
    }
    REPORT_STORE[report_id] = result

    # 8. Persist metadata to SQLite (no source code stored)
    MetadataStore.save(
        report_id, repo, file, timestamp,
        risk_score, security_score, overall_score,
        severity, old_hash, new_hash, semantic_hash,
        mode, status,
    )

    # 9. Persist safe JSON report (no source code)
    safe = {k: v for k, v in result.items()}
    try:
        with open(f"{REPORT_DIR}/{report_id}.json", "w", encoding="utf-8") as fh:
            json.dump(safe, fh, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"⚠️ persist JSON: {e}")

    # ZERO CODE RETENTION — delete source from local scope
    del old_code, new_code

    return result

# ============================================================================
# PDF GENERATION
# ============================================================================

def _generate_pdf(data: Dict) -> BytesIO:
    buf = BytesIO()
    c   = canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    y = h - 0.5 * inch

    c.setFont("Helvetica-Bold", 20)
    c.drawString(0.5*inch, y, "CRONOS v8 — Intelligence Analysis Report"); y -= 0.3*inch
    c.setFont("Helvetica", 10)
    c.drawString(0.5*inch, y, f"Generated: {data.get('timestamp','N/A')}  |  Report: {data.get('report_id','N/A')}"); y -= 0.4*inch

    c.setFont("Helvetica-Bold", 13)
    c.drawString(0.5*inch, y, "Scores"); y -= 0.22*inch
    c.setFont("Helvetica", 11)
    for label, key in [
        ("Mode",           "mode"),
        ("Risk Score",     "risk_score"),
        ("Quality Score",  "quality_score"),
        ("Security Score", "security_score"),
        ("Overall Score",  "overall_score"),
        ("Severity",       "severity"),
        ("Status",         "status"),
    ]:
        c.drawString(0.75*inch, y, f"{label}: {data.get(key, 'N/A')}"); y -= 0.18*inch

    for h_label, hash_key in [("Old Hash", "old_hash"), ("New Hash", "new_hash"), ("Semantic Hash", "semantic_hash")]:
        val = data.get(hash_key, "")
        if val:
            c.setFont("Courier", 9)
            c.drawString(0.75*inch, y, f"{h_label}: {val[:48]}..."); y -= 0.16*inch
    c.setFont("Helvetica", 11)

    y -= 0.15*inch; c.setFont("Helvetica-Bold", 13); c.drawString(0.5*inch, y, "Key Findings"); y -= 0.22*inch
    c.setFont("Helvetica", 10)
    for finding in (data.get("risk_findings") or [])[:8]:
        msg  = (finding.get("findings") or [""])[0]
        risk = finding.get("risk", 0)
        words = msg.split(); line = ""; lines_out = []
        for word in words:
            test = (line + " " + word).strip()
            if c.stringWidth(test, "Helvetica", 10) < (w - 1.5*inch): line = test
            else: lines_out.append(line); line = word
        if line: lines_out.append(line)
        c.drawString(0.75*inch, y, f"• {lines_out[0] if lines_out else msg[:80]}"); y -= 0.17*inch
        for ln in lines_out[1:]: c.drawString(0.95*inch, y, ln); y -= 0.17*inch
        c.setFont("Helvetica-Oblique", 9)
        c.drawString(0.95*inch, y, f"Risk: {risk}/100"); y -= 0.22*inch
        c.setFont("Helvetica", 10)
        if y < 1*inch: c.showPage(); y = h - 0.5*inch

    for section_title, field_key in [
        ("Technical Explanation", "technical_explanation"),
        ("Human Explanation",     "human_explanation"),
        ("Risk Reasoning",        "risk_reasoning"),
        ("Behavioral Impact",     "behavioral_impact"),
    ]:
        if y < 3*inch: c.showPage(); y = h - 0.5*inch
        y -= 0.15*inch
        c.setFont("Helvetica-Bold", 13)
        c.drawString(0.5*inch, y, section_title); y -= 0.22*inch
        c.setFont("Helvetica", 9)
        for line in _wrap(data.get(field_key, "N/A")[:600], c, w - 1.5*inch, "Helvetica", 9)[:20]:
            c.drawString(0.75*inch, y, line); y -= 0.15*inch
            if y < 0.5*inch: break

    c.setFont("Helvetica-Oblique", 8)
    c.drawString(0.5*inch, 0.4*inch, "CRONOS v8.0.0 — Enterprise Intelligence Code Analyzer")
    c.save(); buf.seek(0)
    return buf

def _wrap(text, c, max_w, font, size):
    words = text.split(); line = ""; lines = []
    for word in words:
        test = (line + " " + word).strip()
        if c.stringWidth(test, font, size) < max_w: line = test
        else: lines.append(line); line = word
    if line: lines.append(line)
    return lines

# ============================================================================
# ENDPOINTS
# ============================================================================

# ── POST /analyze_full ───────────────────────────────────────────────────────
@app.post("/analyze_full")
async def analyze_full(req: FullAnalyzeRequest):
    """
    Full 6-layer enterprise intelligence report.
    Always returns: status, severity, risk_score, all 4 AI explanation fields, hashes.
    """
    try:
        result = await run_full_analysis(req.old_code, req.new_code, req.mode, req.repo, req.file)
        return result
    except Exception as e:
        raise HTTPException(500, f"Analysis error: {e}")


# ── POST /analyze_realtime ────────────────────────────────────────────────────
@app.post("/analyze_realtime")
async def analyze_realtime(req: RealtimeAnalyzeRequest):
    """IDE plugin endpoint. Target: < 2 seconds."""
    import time; t0 = time.time()
    code     = req.code
    filename = req.filename
    loop     = asyncio.get_event_loop()

    def _run_all():
        quality,  qi = _qual.analyze(code)
        security, si = _sec.analyze(code)
        pred         = _pred.predict(code)
        sev_w = {"critical": 30, "high": 15, "medium": 8, "low": 3}
        penalty = sum(sev_w.get(f.get("severity","low"), 3) for f in si)
        risk_score = RiskEngine.normalize(min(100, penalty))
        severity   = RiskEngine.classify_severity(risk_score, security, False, pred)
        return quality, qi, security, si, pred, risk_score, severity

    quality, qi, security, si, pred, risk_score, severity = await loop.run_in_executor(_EXECUTOR, _run_all)

    hashes = HashEngine.compute("", code)

    def _explain_rt():
        return _ai_ex.realtime_explain(code, si, risk_score, security)

    ai = await loop.run_in_executor(_EXECUTOR, _explain_rt)

    elapsed = round(time.time() - t0, 3)

    result = {
        "filename":       filename,
        "risk_score":     risk_score,
        "security_score": security,
        "quality_score":  quality,
        "overall_score":  RiskEngine.overall(risk_score, quality, security, 100),
        "severity":       severity,
        "status":         RiskEngine.status(risk_score),
        "old_hash":       hashes["old_hash"],
        "new_hash":       hashes["new_hash"],
        "semantic_hash":  hashes["semantic_hash"],
        "execution_prediction": {
            "possible_outputs": pred.get("possible_outputs", []),
            "exceptions":       pred.get("exceptions", []),
            "confidence":       pred.get("confidence", 0),
        },
        "security_findings":     si[:10],
        "quality_findings":      qi[:10],
        "technical_explanation": ai.get("technical_explanation", ""),
        "human_explanation":     ai.get("human_explanation", ""),
        "risk_reasoning":        ai.get("risk_reasoning", ""),
        "behavioral_impact":     ai.get("behavioral_impact", ""),
        "ai_provider":           ai.get("ai_provider", "None"),
        "elapsed_seconds":       elapsed,
        "timestamp":             datetime.utcnow().isoformat() + "Z",
    }

    del code
    return result


# ── GET /history/{repo} ──────────────────────────────────────────────────────
@app.get("/history/{repo}")
async def get_history(repo: str, limit: int = 100):
    return MetadataStore.history(repo, limit)


# ── GET /trend/{repo} ───────────────────────────────────────────────────────
@app.get("/trend/{repo}")
async def get_trend(repo: str, limit: int = 30):
    return MetadataStore.trend(repo, limit)


# ── GET /dashboard/summary ───────────────────────────────────────────────────
@app.get("/dashboard/summary")
async def dashboard_summary():
    return MetadataStore.summary()


# ── GET /dashboard/recent ────────────────────────────────────────────────────
@app.get("/dashboard/recent")
async def dashboard_recent(limit: int = 20):
    return MetadataStore.recent(limit)


# ── GET /dashboard/high_risk ─────────────────────────────────────────────────
@app.get("/dashboard/high_risk")
async def dashboard_high_risk(threshold: int = 60, limit: int = 50):
    return MetadataStore.high_risk(threshold, limit)


# ── POST /github/pr_comment ──────────────────────────────────────────────────
@app.post("/github/pr_comment")
async def post_pr_comment(request: Request):
    """
    Post PR comment from server side.
    Body: { "report_id": "...", "pr_number": 42, "owner": "...", "repo": "...", "github_token": "..." }
    """
    body = await request.json()
    rid  = body.get("report_id")
    if rid not in REPORT_STORE:
        path = f"{REPORT_DIR}/{rid}.json"
        if not os.path.exists(path):
            raise HTTPException(404, f"Report not found: {rid}")
        with open(path, encoding="utf-8") as fh:
            analysis = json.load(fh)
    else:
        analysis = REPORT_STORE[rid]

    token = body.get("github_token") or os.getenv("GITHUB_TOKEN")
    if not token:
        raise HTTPException(400, "github_token required")

    # Parse owner/repo from "owner/repo" string if needed
    raw_repo  = body.get("repo", "")
    parts     = raw_repo.split("/")
    owner_val = body.get("owner", parts[0] if len(parts) >= 2 else "")
    repo_val  = parts[-1] if len(parts) >= 2 else raw_repo

    result = PRCommentFormatter.post(
        token, owner_val, repo_val, int(body.get("pr_number", 0)), analysis
    )
    return {"success": result is not None, "comment": result}


# ── POST /github/check_run ───────────────────────────────────────────────────
@app.post("/github/check_run")
async def post_check_run(request: Request):
    """
    Create GitHub Check Run with inline annotations.
    Body: { "report_id": "...", "sha": "...", "owner": "...", "repo": "...", "filename": "...", "github_token": "..." }
    """
    body = await request.json()
    rid  = body.get("report_id")
    if rid not in REPORT_STORE:
        path = f"{REPORT_DIR}/{rid}.json"
        if not os.path.exists(path):
            raise HTTPException(404, f"Report not found: {rid}")
        with open(path, encoding="utf-8") as fh:
            analysis = json.load(fh)
    else:
        analysis = REPORT_STORE[rid]

    token = body.get("github_token") or os.getenv("GITHUB_TOKEN")
    if not token:
        raise HTTPException(400, "github_token required")

    result = create_check_run(
        token, body.get("owner",""), body.get("repo",""),
        body.get("sha",""), analysis, body.get("filename", "unknown.py"),
    )
    return {"success": result is not None, "check_run": result}


# ── POST /analyze (legacy CHANGE/COMPLIANCE) ─────────────────────────────────
@app.post("/analyze")
async def analyze(req: AnalyzeRequest):
    mode = req.mode; report_id = str(uuid.uuid4())
    try:
        if mode == "CHANGE":
            old_code = req.get_old_code(); new_code = req.get_new_code()
            if not old_code.strip(): raise HTTPException(400, "old_code required")
            if not new_code.strip(): raise HTTPException(400, "new_code required")
            findings, raw_risk, signals = _intel.analyze_change(old_code, new_code, req.constraints)
            risk = RiskEngine.normalize(raw_risk); status = RiskEngine.status(risk)
            quality, qi = _qual.analyze(new_code); security, si = _sec.analyze(new_code)
            behavior    = _intel.compare_behavior(old_code, new_code)
            overall     = RiskEngine.overall(risk, quality, security, behavior.get("behavior_score", 100))
            hashes      = HashEngine.compute(old_code, new_code)
            severity    = RiskEngine.classify_severity(risk, security, behavior.get("changed", False), {})
            ai_fields   = _ai_ex.explain(old_code, new_code, findings, risk, quality, security, hashes, {}, mode="CHANGE")
            result = {
                "mode": mode, "status": status, "risk_score": risk, "quality_score": quality,
                "security_score": security, "overall_score": overall, "severity": severity,
                "old_hash":      hashes["old_hash"],
                "new_hash":      hashes["new_hash"],
                "semantic_hash": hashes["semantic_hash"],
                "analyzer_findings": [f.dict() for f in findings],
                "quality_findings": qi, "security_findings": si,
                "behavior": {"changed": behavior["changed"], "summary": behavior["summary"]},
                "technical_explanation": ai_fields.get("technical_explanation", ""),
                "human_explanation":     ai_fields.get("human_explanation", ""),
                "risk_reasoning":        ai_fields.get("risk_reasoning", ""),
                "behavioral_impact":     ai_fields.get("behavioral_impact", ""),
                "ai_provider": ai_fields.get("ai_provider", "None"),
                "report_id": report_id, "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        elif mode == "COMPLIANCE":
            if not req.source_code.strip(): raise HTTPException(400, "source_code required")
            findings, raw_risk, signals = _intel.analyze_compliance(req.source_code, req.expected_output)
            risk = RiskEngine.normalize(raw_risk); status = RiskEngine.status(risk)
            quality, qi = _qual.analyze(req.source_code); security, si = _sec.analyze(req.source_code)
            overall  = RiskEngine.overall(risk, quality, security, 100)
            hashes   = HashEngine.compute("", req.source_code)
            severity = RiskEngine.classify_severity(risk, security, False, {})
            ai_fields = _ai_ex.explain("", req.source_code, findings, risk, quality, security, hashes, {}, mode="COMPLIANCE")
            result = {
                "mode": mode, "status": status, "risk_score": risk, "quality_score": quality,
                "security_score": security, "overall_score": overall, "severity": severity,
                "old_hash":      hashes["old_hash"],
                "new_hash":      hashes["new_hash"],
                "semantic_hash": hashes["semantic_hash"],
                "analyzer_findings": [f.dict() for f in findings],
                "quality_findings": qi, "security_findings": si,
                "technical_explanation": ai_fields.get("technical_explanation", ""),
                "human_explanation":     ai_fields.get("human_explanation", ""),
                "risk_reasoning":        ai_fields.get("risk_reasoning", ""),
                "behavioral_impact":     ai_fields.get("behavioral_impact", ""),
                "ai_provider": ai_fields.get("ai_provider", "None"),
                "report_id": report_id, "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        else:
            raise HTTPException(400, f"Invalid mode '{mode}'")

        try:
            with open(f"{REPORT_DIR}/{report_id}.json", "w", encoding="utf-8") as fh:
                json.dump(result, fh, indent=2, ensure_ascii=False)
        except: pass
        return result
    except HTTPException: raise
    except Exception as e: raise HTTPException(500, str(e))


# ── GET/POST /analyze_ci ─────────────────────────────────────────────────────
@app.get("/analyze_ci")
async def analyze_ci_get():
    return {"status": "OK", "message": "POST with {old_code, new_code, mode}"}

@app.post("/analyze_ci")
async def analyze_ci(request: Request):
    try:
        body = await request.json()
    except:
        return JSONResponse(status_code=400, content={
            "status":"FAIL","risk":100,"summary":["Invalid JSON"],
            "pass":False,"warn":False,"fail":True,
        })

    old_code = body.get("old_code", "")
    new_code = body.get("new_code", "")
    mode     = str(body.get("mode", "STRICT")).upper()
    if not new_code:
        return JSONResponse(status_code=400, content={
            "status":"FAIL","risk":100,"summary":["new_code required"],
            "pass":False,"warn":False,"fail":True,
        })
    mode = mode if mode in ("STRICT","BOUNDARY","CONTRACT") else "STRICT"

    try:
        constraints = {
            "STRICT":   Constraint(no_behavior_change=True),
            "BOUNDARY": Constraint(allow_boundary_change=True),
        }.get(mode, Constraint())

        findings, raw, meta = (
            _intel.analyze_change(old_code, new_code, constraints)
            if old_code.strip()
            else _intel.analyze_compliance(new_code, "")
        )
        risk     = RiskEngine.normalize(raw)
        status   = RiskEngine.status(risk)
        quality, _ = _qual.analyze(new_code)
        security, _ = _sec.analyze(new_code)
        behavior   = _intel.compare_behavior(old_code, new_code)
        overall    = RiskEngine.overall(risk, quality, security, behavior.get("behavior_score", 100))
        severity   = RiskEngine.classify_severity(risk, security, behavior.get("changed", False), {})
        hashes     = HashEngine.compute(old_code, new_code)

        return JSONResponse(content={
            "risk": risk, "status": status, "mode": mode, "severity": severity,
            "findings_count": len(findings),
            "summary": [f.findings[0] for f in findings[:5]] or ["No issues"],
            "quality_score": quality, "security_score": security, "overall_score": overall,
            "behavior_changed": behavior.get("changed", False),
            "old_hash":      hashes["old_hash"],
            "new_hash":      hashes["new_hash"],
            "semantic_hash": hashes["semantic_hash"],
            "pass": status=="PASS", "warn": status=="WARN", "fail": status=="FAIL",
            "timestamp": datetime.utcnow().isoformat() + "Z",
        })
    except Exception as e:
        return JSONResponse(status_code=500, content={
            "status":"FAIL","risk":100,"summary":[str(e)],
            "pass":False,"warn":False,"fail":True,
        })


# ── REPORT ENDPOINTS ─────────────────────────────────────────────────────────
@app.get("/report/store/{report_id}")
async def report_store(report_id: str):
    if report_id in REPORT_STORE:
        return JSONResponse(content=REPORT_STORE[report_id])
    path = f"{REPORT_DIR}/{report_id}.json"
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            return JSONResponse(content=json.load(fh))
    raise HTTPException(404, f"Report not found: {report_id}")

@app.get("/report/json/{report_id}")
async def report_json(report_id: str):
    path = f"{REPORT_DIR}/{report_id}.json"
    if not os.path.exists(path): raise HTTPException(404, f"Not found: {report_id}")
    with open(path, encoding="utf-8") as fh:
        return JSONResponse(
            content=json.load(fh),
            headers={"Content-Disposition": f'attachment; filename="cronos_{report_id}.json"'},
        )

@app.get("/report/pdf/{report_id}")
async def report_pdf(report_id: str):
    path = f"{REPORT_DIR}/{report_id}.json"
    if not os.path.exists(path): raise HTTPException(404, f"Not found: {report_id}")
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return StreamingResponse(
        _generate_pdf(data),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="cronos_{report_id}.pdf"'},
    )


# ── HEALTH ───────────────────────────────────────────────────────────────────
@app.get("/")
async def health():
    return {
        "status":  "ok",
        "service": "CRONOS v8.0.0 — Enterprise Intelligence Code Analyzer",
        "version": "8.0.0",
        "stages": {
            "stage_1": "BOUNDARY — boundary condition analysis",
            "stage_2": "CONTRACT — contract compliance analysis",
            "stage_3": "STRICT   — strict behavioral enforcement",
            "stage_4": "UNIFIED INTELLIGENCE — runs only when all 3 pass",
        },
        "features": {
            "feature_1": "Automatic PR Comments (POST /github/pr_comment)",
            "feature_2": "Inline Code Annotations (POST /github/check_run)",
            "feature_3": "Security Severity Classification (severity in all responses)",
            "feature_4": "Historical Trend Tracking (GET /history/{repo}, GET /trend/{repo})",
            "feature_5": "Dashboard UI Backend (GET /dashboard/*)",
            "feature_6": "IDE Plugin Support (POST /analyze_realtime)",
        },
        "endpoints": {
            "POST /analyze_full":      "Full 6-layer enterprise intelligence (all 4 AI explanations)",
            "POST /analyze_realtime":  "IDE plugin — sub-2s analysis",
            "POST /analyze":           "Advanced analysis (CHANGE/COMPLIANCE)",
            "POST /analyze_ci":        "CI/CD fast gate",
            "POST /github/pr_comment": "Post PR intelligence comment",
            "POST /github/check_run":  "Create Check Run with annotations",
            "GET  /history/{repo}":    "Historical reports",
            "GET  /trend/{repo}":      "Trend data for dashboard",
            "GET  /dashboard/summary": "Dashboard summary",
            "GET  /dashboard/recent":  "Recent reports",
            "GET  /dashboard/high_risk": "High risk reports",
            "GET  /report/json/{id}":  "Download JSON report",
            "GET  /report/pdf/{id}":   "Download PDF report",
            "GET  /report/store/{id}": "In-memory report retrieval",
        },
        "security": {
            "zero_code_retention": True,
            "code_stored_on_disk": False,
            "hashes_only": True,
        },
        "intelligence": {
            "gemini":     bool(GEMINI_API_KEY),
            "openrouter": OPENROUTER_ENABLED,
            "layers": [
                "IntelligenceEngine",
                "CodeQualityAnalyzer",
                "SecurityAnalyzer",
                "ExecutionPredictor",
                "AIExplainer",
                "RiskEngine",
            ],
        },
    }


# ── STARTUP ──────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    _init_db()
    print("=" * 80)
    print("✅ CRONOS v8.0.0 — ENTERPRISE INTELLIGENCE CODE ANALYZER")
    print("=" * 80)
    print(f"🤖 Gemini    : {'✅ Enabled' if GEMINI_API_KEY     else '❌ Disabled'}")
    print(f"🤖 OpenRouter: {'✅ Enabled' if OPENROUTER_ENABLED else '❌ Disabled'}")
    print(f"🗄️  Database  : {DB_PATH}")
    print()
    print("🏗️  STAGES:")
    print("  Stage 1 — BOUNDARY        (always runs)")
    print("  Stage 2 — CONTRACT        (always runs)")
    print("  Stage 3 — STRICT          (always runs)")
    print("  Stage 4 — UNIFIED INTEL   (only if all 3 pass)")
    print()
    print("🏢 ENTERPRISE FEATURES:")
    print("  ✓ F1 — Automatic PR Comments")
    print("  ✓ F2 — Inline Code Annotations (Check Runs)")
    print("  ✓ F3 — Security Severity Classification")
    print("  ✓ F4 — Historical Trend Tracking (SQLite)")
    print("  ✓ F5 — Dashboard UI Backend")
    print("  ✓ F6 — IDE Plugin Support (realtime < 2s)")
    print()
    print("🔒 ZERO CODE RETENTION — source code never persisted")
    print("=" * 80)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
