"""AST detector for Python.

Covers the OWASP-LLM categories that are *structurally* detectable with low
noise. The philosophy: be generous about producing candidates, but tag each
one with a `detector_confidence` and a `deterministic` flag so the funnel knows
which need LLM confirmation and which are near-certain on their own.

Detected:
  LLM05  Improper Output Handling  -- LLM output flows into eval/exec/subprocess/SQL
  LLM06  Excessive Agency          -- dangerous agent tools / allow_dangerous_* flags
  LLM04  Data & Model Poisoning    -- pickle/torch/joblib load, trust_remote_code
  LLM10  Unbounded Consumption     -- completion call with no max_tokens
  LLM01  Prompt Injection          -- untrusted input concatenated into a prompt
"""
from __future__ import annotations

import ast

from ..models import Candidate, Severity
from .base import register

# Suffixes that identify an LLM completion/inference call site.
LLM_CALL_SUFFIXES = (
    "chat.completions.create",
    "completions.create",
    "messages.create",       # Anthropic
    "ChatCompletion.create",
    "responses.create",
)
# Method names treated as LLM calls only when a known SDK was imported.
LLM_CALL_METHODS = {"invoke", "predict", "generate", "complete", "run"}
LLM_SDK_HINTS = ("openai", "anthropic", "langchain", "llama_index", "litellm", "cohere")

# Sinks that must never receive raw model output.
CODE_EXEC_SINKS = {"eval", "exec", "compile", "os.system", "subprocess.run",
                   "subprocess.call", "subprocess.Popen", "subprocess.check_output",
                   "pd.eval", "pandas.eval"}
SQL_EXEC_HINTS = ("execute", "executescript", "executemany")

# Untrusted input sources -> taint for the prompt-injection check.
INPUT_SOURCE_SUFFIXES = ("input", "request.get_json", "request.json", "get_json")
INPUT_SOURCE_ATTRS = ("args", "form", "values", "data", "json", "query_params", "body")


def _name(node: ast.AST) -> str:
    """Best-effort dotted name for a call/attribute target."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_name(node.value)}.{node.attr}"
    if isinstance(node, ast.Call):
        return _name(node.func)
    return ""


def _has_kw(call: ast.Call, key: str) -> bool:
    return any(k.arg == key for k in call.keywords)


def _kw(call: ast.Call, key: str):
    for k in call.keywords:
        if k.arg == key:
            return k.value
    return None


def _seg(source: str, node: ast.AST) -> str:
    try:
        return ast.get_source_segment(source, node) or ""
    except Exception:
        return ""


class _Visitor(ast.NodeVisitor):
    def __init__(self, source: str):
        self.source = source
        self.candidates: list[Candidate] = []
        self.sdk_imported = False
        self.llm_tainted: set[str] = set()      # vars holding LLM output
        self.input_tainted: set[str] = set()     # vars holding untrusted input

    # -- imports --------------------------------------------------------
    def visit_Import(self, node):
        for a in node.names:
            if any(h in a.name for h in LLM_SDK_HINTS):
                self.sdk_imported = True
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module and any(h in node.module for h in LLM_SDK_HINTS):
            self.sdk_imported = True
        self.generic_visit(node)

    # -- assignments track taint ---------------------------------------
    def visit_Assign(self, node):
        target = node.targets[0]
        tname = target.id if isinstance(target, ast.Name) else None
        if isinstance(node.value, ast.Call):
            if self._is_llm_call(node.value) and tname:
                self.llm_tainted.add(tname)
            elif self._is_input_source(node.value) and tname:
                self.input_tainted.add(tname)
        # `resp.choices[0].message.content` style re-assignment stays tainted
        if tname and self._references_tainted(node.value, self.llm_tainted):
            self.llm_tainted.add(tname)
        if tname and self._references_tainted(node.value, self.input_tainted):
            self.input_tainted.add(tname)
        self.generic_visit(node)

    # -- the interesting node -------------------------------------------
    def visit_Call(self, node):
        fname = _name(node.func)

        # LLM10: completion call without a token cap
        if self._is_llm_call(node) and not _has_kw(node, "max_tokens") and not _has_kw(node, "max_completion_tokens"):
            self._add(node, "RUDRA-AST-UNBOUNDED", "LLM10:2025",
                      "LLM call without an output token limit", Severity.LOW,
                      "This completion call sets no `max_tokens`, so a crafted prompt can force "
                      "very long, expensive generations (denial-of-wallet / DoS).",
                      "Pass an explicit `max_tokens` (and a request `timeout`) sized to the use case.",
                      conf=0.45)

        # LLM01: untrusted input concatenated into a prompt
        if self._is_llm_call(node):
            for arg in list(node.args) + [k.value for k in node.keywords if k.arg in ("prompt", "messages", "input")]:
                if self._taints_prompt(arg):
                    self._add(node, "RUDRA-AST-PROMPT-INJECTION", "LLM01:2025",
                              "Untrusted input concatenated directly into a prompt", Severity.HIGH,
                              "User-controlled data is interpolated into the model prompt with no "
                              "delimiting or sanitisation, enabling direct prompt injection.",
                              "Never string-concat untrusted input into instructions. Pass it as a "
                              "clearly-delimited data field, keep system instructions separate, and "
                              "validate/deny-list where possible.",
                              conf=0.55)
                    break

        # LLM05: model output reaching a dangerous sink
        if fname in CODE_EXEC_SINKS or (isinstance(node.func, ast.Attribute) and node.func.attr in SQL_EXEC_HINTS):
            if any(self._references_tainted(a, self.llm_tainted) for a in node.args):
                sink_kind = "SQL query" if node.func.__class__ is ast.Attribute and getattr(node.func, "attr", "") in SQL_EXEC_HINTS else "code execution"
                self._add(node, "RUDRA-AST-OUTPUT-EXEC", "LLM05:2025",
                          f"LLM output flows into {sink_kind}", Severity.CRITICAL,
                          "Raw model output is passed to a dangerous sink. A prompt-injected or "
                          "hallucinated response becomes remote code / query execution.",
                          "Treat model output as untrusted. Never eval/exec it or splice it into "
                          "queries. Constrain to a strict schema/enum, parse, and validate before use.",
                          conf=0.75)

        # LLM04/LLM03: unsafe deserialization & remote code trust (deterministic)
        self._check_supply_chain(node, fname)

        # LLM06: excessive agency (deterministic danger flags)
        self._check_excessive_agency(node, fname)

        self.generic_visit(node)

    # -- helpers --------------------------------------------------------
    def _is_llm_call(self, node: ast.Call) -> bool:
        fname = _name(node.func)
        if any(fname.endswith(s) for s in LLM_CALL_SUFFIXES):
            return True
        if isinstance(node.func, ast.Attribute) and node.func.attr in LLM_CALL_METHODS and self.sdk_imported:
            return True
        return False

    def _is_input_source(self, node: ast.Call) -> bool:
        fname = _name(node.func)
        return any(fname.endswith(s) for s in INPUT_SOURCE_SUFFIXES)

    def _references_tainted(self, node: ast.AST, taint: set[str]) -> bool:
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and n.id in taint:
                return True
            if isinstance(n, ast.Attribute) and n.attr in INPUT_SOURCE_ATTRS and taint is self.input_tainted:
                return True
        return False

    def _taints_prompt(self, arg: ast.AST) -> bool:
        # f-string or `+`/`%`/.format() built from untrusted input
        if isinstance(arg, (ast.JoinedStr, ast.BinOp)):
            if self._references_tainted(arg, self.input_tainted):
                return True
        if isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "format":
            if any(self._references_tainted(a, self.input_tainted) for a in arg.args):
                return True
        # request.args["q"] used inline
        if self._references_tainted(arg, self.input_tainted):
            return True
        return False

    def _check_supply_chain(self, node, fname):
        if fname in ("pickle.load", "pickle.loads", "cPickle.load", "dill.load"):
            self._add(node, "RUDRA-AST-UNSAFE-DESERIALIZE", "LLM04:2025",
                      "Unsafe deserialization of a model/artifact", Severity.HIGH,
                      "`pickle`/`dill` executes arbitrary code on load. A poisoned model or "
                      "cache file becomes code execution the moment it is loaded.",
                      "Load model weights with safetensors or `torch.load(..., weights_only=True)`. "
                      "Never unpickle data from an untrusted or network source.",
                      conf=0.9, deterministic=True)
        elif fname == "torch.load" and not (_kw(node, "weights_only") and getattr(_kw(node, "weights_only"), "value", False) is True):
            self._add(node, "RUDRA-AST-TORCH-LOAD", "LLM04:2025",
                      "torch.load without weights_only=True", Severity.HIGH,
                      "`torch.load` unpickles by default, allowing code execution from a "
                      "malicious checkpoint.",
                      "Pass `weights_only=True`, or migrate to safetensors.",
                      conf=0.85, deterministic=True)
        elif fname in ("joblib.load",):
            self._add(node, "RUDRA-AST-JOBLIB-LOAD", "LLM04:2025",
                      "joblib.load of a possibly-untrusted artifact", Severity.MEDIUM,
                      "joblib uses pickle under the hood; loading an untrusted file runs code.",
                      "Only load artifacts you produced from a trusted, integrity-checked source.",
                      conf=0.6)
        # trust_remote_code=True on HF transformers
        if _has_kw(node, "trust_remote_code"):
            v = _kw(node, "trust_remote_code")
            if isinstance(v, ast.Constant) and v.value is True:
                self._add(node, "RUDRA-AST-TRUST-REMOTE-CODE", "LLM03:2025",
                          "trust_remote_code=True", Severity.HIGH,
                          "Executes arbitrary Python shipped with a downloaded model repo.",
                          "Set `trust_remote_code=False` unless the repo is fully vetted and pinned "
                          "to a specific commit hash.",
                          conf=0.9, deterministic=True)

    def _check_excessive_agency(self, node, fname):
        short = fname.split(".")[-1]
        if short in ("PythonREPLTool", "PythonAstREPLTool", "ShellTool", "TerminalTool"):
            self._add(node, "RUDRA-AST-DANGEROUS-TOOL", "LLM06:2025",
                      f"Agent granted a high-privilege tool ({short})", Severity.HIGH,
                      "The agent can execute shell/Python. Combined with prompt injection this is "
                      "remote code execution with the app's privileges.",
                      "Remove code/shell execution tools, or sandbox them and require human approval "
                      "for each invocation. Apply least privilege to the tool set.",
                      conf=0.8, deterministic=True)
        for flag in ("allow_dangerous_code", "allow_dangerous_requests", "allow_dangerous_deserialization"):
            v = _kw(node, flag)
            if isinstance(v, ast.Constant) and v.value is True:
                self._add(node, "RUDRA-AST-DANGEROUS-FLAG", "LLM06:2025",
                          f"{flag}=True", Severity.HIGH,
                          "An explicit safety guard has been disabled, widening the agent's blast radius.",
                          f"Remove `{flag}=True`. If the capability is truly required, gate it behind "
                          "human-in-the-loop approval and strict allow-lists.",
                          conf=0.85, deterministic=True)
        if short == "load_tools":
            for a in node.args:
                if isinstance(a, ast.List):
                    names = [e.value for e in a.elts if isinstance(e, ast.Constant)]
                    dangerous = [n for n in names if n in ("terminal", "python_repl", "shell", "requests_all")]
                    if dangerous:
                        self._add(node, "RUDRA-AST-LOAD-TOOLS", "LLM06:2025",
                                  f"Agent loads dangerous tools: {', '.join(dangerous)}", Severity.HIGH,
                                  "These tools give the agent shell/HTTP/code capabilities exploitable via injection.",
                                  "Drop the dangerous tools or replace with narrowly-scoped, audited equivalents.",
                                  conf=0.8, deterministic=True)

    def _add(self, node, rule_id, owasp, title, sev, msg, remediation, conf, deterministic=False):
        self.candidates.append(Candidate(
            rule_id=rule_id, owasp_id=owasp, title=title,
            file_path="", start_line=node.lineno, end_line=getattr(node, "end_lineno", node.lineno),
            code_snippet=_seg(self.source, node), severity=sev, message=msg,
            remediation=remediation, detector_confidence=conf, deterministic=deterministic,
        ))


class PythonASTDetector:
    name = "python_ast"

    def scan(self, file_path: str, source: str, changed: set[int]) -> list[Candidate]:
        if not file_path.endswith(".py"):
            return []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return []
        v = _Visitor(source)
        v.visit(tree)
        out = []
        for c in v.candidates:
            if changed and c.start_line not in changed:
                continue
            c.file_path = file_path
            out.append(c)
        return out


register(PythonASTDetector())
