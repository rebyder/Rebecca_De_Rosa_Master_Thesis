#!/usr/bin/env python3
"""
LLM-as-a-Judge evaluation script for SVD Agent outputs.

Evaluates:
  1. sast_report.md       — quality of SuggestorAgent's CWE gap analysis
  2. generated_queries/   — quality of CreatorAgent's generated CodeQL queries

Usage:
  python evaluate.py
  python evaluate.py --report sast_report.md --queries_dir generated_queries --output eval_results
  python evaluate.py --model gpt-4o
"""

import os
import re
import json
import argparse
from pathlib import Path
from typing import List

from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage
from dotenv import load_dotenv

load_dotenv()

# Map OPENAI_KEY -> OPENAI_API_KEY (project uses OPENAI_KEY in .env)
if not os.environ.get("OPENAI_API_KEY") and os.environ.get("OPENAI_KEY"):
    os.environ["OPENAI_API_KEY"] = os.environ["OPENAI_KEY"]

DEFAULT_MODEL = "gpt-4o"


# ---------------------------------------------------------------------------
# Pydantic schemas for structured judge output
# ---------------------------------------------------------------------------

class SuggestorScore(BaseModel):
    gap_identification: int = Field(
        ..., ge=1, le=5,
        description="How accurately the report identifies a real CodeQL coverage gap for this CWE (1=incorrect/trivial, 5=precise and non-obvious)")
    source_specificity: int = Field(
        ..., ge=1, le=5,
        description="How concrete and correctly specified the missing sources are (1=vague/generic, 5=specific API signatures)")
    sink_specificity: int = Field(
        ..., ge=1, le=5,
        description="How concrete and correctly specified the missing sinks are (1=vague/generic, 5=specific APIs with correct argument positions)")
    sanitizer_correctness: int = Field(
        ..., ge=1, le=5,
        description="Whether proposed sanitizers actually neutralize the vulnerability for this CWE (1=incorrect, 5=technically sound and complete)")
    actionability: int = Field(
        ..., ge=1, le=5,
        description="How directly the proposals can be turned into CodeQL predicates (1=too abstract, 5=immediately implementable)")
    overall_quality: int = Field(
        ..., ge=1, le=5,
        description="Holistic quality of the gap analysis (1=poor, 5=excellent)")
    reasoning: str = Field(
        ..., description="Step-by-step reasoning justifying each score")
    strengths: List[str] = Field(
        default_factory=list, description="Specific positive aspects of this analysis")
    weaknesses: List[str] = Field(
        default_factory=list, description="Specific gaps or inaccuracies in the analysis")


class QueryScore(BaseModel):
    report_alignment: int = Field(
        ..., ge=1, le=5,
        description="How faithfully the query implements the suggestor's proposals (1=ignores report, 5=implements all proposed sources/sinks/sanitizers)")
    codeql_correctness: int = Field(
        ..., ge=1, le=5,
        description="Correctness of CodeQL syntax, QL idioms, and API usage (1=many errors, 5=correct and idiomatic)")
    coverage: int = Field(
        ..., ge=1, le=5,
        description="How completely the query covers the identified gap (sources + sinks + sanitizers) (1=partial, 5=complete)")
    false_positive_mitigation: int = Field(
        ..., ge=1, le=5,
        description="Quality of barriers/sanitizers to reduce false positives (1=none or over-broad, 5=well-calibrated)")
    metadata_quality: int = Field(
        ..., ge=1, le=5,
        description="Quality of CodeQL metadata annotations (@name, @description, @id, @kind, @tags, @precision) (1=missing/incorrect, 5=complete and accurate)")
    overall_quality: int = Field(
        ..., ge=1, le=5,
        description="Holistic quality of the generated query (1=poor, 5=excellent)")
    reasoning: str = Field(
        ..., description="Step-by-step reasoning justifying each score")
    strengths: List[str] = Field(
        default_factory=list, description="Specific positive aspects of this query")
    weaknesses: List[str] = Field(
        default_factory=list, description="Improvement areas in this query")
    technical_issues: List[str] = Field(
        default_factory=list,
        description="Concrete technical issues: API misuse, syntax errors, logical flaws, incorrect CodeQL patterns")


# ---------------------------------------------------------------------------
# Judge prompts
# ---------------------------------------------------------------------------

SUGGESTOR_SYSTEM = """\
You are an expert security engineer and CodeQL specialist. You are evaluating the output of an automated SuggestorAgent that analyzed an existing CodeQL query's coverage gaps for a specific CWE and proposed extensions.

Scoring guide (1–5):
  1 = Very poor: incorrect, vague, or trivially obvious
  2 = Poor: significant gaps or inaccuracies
  3 = Acceptable: correct but incomplete or only partially actionable
  4 = Good: mostly correct and concrete with minor omissions
  5 = Excellent: precise, complete, technically sound, and immediately actionable

Be strict. A score of 5 means no meaningful improvement is possible.

Criteria:
- gap_identification: Is the identified gap real and non-trivial? Would standard CodeQL queries actually miss these patterns?
- source_specificity: Are missing sources named with their exact module, class, and method (e.g. `flask.request.args.get()`)?
- sink_specificity: Are missing sinks named with the exact call site and the relevant argument position that carries tainted data?
- sanitizer_correctness: Do the proposed sanitizers actually prevent exploitation for this CWE type? Are there false negatives in the sanitizer list?
- actionability: Could a CodeQL developer write QL predicates directly from these proposals without additional research?
- overall_quality: Holistic assessment.\
"""

SUGGESTOR_HUMAN = """\
Evaluate the SuggestorAgent gap analysis below for {cwe_id}.

## REPORT SECTION
{report_section}
"""

QUERY_SYSTEM = """\
You are an expert CodeQL developer and security researcher. You are evaluating a CodeQL query for Python vulnerability detection that was automatically generated by a CreatorAgent. The query should implement improvements proposed in a gap analysis report.

Scoring guide (1–5):
  1 = Very poor
  2 = Poor
  3 = Acceptable
  4 = Good
  5 = Excellent

Be strict and technically precise.

Criteria:
- report_alignment: Does the query implement the proposed sources, sinks, and sanitizers from the report?
- codeql_correctness: Check for: correct class names (e.g. `CallNode` not `Call`), correct predicate overrides, correct `@kind path-problem` with 4-argument select and PathGraph import, correct use of `with_structured_output`, proper subclassing patterns.
- coverage: How many of the identified missing sources/sinks/sanitizers are actually covered?
- false_positive_mitigation: Are barriers realistic and well-scoped? Does the query avoid trivial over-approximation?
- metadata_quality: Are all required CodeQL metadata fields present and correct (@name, @description, @id, @kind, @problem.severity, @security-severity, @precision, @tags)?
- overall_quality: Holistic assessment including maintainability and robustness.

Common CodeQL Python API facts to check:
- `DataFlow::Node`, `TaintTracking::AdditionalTaintStep` are the standard taint extension points
- `CallNode` (not `Call`) is the AST class for call expressions
- `AttributeAccess` is correct for attribute access
- `BinaryExpr` is correct for binary operations; `.getOperator()` returns a string
- `StringLiteral` is the correct class for string literals
- `@kind path-problem` requires `import DataFlow::PathGraph` and a 4-argument `select`
- Subclassing a `TaintTracking::Configuration` and overriding `isSource`/`isSink`/`isSanitizer`/`isAdditionalTaintStep` is the standard configuration pattern
- `.toString().matches(...)` is fragile; prefer API-based resolution where possible\
"""

QUERY_HUMAN = """\
Evaluate the generated CodeQL query for {cwe_id}.

## SUGGESTOR REPORT (what the query should implement)
{report_section}

## GENERATED QUERY ({query_file})
```ql
{query_code}
```
"""


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def parse_cwe_sections(report_path: str) -> dict:
    """Split sast_report.md into per-CWE sections keyed by 'CWE-XX'."""
    text = Path(report_path).read_text(encoding="utf-8")
    # Split at each ## CWE-\d+ heading
    parts = re.split(r"(?=^## CWE-\d+)", text, flags=re.MULTILINE)
    sections = {}
    for part in parts:
        m = re.match(r"^## (CWE-\d+)", part.strip())
        if m:
            sections[m.group(1)] = part.strip()
    return sections


def load_queries(queries_dir: str) -> dict:
    """Load .ql files from directory. Returns {cwe_id: (filename, content)}."""
    queries = {}
    for ql_file in sorted(Path(queries_dir).glob("*.ql")):
        m = re.search(r"CWE[_-](\d+)", ql_file.name, re.IGNORECASE)
        if m:
            cwe_id = f"CWE-{m.group(1)}"
            queries[cwe_id] = (ql_file.name, ql_file.read_text(encoding="utf-8"))
    return queries


# ---------------------------------------------------------------------------
# Evaluation helpers
# ---------------------------------------------------------------------------

SCORE_KEYS_SUGGESTOR = [
    "gap_identification", "source_specificity", "sink_specificity",
    "sanitizer_correctness", "actionability", "overall_quality",
]

SCORE_KEYS_QUERY = [
    "report_alignment", "codeql_correctness", "coverage",
    "false_positive_mitigation", "metadata_quality", "overall_quality",
]


def avg_score(ev: dict, keys: list) -> float:
    vals = [ev[k] for k in keys if isinstance(ev.get(k), (int, float))]
    return round(sum(vals) / len(vals), 2) if vals else 0.0


def evaluate_suggestor(llm, cwe_id: str, section: str) -> dict:
    structured = llm.with_structured_output(SuggestorScore)
    result = structured.invoke([
        SystemMessage(content=SUGGESTOR_SYSTEM),
        HumanMessage(content=SUGGESTOR_HUMAN.format(
            cwe_id=cwe_id, report_section=section)),
    ])
    return {"cwe_id": cwe_id, **result.model_dump()}


def evaluate_query(llm, cwe_id: str, section: str, filename: str, code: str) -> dict:
    structured = llm.with_structured_output(QueryScore)
    result = structured.invoke([
        SystemMessage(content=QUERY_SYSTEM),
        HumanMessage(content=QUERY_HUMAN.format(
            cwe_id=cwe_id, report_section=section,
            query_file=filename, query_code=code)),
    ])
    return {"cwe_id": cwe_id, "query_file": filename, **result.model_dump()}


# ---------------------------------------------------------------------------
# Markdown report generation
# ---------------------------------------------------------------------------

def build_markdown(suggestor_evals: list, query_evals: list) -> str:
    lines = ["# SVD Agent — LLM-as-a-Judge Evaluation\n"]

    # --- Suggestor ---
    lines.append("## 1. SuggestorAgent Report Quality\n")
    for ev in suggestor_evals:
        lines.append(f"### {ev['cwe_id']}\n")
        lines.append("| Criterion | Score |")
        lines.append("|-----------|-------|")
        for k in SCORE_KEYS_SUGGESTOR:
            label = k.replace("_", " ").title()
            lines.append(f"| {label} | {ev.get(k, 'N/A')}/5 |")
        a = avg_score(ev, SCORE_KEYS_SUGGESTOR)
        lines.append(f"| **Average** | **{a}/5** |\n")
        lines.append(f"**Reasoning:** {ev.get('reasoning', '')}\n")
        if ev.get("strengths"):
            lines.append("**Strengths:**")
            lines.extend(f"- {s}" for s in ev["strengths"])
            lines.append("")
        if ev.get("weaknesses"):
            lines.append("**Weaknesses:**")
            lines.extend(f"- {w}" for w in ev["weaknesses"])
            lines.append("")

    # --- Queries ---
    lines.append("## 2. CreatorAgent Query Quality\n")
    for ev in query_evals:
        lines.append(f"### {ev['cwe_id']} — `{ev['query_file']}`\n")
        lines.append("| Criterion | Score |")
        lines.append("|-----------|-------|")
        for k in SCORE_KEYS_QUERY:
            label = k.replace("_", " ").title()
            lines.append(f"| {label} | {ev.get(k, 'N/A')}/5 |")
        a = avg_score(ev, SCORE_KEYS_QUERY)
        lines.append(f"| **Average** | **{a}/5** |\n")
        lines.append(f"**Reasoning:** {ev.get('reasoning', '')}\n")
        if ev.get("strengths"):
            lines.append("**Strengths:**")
            lines.extend(f"- {s}" for s in ev["strengths"])
            lines.append("")
        if ev.get("weaknesses"):
            lines.append("**Weaknesses:**")
            lines.extend(f"- {w}" for w in ev["weaknesses"])
            lines.append("")
        if ev.get("technical_issues"):
            lines.append("**Technical Issues:**")
            lines.extend(f"- {t}" for t in ev["technical_issues"])
            lines.append("")

    # --- Summary ---
    lines.append("## 3. Pipeline Summary\n")
    s_avgs = [avg_score(ev, SCORE_KEYS_SUGGESTOR) for ev in suggestor_evals]
    q_avgs = [avg_score(ev, SCORE_KEYS_QUERY) for ev in query_evals]
    s_mean = round(sum(s_avgs) / len(s_avgs), 2) if s_avgs else 0.0
    q_mean = round(sum(q_avgs) / len(q_avgs), 2) if q_avgs else 0.0
    overall = round((s_mean + q_mean) / 2, 2)
    lines.append("| Component | Avg Score (1–5) |")
    lines.append("|-----------|----------------|")
    lines.append(f"| SuggestorAgent Report | {s_mean} |")
    lines.append(f"| CreatorAgent Queries  | {q_mean} |")
    lines.append(f"| **Overall Pipeline**  | **{overall}** |")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="LLM-as-a-Judge evaluation for SVD Agent outputs")
    parser.add_argument("--report", default="sast_report.md",
                        help="Path to sast_report.md (default: sast_report.md)")
    parser.add_argument("--queries_dir", default="generated_queries",
                        help="Directory containing .ql files (default: generated_queries)")
    parser.add_argument("--output", default="eval_results",
                        help="Output file prefix; produces <prefix>.json and <prefix>.md (default: eval_results)")
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help=f"OpenAI model to use as judge (default: {DEFAULT_MODEL})")
    args = parser.parse_args()

    llm = ChatOpenAI(model=args.model, temperature=0)

    # --- Load inputs ---
    print(f"Loading report: {args.report}")
    cwe_sections = parse_cwe_sections(args.report)
    print(f"  Found sections: {list(cwe_sections.keys())}")

    print(f"Loading queries: {args.queries_dir}")
    queries = load_queries(args.queries_dir)
    print(f"  Found queries: {list(queries.keys())}")

    suggestor_evals = []
    query_evals = []

    # --- Evaluate suggestor sections ---
    for cwe_id, section in cwe_sections.items():
        print(f"\n[Suggestor] Evaluating {cwe_id} ...")
        ev = evaluate_suggestor(llm, cwe_id, section)
        suggestor_evals.append(ev)
        print(f"  Average: {avg_score(ev, SCORE_KEYS_SUGGESTOR)}/5")

    # --- Evaluate generated queries ---
    for cwe_id, (filename, code) in queries.items():
        section = cwe_sections.get(cwe_id, "No corresponding report section found.")
        print(f"\n[Query] Evaluating {filename} ...")
        ev = evaluate_query(llm, cwe_id, section, filename, code)
        query_evals.append(ev)
        print(f"  Average: {avg_score(ev, SCORE_KEYS_QUERY)}/5")

    # --- Write outputs ---
    results = {
        "model": args.model,
        "suggestor_evaluations": suggestor_evals,
        "query_evaluations": query_evals,
    }
    json_path = f"{args.output}.json"
    Path(json_path).write_text(
        json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nJSON results  → {json_path}")

    md_path = f"{args.output}.md"
    Path(md_path).write_text(build_markdown(suggestor_evals, query_evals), encoding="utf-8")
    print(f"Markdown report → {md_path}")


if __name__ == "__main__":
    main()
