# Hybrid LLM-CodeQL Multi-Agent Pipeline for Software Vulnerability Detection

This repository contains the code and experiment artefacts for a Master's thesis on augmenting static application security testing with large language models. The project implements a hybrid three-agent architecture that uses LLMs to validate CodeQL findings, analyse coverage gaps, and propose new CodeQL queries rather than replacing CodeQL outright.

The core research question is whether a hybrid LLM-SAST pipeline can improve vulnerability detection quality while preserving the determinism, auditability, and DevSecOps compatibility of a rule-based static analysis tool.

## Thesis Abstract

Software vulnerabilities remain a critical challenge, with tens of thousands of Common Vulnerabilities and Exposures (CVEs) recorded annually. Static analysis tools like CodeQL offer scalable, deterministic detection through pre-determined rule-based queries, but they are limited in contextual reasoning and novel vulnerability patterns, while fully LLM-based approaches raise concerns regarding reproducibility, cost, and integration within established DevSecOps pipelines. This thesis proposes a hybrid three-agent architecture that uses LLMs to augment CodeQL rather than replace it. An Analyzer agent validates CodeQL results through autonomous reasoning on source code, quadrupling CodeQL's F1-score on a labeled Python dataset (0.43 vs 0.11). A Suggestor agent identifies coverage gaps by analysing false negatives and generating structured improvement proposals, and a Creator agent synthesises new CodeQL queries based on these proposals, successfully targeting missing sources, sinks, and taint-propagation steps for CWE-89 and CWE-79. Preliminary LLM-as-judge evaluation confirmed high gap coverage (4-5/5), though generated queries required manual refinement to compile due to syntactic issues (2-3/5 syntactic correctness). These results demonstrate that a hybrid LLM-SAST pipeline can substantially augment static analysis through contextual reasoning, while preserving the determinism and integration properties essential for production use.

## Research Contribution

The pipeline is organized into three agents:

1. `AnalyzerAgent`
   Runs CodeQL on a vulnerable Python dataset, parses SARIF output, and performs LLM-based validation of findings against source code context.

2. `SuggestorAgent`
   Examines false negatives and existing CodeQL coverage to produce structured proposals describing missing sources, sinks, sanitizers, and taint steps.

3. `CreatorAgent`
   Converts these proposals into candidate `.ql` queries and attempts compilation with the local CodeQL CLI.

This architecture is designed to keep CodeQL as the deterministic execution engine while using LLMs where contextual reasoning is most useful: validating noisy findings, diagnosing coverage gaps, and drafting query extensions.

## Repository Contents

Key directories and files:

- `main.py`: entry point for the end-to-end workflow.
- `agents_dir/`: agent implementations, orchestrator, and config.
- `tools.py`: tool layer for SARIF parsing, web search, and query writing.
- `data/`: labeled Python benchmark used by the pipeline.
- `generated_queries/`: output directory for queries produced by the Creator agent.
- `results/`: outputs from the most recent local workflow run.
- `GPT5.2_RESULTS/`: archived thesis-relevant outputs for the GPT-5.2 experiment snapshot.
- `evaluation/`: LLM-as-judge evaluation scripts and generated evaluation reports.
- `requirements.txt`: Python dependencies.
- `agent_memory.json`: shared-memory snapshot persisted across the workflow.

## Dataset

The checked-in benchmark in `data/` contains 27 vulnerable Python files labeled with ground truth in `data/ground_truth.json`:

- `CWE-78`: 7 files
- `CWE-89`: 10 files
- `CWE-79`: 10 files

`data/metadata.csv` maps the shortened dataset filenames used in this repository to their original project-relative paths used during evaluation and reporting.

## Pipeline Overview

### 1. Analyzer Stage

The analyzer:

- builds a CodeQL database over the dataset,
- runs the Python security query suite,
- parses the SARIF output into a structured JSON form,
- normalizes findings to CWE-level predictions,
- compares the LLM-validated report against ground truth and raw CodeQL results,
- writes evaluation artefacts such as:
  - `results/codeql_report.json`
  - `results/agent_report.json`
  - `results/comparison.json`
  - `results/metrics.json`

### 2. Suggestor Stage

The suggestor:

- reads the analyzer gap analysis,
- focuses on the most relevant false-negative CWEs,
- inspects existing CodeQL queries from the local CodeQL Python query pack,
- optionally uses targeted web search for CodeQL or API context,
- writes a structured proposal report to `sast_report.md`.

### 3. Creator Stage

The creator:

- reads the Suggestor report,
- generates one candidate CodeQL query per target CWE,
- saves the query in `generated_queries/`,
- creates a local `qlpack.yml` if needed,
- attempts `codeql query compile --check-only` validation.

## Thesis Results

The thesis-relevant output snapshot is stored in `GPT5.2_RESULTS/`.

### Analyzer Results

From [metrics.json](/Users/rebeccaderosa/Desktop/SVD_agent/GPT5.2_RESULTS/Analyzer/metrics.json):

| System | Precision | Recall | F1 |
|--------|-----------|--------|----|
| Analyzer agent | 0.667 | 0.320 | 0.432 |
| Baseline CodeQL | 0.167 | 0.080 | 0.108 |

This corresponds to an approximately 4x F1 improvement over baseline CodeQL on the labeled benchmark.

Related archived files:

- [agent_report.json](/Users/rebeccaderosa/Desktop/SVD_agent/GPT5.2_RESULTS/Analyzer/agent_report.json)
- [codeql_report.json](/Users/rebeccaderosa/Desktop/SVD_agent/GPT5.2_RESULTS/Analyzer/codeql_report.json)
- [comparison.json](/Users/rebeccaderosa/Desktop/SVD_agent/GPT5.2_RESULTS/Analyzer/comparison.json)
- [ground_truth.json](/Users/rebeccaderosa/Desktop/SVD_agent/GPT5.2_RESULTS/Analyzer/ground_truth.json)

### Suggestor and Creator Evaluation

From [eval_results.md](/Users/rebeccaderosa/Desktop/SVD_agent/GPT5.2_RESULTS/eval_results.md):

- SuggestorAgent average quality: `4.78 / 5`
- CreatorAgent query quality: `3.0 / 5`
- Overall pipeline score: `3.89 / 5`

Per-CWE highlights:

- `CWE-89` Suggestor quality: `5.0 / 5`
- `CWE-79` Suggestor quality: `4.83 / 5`
- `CWE-78` Suggestor quality: `4.5 / 5`
- `CWE-89` generated query quality: `4.5 / 5`
- `CWE-79` generated query quality: `3.5 / 5`
- `CWE-78` generated query quality: `1.0 / 5`

Archived thesis artefacts:

- [sast_report-2.md](/Users/rebeccaderosa/Desktop/SVD_agent/GPT5.2_RESULTS/Suggestor/sast_report-2.md)
- [CWE_78_failed-2.ql](/Users/rebeccaderosa/Desktop/SVD_agent/GPT5.2_RESULTS/Creator/CWE_78_failed-2.ql)
- [CWE_79_failed-3.ql](/Users/rebeccaderosa/Desktop/SVD_agent/GPT5.2_RESULTS/Creator/CWE_79_failed-3.ql)
- [CWE_89_failed-3.ql](/Users/rebeccaderosa/Desktop/SVD_agent/GPT5.2_RESULTS/Creator/CWE_89_failed-3.ql)
- [eval_results.json](/Users/rebeccaderosa/Desktop/SVD_agent/GPT5.2_RESULTS/eval_results.json)

## Requirements

### System Requirements

- Python 3.10+ recommended
- CodeQL CLI installed and available as `codeql`
- Access to the CodeQL Python query pack
- OpenAI API key for the LLM-driven agents

### Python Dependencies

Install the Python requirements from `requirements.txt`:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## CodeQL Setup

The project expects a local CodeQL installation and a Python query pack. The current configuration points to:

```text
~/.codeql/packages/codeql/python-queries/1.6.8/Security
```

and, in `config.py`, to:

```text
~/.codeql/packages/codeql/python-queries/1.6.8/codeql-suites/python-security-and-quality.qls
```

If your local CodeQL package version differs, update:

- [agents_dir/config.yaml](/Users/rebeccaderosa/Desktop/SVD_agent/agents_dir/config.yaml)
- [config.py](/Users/rebeccaderosa/Desktop/SVD_agent/config.py)

You may need to install the standard Python queries with:

```bash
codeql pack install codeql/python-queries
```

## Environment Variables

Create a `.env` file in the project root with at least:

```env
OPENAI_KEY=your_api_key_here
```

The evaluation script also maps `OPENAI_KEY` to `OPENAI_API_KEY` automatically if needed.

## How to Run

Run the full workflow:

```bash
python3 main.py --dataset_path data --memory_path agent_memory.json
```

Arguments:

- `--dataset_path`: dataset root to analyze. Defaults to `data/`.
- `--memory_path`: output path for the shared-memory JSON snapshot. Defaults to `agent_memory.json`.

The workflow:

1. runs CodeQL analysis,
2. validates findings with the Analyzer agent,
3. computes gap analysis against the ground truth,
4. generates a Suggestor report,
5. generates candidate CodeQL queries.

## Main Outputs

After a workflow run, the most important outputs are:

- `results/metrics.json`: compact agent vs CodeQL metrics.
- `results/comparison.json`: file-by-file comparison against ground truth.
- `results/agent_report.json`: validated Analyzer findings.
- `results/codeql_report.json`: normalized baseline CodeQL findings.
- `sast_report.md`: Suggestor output report.
- `generated_queries/*.ql`: candidate queries produced by the Creator.
- `agent_memory.json`: serialized shared-memory trace.

## Evaluation

The repository includes an LLM-as-judge evaluator in [evaluate.py](/Users/rebeccaderosa/Desktop/SVD_agent/evaluation/evaluate.py).

Run it from the repository root:

```bash
python3 evaluation/evaluate.py
```

Example with explicit paths:

```bash
python3 evaluation/evaluate.py \
  --report sast_report.md \
  --queries_dir generated_queries \
  --output eval_results
```

This evaluates:

- the quality of the Suggestor report,
- the alignment and technical correctness of generated CodeQL queries.

## Reproducibility Notes

This repository mixes code, local run outputs, and archived thesis artefacts. For thesis reporting:

- use `GPT5.2_RESULTS/` as the reference snapshot,
- treat `results/` as local run output,
- treat `generated_queries/` as mutable experimental output.

Because the pipeline depends on LLM calls, exact outputs can vary between runs, models, and prompt versions. Query compilation outcomes also depend on the installed local CodeQL version and available packages.

## Limitations

- The Creator agent can generate syntactically imperfect CodeQL that still requires manual refinement.
- Query pack paths are currently version-specific and may need local adjustment.
- The pipeline is currently tailored to Python and the supplied benchmark.
- Evaluation includes an LLM-as-judge component, so some assessments are model-dependent.

## Future Work

Natural next steps for extending this thesis codebase include:

- improving Creator-side CodeQL syntax robustness,
- adding automated repair loops for failed compilations,
- expanding to additional CWEs and larger datasets,
- integrating the pipeline more directly into CI or DevSecOps workflows,
- comparing different frontier LLMs under the same benchmark and prompts.

## Citation

If you use this repository in academic work, cite the corresponding Master's thesis and reference this repository as the implementation artefact.
