"""
Module that defines the Analyzer ReAct agent. It calls the CodeQL SAST tool for a preliminary scan
of the source code. Later, it validate the results of the tool and returns a report containing 
all the necessary information about each vulnerability found. 

Principal class:
    - AnalyzerAgent: ReAct agent that executes CodeQL analysis, SARIF parsing and generates enriched report with validation audits.

Main methods:
    - run_analysis: executes the CodeQL analysis, SARIF parsing based on the given task and reasoning.
    - step: execute eache single step of the ReAct cycle.
    - load_existing_queries: loads existing CodeQL queries for one CWE from the local CodeQL packet.
"""

from tools import ParseSarifTool
from agents_dir.base_agent import BaseAgent, ReActChain, SharedMemory, BaseTaskInput
from pydantic import BaseModel, Field

from procedures.summ_procedure import SummaryProcedure
from procedures.action_procedure import ActionProcedure
from procedures.tought_procedure import ThoughtProcedure
from prompts import SUMMARY_TEMPLATE, THOUGHT_TEMPLATE, ACTION_TEMPLATE
from typing import List, Optional, Dict

import json
import os
import time
from pathlib import Path

class VulnerabilityModel(BaseModel):
    """
    Unified format for representing vulnerabilities, used both for CodeQL and Agent reports.

    Attributes:
        cwe (str): CWE ID.
        cwe_description (str): brief description of the vulnerability.
        line (int): crash location.
    """
    cwe: str = Field(...)
    cwe_description: str = Field(...)
    line: int = Field(...)

class UnifiedReportModel(BaseModel):
    """
    Unified report format for both CodeQL and Agent results.
    
    Attributes:
        filename (str): relative path to the analyzed file.
        vulnerabilities (List[VulnerabilityModel]): list of detected vulnerabilities found.
        source (str): detection source ("CodeQL" or "Agent").
    """
    filename: str = Field(...)
    vulnerabilities: List[VulnerabilityModel] = Field(default_factory=list)
    source: str = Field(...)


class CodeQLAnalyzerInput(BaseTaskInput):
    """
    Input for the CodeQL analysis tool.
    
    Attributes:
        source_root (str): Path to the source code file.
    
    """

    source_root: str = Field(...)
       
class CWEMappingModel(BaseModel):
    """
    Pydantic model for mapping Rule ID -> CWE through LLM.
    
    Attributes:
        cwe (str): CWE ID
        description (str): brief description of the vulnerability

    """
    cwe: str = Field(...)
    description: str = Field(...)


class AnalyzerAgent(BaseAgent):
    """ReAct Agent that executes CodeQL analysis, SARIF parsing and generates enriched report with its validation audits about the report.
    
    Args:
       prompt_template (str): the prompt containing the system instructions for the agent.
       shared_memory (SharedMemory): shared memory for the agent.
       tools (list): list of tools available to the agent.
       logpath (str | None): optional path for logging.
    
    Attributes:
        prompt_template (str): the prompt containing the system instructions for the agent.
        shared_memory (SharedMemory): shared memory for the agent.
        tools (list): list of tools available to the agent.
        logpath (str | None): optional path for logging.
        summ_procedure (SummaryProcedure): procedure for generating summaries.
        thought_procedure (ThoughtProcedure): procedure for generating thoughts.
        action_procedure (ActionProcedure): procedure for generating actions.
        max_steps (int): maximum number of steps for the ReAct cycle.
    
    Methods:
        run_analysis(task): executes the CodeQL analysis, SARIF parsing based on the given task and reasoning.
        add_cwe(report): adds cwe related to the reul_id.
        step(observation): execute eache single step of the ReAct cycle.
        load_existing_queries(cwe): loads existing CodeQL queries for one CWE from the local CodeQL packet.

    """

    def __init__(self, prompt_template: str, shared_memory: SharedMemory, tools: list, logpath: str=None, config: dict = None):
        """
        AnalyzerAgent's constructor.
        It initializes the base agent with the provided prompt, memory, tools, and logpath.
        
        Args:
            prompt_template (str): the prompt template that will be formatted and used as input to the LLM.
            shared_memory (SharedMemory): shared memory for the agent.
            tools (list): list of tools available to the agent.
            logpath (str | None): optional path for logging.  
        """
        super().__init__(prompt_template=prompt_template, shared_memory=shared_memory, tools=tools, logpath=logpath)
        
        self.summ_procedure=SummaryProcedure(self.llm, SUMMARY_TEMPLATE)
        self.thought_procedure=ThoughtProcedure(self.llm, THOUGHT_TEMPLATE)
        self.action_procedure = ActionProcedure(self.llm, ACTION_TEMPLATE)

        self.max_steps=20   
        self.max_context_steps = 8

        self.config = config or {}
        self.query_pack_path = self.config.get(
            "query_pack_path",
            Path.home() / ".codeql/packages/codeql/python-queries/1.6.8/Security"
        )

        self.metadata_csv_path = self.config.get(
            "metadata_csv_path",
            "data/metadata.csv"
        )
        raw_sarif = self.config.get("sarif_path", "python.sarif")
        self.sarif_path = str(Path(raw_sarif).expanduser()) if Path(raw_sarif).is_absolute() \
            else str(Path(__file__).parent.parent / raw_sarif)

    def normalize_dataset_path(self, path: str, mapping: dict, dataset_label: Optional[str] = None) -> str:
        """
        Normalize dataset paths to match ground truth format.

        Examples:
            - Input: "01__general.py"
            - Output: "django/contrib/postgres/aggregates/general.py"

        Args:
            path (str): original file path from the dataset.
            mapping (dict): mapping from metatdata.csv {finename: new_path}.
            dataset_label: optional prefix for multi-dataset support.
        """

        base = os.path.basename(path)
       
        if "__" in base:
            base = base.split("__", 1)[1]
        normalized = mapping.get(base, base)
        if dataset_label:
            return f"{dataset_label}/{normalized}"
        return normalized


    def build_filename(self, csv_path: str) -> dict:
        """
        Create mapping: filename -> new_path from the metadata CSV.
        
        Example: "general.py" -> "django/contrib/postgres/aggregates/general.py"

        Args:
            csv_path (str): path to the metadata CSV file.
        
        Returns: 
            dict: mapping of filename to new_path.
        """

        import pandas as pd

        if not os.path.exists(csv_path):
            print(f"WARNING: Metadata CSV not found at {csv_path}, using empty mapping")
            return {}
        
        df = pd.read_csv(csv_path)
        return {row["filename"]: row["new_path"] for _, row in df.iterrows()}


    def normalize_cwe(self, cwe: str) -> str:
        """
        Normalize CWE format to avoid mismatches:
        - CWE-020 → CWE-20
        - cwe-089 → CWE-89
        - CWE-0079 → CWE-79
        
        Args:
            cwe: raw CWE string
        
        Returns:
            normalized CWE string
        """
        if not cwe:
            return ""
    
        cwe = cwe.upper()
        if cwe.startswith("CWE-"):
            # Remove leading zeros: CWE-020 → CWE-20
            num = cwe[4:].lstrip("0") or "0"
            return f"CWE-{num}"
        
        return cwe

    def compute_metrics(self, ground_truth: Dict[str, List[str]], agent_report: Dict[str, UnifiedReportModel],
                        codeql_report: Dict[str, UnifiedReportModel]) -> dict:
        """
        Compute compact metrics for agent and CodeQL:
        tp, fp, fn, precision, recall, f1.
        """
        def extract_cwes(report_model: UnifiedReportModel) -> set:
            return {self.normalize_cwe(v.cwe) for v in report_model.vulnerabilities}

        def comp_metr(gt_dict: Dict[str, List[str]], report_dict: Dict[str, UnifiedReportModel]) -> dict:
            tp = 0
            fp = 0
            fn = 0

            for filename, gt_cwes in gt_dict.items():
                gt_set = {self.normalize_cwe(c) for c in (gt_cwes or [])}
                pred_set = extract_cwes(report_dict[filename]) if filename in report_dict else set()

                tp += len(gt_set & pred_set)
                fp += len(pred_set - gt_set)
                fn += len(gt_set - pred_set)

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

            return {
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "precision": precision,
                "recall": recall,
                "f1": f1,
            }

        return {
            "agent": comp_metr(ground_truth, agent_report),
            "codeql": comp_metr(ground_truth, codeql_report),
        }
    
    def compute_metrics_per_cwe(
        self,
        ground_truth: Dict[str, List[str]],
        agent_report: Dict[str, UnifiedReportModel],
        codeql_report: Dict[str, UnifiedReportModel],
    ) -> dict:
        """Compute precision, recall, F1 broken down by CWE category."""

        def extract_cwes(report_model: UnifiedReportModel) -> set:
            return {self.normalize_cwe(v.cwe) for v in report_model.vulnerabilities}

        all_cwes = set()
        for cwes in ground_truth.values():
            for c in (cwes or []):
                all_cwes.add(self.normalize_cwe(c))

        def per_cwe(gt_dict: Dict[str, List[str]], report_dict: Dict[str, UnifiedReportModel]) -> dict:
            metrics = {}
            for target_cwe in sorted(all_cwes):
                tp = fp = fn = 0
                for filename, gt_cwes in gt_dict.items():
                    gt_set = {self.normalize_cwe(c) for c in (gt_cwes or [])}
                    pred_set = extract_cwes(report_dict[filename]) if filename in report_dict else set()
                    gt_has, pred_has = target_cwe in gt_set, target_cwe in pred_set
                    if gt_has and pred_has:
                        tp += 1
                    elif pred_has:
                        fp += 1
                    elif gt_has:
                        fn += 1

                prec = tp / (tp + fp) if (tp + fp) else 0.0
                rec = tp / (tp + fn) if (tp + fn) else 0.0
                f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
                metrics[target_cwe] = {
                    "tp": tp,
                    "fp": fp,
                    "fn": fn,
                    "precision": round(prec, 4),
                    "recall": round(rec, 4),
                    "f1": round(f1, 4),
                    "support": tp + fn,
                }
            return metrics

        return {
            "agent": per_cwe(ground_truth, agent_report),
            "codeql": per_cwe(ground_truth, codeql_report),
        }

    def confusion_matrix(self, results: dict, label: str = "Confusion Matrix metrics") -> None:
        """
        Print confusion matrix metrics in tabular format.
        Works for both overall metrics and per-CWE metrics.

        Args:
            results: output from compute_metrics() or compute_metrics_per_cwe()
            label: header label for the table
        """
        import pandas as pd

        rows = []
        for tool in ["agent", "codeql"]:
            data = results[tool]
            if isinstance(data, dict) and "tp" in data:
                # Overall metrics: {"tp": ..., "fp": ..., ...}
                rows.append({
                    "Tool": tool.capitalize(),
                    "TP": data["tp"],
                    "FP": data["fp"],
                    "FN": data["fn"],
                    "Precision": f"{data['precision']:.4f}",
                    "Recall": f"{data['recall']:.4f}",
                    "F1-score": f"{data['f1']:.4f}",
                })
            else:
                # Per-CWE metrics: {"CWE-79": {"tp": ..., ...}, ...}
                for cwe, m in data.items():
                    rows.append({
                        "Tool": tool.capitalize(),
                        "CWE": cwe,
                        "Support": m["support"],
                        "TP": m["tp"],
                        "FP": m["fp"],
                        "FN": m["fn"],
                        "Precision": f"{m['precision']:.4f}",
                        "Recall": f"{m['recall']:.4f}",
                        "F1-score": f"{m['f1']:.4f}",
                    })

        df = pd.DataFrame(rows)
        print(f"\n{label}:")
        print(df.to_string(index=False))


    def load_gt(self, json_path: str) -> Dict[str, List[str]]:
        """
        Load ground truth with CWE for each file.
        
        Args:
            json_path : path to ground truth file.

        Retruns:
            dict: {
                "vulnerable/file1.py": ["CWE-089", "-079"],
                "vulnerable/file2.py": ["CWE-089"],
                ...
            }
        """
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        gt_mapping = {}
        for i in data:
            path = i.get("path")
            cwe = i.get("cwe_id")

            if isinstance(cwe, str):
                cwe = [cwe]
            elif cwe is None:
                cwe = []

            gt_mapping[path] = cwe

        return gt_mapping

    def step(self, observation: str) -> ReActChain:
        """
        Execute eache single step of the ReAct cycle.
        
        The cycle includes:
            1. memory update
            2. summary generation
            3. reasoning (thought)
            4. selection/creation next action
            5. existing CodeQL queries integration as inspiration
        
        Args: 
            observation (str): new observation to process
        
        Returns:
            ReActChain: updated chain containing summary, thought and action.

        """

        self.update_memory(observation)

        scratchpad = self.shared_memory.to_messages(last=self.max_context_steps)
        instructions = self.prompt_template 

        summary_out = self.summ_procedure.run(instructions, scratchpad)
        summary = summary_out.summary

        thought_out =self.thought_procedure.run(summary, scratchpad, self.last_step)
        thought = thought_out.thought
        
        action_out = self.action_procedure.run(summary, scratchpad, self.last_step, thought, self.tools)
        action = action_out.action
    
        self.last_step = ReActChain.format(summary=summary, thought=thought, action=action)

        return self.last_step

    def run_analysis(self, task: CodeQLAnalyzerInput, gt_json_path: str, dataset_label: str = "cwefixes",
                     output_dir: str = "results") -> dict:
        """
        Execute the entire workflow and return comparable reports.

        Args:
            task: CodeQLAnalyzerInput with paths.
            gt_json_path: path to the ground truth JSON file.
            dataset_label: label for dataset normalization
            output_dir: directory to save the results.

        Returns:
            dict with all results and metrics.
            }
        """
    
        self.mapping = self.build_filename(self.metadata_csv_path)

        gt_raw = self.load_gt(gt_json_path)
        gt = {}
        for path, cwes in gt_raw.items():
            normalized_path = self.normalize_dataset_path(path, self.mapping, dataset_label)
            gt[normalized_path] = cwes

        print("\nStep 1: CodeQL scan...")
        codeql_results = {}
        if os.path.exists(self.sarif_path):
            try:
                parse_tool = ParseSarifTool(sarif_filepath=self.sarif_path)
                sarif_parsed = json.loads(parse_tool.run())
                codeql_results = self.unify_format(sarif_parsed)
            except json.JSONDecodeError as e:
                print(f"Warning: invalid SARIF JSON at {self.sarif_path}: {e}")
            except Exception as e:
                print(f"Warning: CodeQL parsing skipped ({self.sarif_path}): {e}")
        else:
            print(f"Warning: SARIF file not found at {self.sarif_path}. Skipping CodeQL baseline.")

        codeql_norm = {}
        for path, data in codeql_results.items():
            normalized_path = self.normalize_dataset_path(path, self.mapping, dataset_label)
            codeql_norm[normalized_path] = data
        # codeql_norm: {
        #   "general.py" -> UnifiedReportModel(
        #       filename="general.py",
        #       vulnerabilities=[VulnerabilityModel(cwe="CWE-89", cwe_description="No desciption", line=42)],
        #       source="codeql"
        #   ), ... }
       
        print("\nStep 2: Analyzer agent scan...")
        agent_start = time.perf_counter()
        agent_results = self.run_agent(task)
        agent_elapsed = time.perf_counter() - agent_start
        print(f"Agent phase completed in {agent_elapsed:.3f}s")

        agent_norm = {}
        for path, data in agent_results.items():
            normalized_path = self.normalize_dataset_path(path, self.mapping, dataset_label)
            agent_norm[normalized_path] = data
        # agent_norm: {
        #   "general.py" -> UnifiedReportModel(
        #       filename="general.py",
        #       vulnerabilities=[
        #       VulnerabilityModel(cwe="CWE-89", cwe_description="SQL injection in raw query", line=42)
        #       ],
        #       source="agent"
        #       ), ...
        # }

        print("Step 3: Computing metrics...")
        metrics = self.compute_metrics(gt, agent_norm, codeql_norm)
        # metrics: {
        #   "agent": {
        #         "tp": tp,
        #         "fp": fp,
        #         "tn": tn,
        #         "precision": precision,
        #         "recall": recall,
        #         "f1": f1,
        #    }, 
        #   "codeql": {
        #         "tp": tp,
        #         "fp": fp,
        #         "tn": tn,
        #         "precision": precision,
        #         "recall": recall,
        #         "f1": f1,}
        #   }
        
        self.confusion_matrix(metrics)

        per_cwe = self.compute_metrics_per_cwe(gt, agent_norm, codeql_norm)
        self.confusion_matrix(per_cwe, label="Per-CWE Metrics")

        print("\nMacro-average F1 (mean of per-CWE F1):")
        for tool in ["agent", "codeql"]:
            f1_scores = [m["f1"] for m in per_cwe[tool].values()]
            macro_f1 = sum(f1_scores) / len(f1_scores) if f1_scores else 0.0
            print(f"  {tool.capitalize()}: {macro_f1:.4f}")

        comparison = self.compare_results(agent_norm, codeql_norm, gt)
        # comparison: {
        #   "file_by_file": [
        #     {
        #       "filename": "cwefixes/django/contrib/postgres/aggregates/general.py",
        #       "ground_truth_cwes": ["CWE-79", "CWE-89"],
        #       "agent_cwes": ["CWE-79", "CWE-89"],
        #       "codeql_cwes": ["CWE-79"],
        #       "agent_status": "exact_match",
        #       "codeql_status": "partial_match",
        #       "agent_correct_cwes": ["CWE-79", "CWE-89"],
        #       "codeql_correct_cwes": ["CWE-79"],
        #       "agreement": false
        #     },
        #     {
        #       "filename": "cwefixes/flask/app.py",
        #       "ground_truth_cwes": ["CWE-22"],
        #       "agent_cwes": [],
        #       "codeql_cwes": ["CWE-22"],
        #       "agent_status": "missed",
        #       "codeql_status": "exact_match",
        #       "agent_correct_cwes": [],
        #       "codeql_correct_cwes": ["CWE-22"],
        #       "agreement": false
        #     },
        #     {
        #       "filename": "cwefixes/api/views.py",
        #       "ground_truth_cwes": ["CWE-89"],
        #       "agent_cwes": ["CWE-89"],
        #       "codeql_cwes": ["CWE-89"],
        #       "agent_status": "exact_match",
        #       "codeql_status": "exact_match",
        #       "agent_correct_cwes": ["CWE-89"],
        #       "codeql_correct_cwes": ["CWE-89"],
        #       "agreement": true
        #     }
        #   ],
        #   "summary": {
        #     "total_files": 3,
        #     "exact_agree": 1,
        #     "agree_rate": 0.3333333333,
        #     "both_correct": 1,
        #     "both_correct_rate": 0.3333333333
        #   }
        # }

        timings = {
            "agent_seconds": round(agent_elapsed, 3),
        }
        print(f"Agent scan time: {agent_elapsed:.3f}s")

        results = {
            "ground_truth": gt, 
            "agent": {k: v.model_dump() for k,v in agent_norm.items()},
            "codeql": {k: v.model_dump() for k,v in codeql_norm.items()},
            "metrics": metrics,
            "comparison": comparison,
            "timings": timings,
        }

        self.save_results(results, output_dir)
        return results


    # ha come input il dataset
    def run_agent(self, task: CodeQLAnalyzerInput) -> Dict[str, UnifiedReportModel]:
        """
        Execute the scan of the Agent on each file.
        
        Args:
            task: CodeQLAnalyzerInput with source_root

        Returns:
            Dict[str, UnifiedReportModel]: filename -> UnifiedReportModel with agent results.
        """
        source_root = Path(task.source_root)
        files = list(source_root.rglob("*.py"))

        results = []
        shared_memory_ref = self.shared_memory

        for file_path in files:
            # Strict per-file isolation: each scan gets an empty ephemeral memory.
            self.shared_memory = SharedMemory()
            self.reset(task)

            relative_path = file_path.relative_to(source_root)
            filename = str(relative_path)
            print(f"\nScanning of {filename}...")

            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception as e:
                print(f"Error in reading the file {file_path.name}: {e}")
                results.append(UnifiedReportModel(
                    filename=filename,
                    vulnerabilities=[],
                    source="agent"
                ))
                continue
        
            frameworks = []
            cl = content.lower()
            if "from flask" in cl or "import flask" in cl: frameworks.append("Flask")
            if "from django" in cl or "import django" in cl: frameworks.append("Django")
            if "cursor.execute" in cl: frameworks.append("Raw SQL")
            if "os.path" in cl or "open(" in cl: frameworks.append("File I/O")
            fw_hint = ", ".join(frameworks) if frameworks else "Unknown"

            analysis_context = {
               "instruction": (
                    f"Perform a COMPLETE security audit of '{filename}'. "
                    f"Detected context: {fw_hint}. "
                    "Map ALL user inputs (sources) and ALL dangerous operations (sinks). "
                    "Trace every dataflow. Report ALL vulnerabilities found — "
                    "a file may have MULTIPLE issues, even of the same CWE type. "
                    "Use the most specific CWE (avoid CWE-20, CWE-74 when a child CWE fits)."
                ),
                "target_file": filename,
                "full_file": content
            }

            last_observation = f"New scan task: {json.dumps(analysis_context, indent=2)}"

            result = None
            for step in range(self.max_steps):
                current_reasoning = self.step(last_observation)
                current_action = current_reasoning.action

                print(f"Agent thought: {current_reasoning.thought}\n")
                print(f"Agent action: {current_action}\n")


                if not current_action:
                    last_observation = (
                        "Error: no action decided. Review the file: "
                        "1) List all user inputs, 2) List all dangerous sinks, "
                        "3) Check which inputs reach sinks without sanitization, "
                        "4) Report findings using FinishTool."
                    )
                    self.update_memory(last_observation)
                    continue

                action_name = current_action.__class__.__name__
                if action_name == "FinishTool":
                    final_report = current_action.final_report

                    if hasattr(final_report, "model_dump"):
                        final_report_dict = final_report.model_dump()
                    elif isinstance(final_report, dict):
                        final_report_dict = final_report
                    else:
                        final_report_dict = dict(final_report)

                    vulnerabilities = final_report_dict.get("vulnerabilities", [])

                    vuln_models = []
                    for v in vulnerabilities:
                        if isinstance(v, dict):
                            vuln_models.append(VulnerabilityModel(
                                cwe=v.get("cwe", "CWE-000"),
                                cwe_description=v.get("cwe_description", "No descriprtion"),
                                line=v.get("line", 0)
                            ))
                        else:
                            vuln_models.append(v)
                        
                    result = UnifiedReportModel(
                        filename=filename,
                        vulnerabilities=vuln_models,
                        source="agent"
                    )

                    is_vuln = len(vuln_models) > 0
                    print(f"Verdict: {'VULNERABLE' if is_vuln else 'NOT VULNERABLE'} | Found {len(vuln_models)} issues.")
                    break
            
                last_observation = (
                    f"Step {step+1} complete. If you've finished analysis, use FinishTool. "
                    f"Otherwise: have you checked ALL sources and ALL sinks in '{filename}'?"
                )
                
            if result is None:
                result = UnifiedReportModel(
                    filename=filename,
                    vulnerabilities=[],
                    source="agent"
                )
           
            results.append(result)

        # Restore cross-agent shared memory without analyzer scratchpad residue.
        self.shared_memory = shared_memory_ref
        results_dict = {r.filename: r for r in results}
        return results_dict


    # il sarif_data è tipicamente così:
    # [
    #   {
    #   "rule_id": "py/sql-injection",
    #   "cwe": ["CWE-89"],
    #   "message": "Possible SQL injection",
    #   "locations": [{"uri": "01__general.py", "line": 42}]
    #   }, ...,
    # ]
    def unify_format(self, sarif_data: List[dict]) -> Dict[str, UnifiedReportModel]:
        """
        Convert SARIF data to unified report format.
        
        Args:
            sarif_data: parsed SARIF data.

        Returns:
            Dict[str, UnifiedReportModel]: filename -> UnifiedReportModel.
        """
        report = {}

        for item in sarif_data:
            raw_cwe = item.get("cwe")
            if isinstance(raw_cwe, list):
                cwes = [str(c).strip() for c in raw_cwe if str(c).strip()]
            elif isinstance(raw_cwe, str) and raw_cwe.strip():
                cwes = [raw_cwe.strip()]
            else:
                cwes = ["CWE-Unknown"]

            cwe_description = item.get("cwe_description", "No desciption")

            for loc in item.get("locations", []):
                filename = loc.get("uri")
                line = loc.get("line", 0)

                if not filename:
                    continue
        
                if filename not in report:
                    report[filename] = UnifiedReportModel(
                        filename=filename,
                        vulnerabilities=[],
                        source="codeql"
                    )

                for cwe in cwes:
                    vuln_model = VulnerabilityModel(
                        cwe=cwe,
                        cwe_description=cwe_description,
                        line=line,
                    )
                    report[filename].vulnerabilities.append(vuln_model)

        for filename in report:
            seen = set()
            unique_vulns = []
            for v in report[filename].vulnerabilities:
                key = (v.cwe, v.line)
                if key not in seen:
                    seen.add(key)
                    unique_vulns.append(v)
            
            report[filename].vulnerabilities = sorted(unique_vulns, key=lambda x:x.line)

        return report
                
    def compare_results(self, agent_res: Dict[str, UnifiedReportModel],
                         codeql_res: Dict[str, UnifiedReportModel], ground_truth: Dict[str, List[str]]) -> dict:
        """
        Compare the results of the Agent and CodeQL with the ground truth.

        Args:
            agent_res: agent results (filename -> UnifiedReportModel).
            codeql_res: CodeQL results (filename -> UnifiedReportModel).
            ground_truth: ground truth mapping (filename -> list of CWEs).
        
        Returns:
            dict with detailed comparison
        """

        file_comparison = []

        for filename, gt_cwes in ground_truth.items():
            
            agent_cwes = set()
            if filename in agent_res:
                agent_cwes = {self.normalize_cwe(v.cwe) for v in agent_res[filename].vulnerabilities}
            
            codeql_cwes = set()
            if filename in codeql_res:
                codeql_cwes = {self.normalize_cwe(v.cwe) for v in codeql_res[filename].vulnerabilities}
            
            gt_set = {self.normalize_cwe(c) for c in (gt_cwes or [])}

            agent_correct = gt_set == agent_cwes if agent_cwes else False
            agent_partial = bool(gt_set & agent_cwes) and gt_set != agent_cwes

            codeql_correct = gt_set == codeql_cwes if codeql_cwes else False
            codeql_partial = bool(gt_set & codeql_cwes) and gt_set != codeql_cwes

            file_comparison.append({
                "filename": filename, 
                "ground_truth_cwes": sorted(gt_set),
                "agent_cwes": sorted(agent_cwes),
                "codeql_cwes": sorted(codeql_cwes),
                "agent_status": "exact_match" if agent_correct else ("partial_match" if agent_partial else ("missed" if not agent_cwes else "wrong")),
                "codeql_status": "exact_match" if codeql_correct else ("partial_match" if codeql_partial else ("missed" if not codeql_cwes else "wrong")),
                "agent_correct_cwes": sorted(gt_set & agent_cwes),
                "codeql_correct_cwes": sorted(gt_set & codeql_cwes),
                "agreement": agent_cwes == codeql_cwes
            })

        exact_agree = sum(1 for f in file_comparison if f["agent_cwes"] == f["codeql_cwes"])
        both = sum(1 for f in file_comparison if f["agent_status"] == "exact_match" and f["codeql_status"] == "exact_match")

        return {
            "file_by_file": file_comparison,
            "summary": {
                "total_files": len(file_comparison),
                "exact_agree": exact_agree,
                "agree_rate": exact_agree / len(file_comparison) if file_comparison else 0,
                "both_correct": both,
                "both_correct_rate": both / len(file_comparison) if file_comparison else 0,
            }
        }


    def save_results(self, results: dict, output_dir: str = "results") -> None:
        """
        Save all results to JSON files.
        Args:
            results: results dictionary from run_analysis().
            output_dir: the directory where the results will be saved.
        """


        with open(f"{output_dir}/agent_report.json", "w") as f:
            json.dump(results["agent"], f, indent=2)
        
        with open(f"{output_dir}/codeql_report.json", "w") as f:
            json.dump(results["codeql"], f, indent=2)
        
        with open(f"{output_dir}/metrics.json", "w") as f:
            json.dump(results["metrics"], f, indent=2)
        
        with open(f"{output_dir}/comparison.json", "w") as f:
            json.dump(results["comparison"], f, indent=2)

        with open(f"{output_dir}/ground_truth.json", "w") as f:
            json.dump(results["ground_truth"], f, indent=2)
        
        print(f"\nResults saved to {output_dir}/")

    
    def build_gap_analysis(
        self,
        agent_res: Dict[str, UnifiedReportModel],
        codeql_res: Dict[str, UnifiedReportModel],
        ground_truth: Dict[str, List[str]],
        source_root: Optional[str] = None,
    ) -> dict:
    
        """"""
        fn: Dict[str, List[dict]] = {}
        dataset_root = Path(source_root) if source_root else None

        for filename, gt_cwes in ground_truth.items():
            gt_set = set(gt_cwes or [])
            if not gt_set:
                continue

            agent_cwes = {v.cwe for v in agent_res[filename].vulnerabilities} if filename in agent_res else set()
            codeql_cwes = {v.cwe for v in codeql_res[filename].vulnerabilities} if filename in codeql_res else set()
            
            agent_status = ("exact_match" if gt_set == agent_cwes else 
                            "partial_match" if gt_set & agent_cwes    else 
                            "missed" if not agent_cwes          else 
                            "wrong"
            )

            codeql_status = ("exact_match" if gt_set == codeql_cwes else 
                            "partial_match" if gt_set & codeql_cwes    else 
                            "missed" if not codeql_cwes          else 
                            "wrong"
            )

            if codeql_status not in ("missed", "wrong"):
                continue
            if agent_status not in ("exact_match", "partial_match"):
                continue

    
            missed_cwes = gt_set - codeql_cwes

            source_path = ""
            source_exists = False
            if dataset_root:
                parts = filename.split("/", 1)
                rel = parts[1] if len(parts) == 2 else filename
                candidate = dataset_root / rel
                if candidate.exists():
                    source_path = str(candidate)
                    source_exists = True
                else:
                    source_path = str(candidate)

            for cwe in missed_cwes:
                fn.setdefault(cwe, []).append({
                    "filename": filename,
                    "source_path": source_path,
                    "source_exists": source_exists,
                    "ground_truth_cwes": sorted(gt_set),
                    "agent_cwes": sorted(agent_cwes),
                    "codeql_cwes": sorted(codeql_cwes),
                    "agent_verdict": agent_status,
                    "codeql_verdict": codeql_status,
                    "agent_audit": "",
                })


        cwe_coverage = {cwe: len(entries) for cwe, entries in fn.items()}
        top_missed = sorted(cwe_coverage, key=lambda c:cwe_coverage[c], reverse=True)

        return {
            "false_negatives_by_cwe": fn,
            "summary": {
                "total_fn_files": sum(len(v) for v in fn.values()),
                "cwe_coverage": cwe_coverage,
                "top_missed_cwes": top_missed
            }
        }

    
