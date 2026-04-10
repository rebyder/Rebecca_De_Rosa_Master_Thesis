"""
Module that defines the OrchestratorAgent, responsible of the management of the
entire multi-agent workflow for:

    1. Source code analysis through CodeQL and validation of the CodeQL report (AnalyzerAgent)
    2. Generation of suggetions for new improved queries (SuggestorAgent)
    3. Creation of new CodeQL queries (CreatorAgent)

The module integrates different agents, each specialized in different tasks, and coordinates
the entire process.

Principal class:
    - OrchestratorAgent: manager of the entire multi-agent workflow

Main function:
    - run_workflow: complete execution of the process

"""

import tempfile
import os
from pathlib import Path
import yaml
import json

from tools import WebSearchTool, FinishTool
from agents_dir.base_agent import SharedMemory
from agents_dir.analyzer_agent import AnalyzerAgent, CodeQLAnalyzerInput, UnifiedReportModel
from agents_dir.suggestor_agent import SuggestorAgent, SuggestorInput, GenerateProposalTool, FinishToolSuggestor
from agents_dir.creator_agent import CreatorAgent, CreatorInput, FinishToolCreator, WriteQueryTool 
from prompts import SYSTEM_ANALYZER_SPECIFIC, SYSTEM_SUGGESTOR, SYSTEM_QUERY_CREATOR



def _save_shared_memory(shared_memory: SharedMemory, memory_path: str) -> None:
    """Persist shared memory snapshot to JSON."""
    out = {
        "steps": shared_memory.to_log(),
        "data": shared_memory.data,
    }
    path = Path(memory_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False, default=str)


def run_workflow(dataset_path: str, memory_path: str = "agent_memory.json") -> str:
    """
    Execute the entire multi-agent workflow for dataset analysis and new CodeQL queries creation.
    
    Args:
        dataset_path (str): Path of the directory containing all the vulberable files.
        memory_path (str): Path where shared memory snapshot will be written.

    Returns:
        str: final_message of the CreatorAgent
    Pipeline:
        1. AnalyzerAgent: CodeQL execution, SARIF report generation and SARRIF report validation
        2. SuggestorAgent: new queries suggestions generation
        3. CreatorAgent: new queries creation
    
    """

    print("="*40)
    print("WORKFLOW START")
    print("="*40)

    shared_memory = SharedMemory()
    output_dir = "results"
    log_dir = tempfile.mkdtemp(prefix="agent_logs_")

    creator_output = None
    try:
        #first: AnalyzerAgent
        print("\nAnalyzer agent...\n")
        config_path = Path(__file__).parent / "config.yaml"
        with config_path.open("r", encoding="utf-8") as f:
            config = yaml.safe_load(f)["paths"]

        gt_file = config.get("ground_truth_path", "data/ground_truth.json")
        dataset_label = config.get("dataset_label", Path(dataset_path).name or "dataset")
                  
        analyzer = AnalyzerAgent(
            prompt_template=SYSTEM_ANALYZER_SPECIFIC,
            shared_memory=shared_memory,
            tools=[FinishTool],
            logpath = os.path.join(log_dir, "analyzer_log"),
            config=config
        )

        analyzer_input = CodeQLAnalyzerInput(
            source_root=dataset_path
        )

        output = analyzer.run_analysis(
            task=analyzer_input,
            gt_json_path=gt_file,
            dataset_label=dataset_label,
            output_dir=output_dir)
        
        if not output:
            return "Workflow stopped: Analyzer did not produce output. Check previous errors."
        
        agent_norm = {k: UnifiedReportModel(**v) for k, v in output["agent"].items()}
        codeql_norm = {k: UnifiedReportModel(**v) for k, v in output["codeql"].items()}
        gt = output["ground_truth"]
        gap = analyzer.build_gap_analysis(agent_norm, codeql_norm, gt, source_root=dataset_path)
    #   gap:
    #     {
    #   "false_negatives_by_cwe": {
    #     "CWE-89": [
    #       {
    #         "filename": "cwefixes/django/contrib/postgres/aggregates/general.py",
    #         "source_path": "data/cwefixes/django/contrib/postgres/aggregates/general.py",
    #         "source_exists": True,
    #         "ground_truth_cwes": ["CWE-79", "CWE-89"],
    #         "agent_cwes": ["CWE-79", "CWE-89"],
    #         "codeql_cwes": ["CWE-79"],
    #         "agent_verdict": "exact_match",
    #         "codeql_verdict": "partial_match",
    #         "agent_audit": ""
    #       }
    #     ],
    #     "CWE-22": [
    #       {
    #         "filename": "cwefixes/flask/app.py",
    #         "source_path": "data/cwefixes/flask/app.py",
    #         "source_exists": True,
    #         "ground_truth_cwes": ["CWE-22"],
    #         "agent_cwes": ["CWE-22"],
    #         "codeql_cwes": [],
    #         "agent_verdict": "exact_match",
    #         "codeql_verdict": "missed",
    #         "agent_audit": ""
    #       }
    #     ]
    #   },
    #   "summary": {
    #     "total_fn_files": 2,
    #     "cwe_coverage": {
    #       "CWE-89": 1,
    #       "CWE-22": 1
    #     },
    #     "top_missed_cwes": ["CWE-89", "CWE-22"]
    #   }
    # }


        existing_queries = {}
        query_dir = Path(config["query_pack_path"]).expanduser()
        for cwe in gap["summary"]["top_missed_cwes"]:
            cwe_folder = cwe.replace("CWE-", "CWE-").lstrip("CWE-").zfill(3)
            cwe_dir = query_dir / f"CWE-{cwe_folder}"
            if cwe_dir.exists():
                for ql_file in cwe_dir.glob("*.ql"):
                    existing_queries.setdefault(cwe, []).append(
                        ql_file.read_text(encoding='utf-8')
                    )

        gap["existing_queries"] = {k: "\n\n---\n".join(v) for k, v in existing_queries.items()}
#       gap = {
#           "false_negatives_by_cwe": {...},
#           "summary": {...},
#           "existing_queries": {
#               "CWE-89": "query1\n\n---\nquery2",
#               "CWE-22": "queryA\n\n---\nqueryB"
#               }
#           }

        print("\nEexisting_queries:\n")
        print(json.dumps(gap.get("existing_queries", {}), indent=2, ensure_ascii=False))


        shared_memory.set_data("existing_queries", gap.get("existing_queries", {}))

        print("\nSuggestor agent...\n")

        print(f"\n  Gap analysis: {gap['summary']['total_fn_files']} FN files "
            f"across {len(gap['summary']['top_missed_cwes'])} CWEs: "
            f"{gap['summary']['top_missed_cwes']}")
        
        suggestor = SuggestorAgent(
            prompt_template=SYSTEM_SUGGESTOR,
            shared_memory=shared_memory,
            tools=[WebSearchTool, FinishToolSuggestor, GenerateProposalTool],
            logpath=os.path.join(log_dir, "suggestor_log")
        )

        suggestor_input = SuggestorInput(gap_analysis=json.dumps(gap))
        suggestor.reset(suggestor_input)
        suggestor_output = suggestor.run()

        print(f"\n  Processed CWEs: {suggestor_output.processed_cwes}")
        print(f"  Skipped CWEs:   {suggestor_output.skipped_cwes}")

        with open("sast_report.md", "w", encoding="utf-8") as f:
            f.write(suggestor_output.raw_report)
        print("\nReport of the Suggestor saved in sast_report.md\n")



        # esempio putput Suggestor:
        # {
        #   "processed_cwes": [
        #     "CWE-89",
        #     "CWE-22"
        #   ],
        #   "skipped_cwes": [],
        #   "raw_report": "# Suggestor Report\n\n## Summary\n- Processed CWEs: CWE-89, CWE-22\n- Skipped CWEs: None\n\n## CWE-89\n..."
        # }


        print("\nCreator agent...\n")
        creator = CreatorAgent(
            prompt_template=SYSTEM_QUERY_CREATOR,
            shared_memory=shared_memory,
            tools=[WebSearchTool, WriteQueryTool, FinishToolCreator],
            logpath=os.path.join(log_dir, "creator_log")
        )

        creator_input = CreatorInput(final_report=suggestor_output.raw_report)
        creator.reset(creator_input)
        creator_output = creator.run()

        print(f"\nLog saved in: {log_dir}")
        return creator_output.final_message

    except Exception as e:
        import traceback
        print(f"\nWorkflow failed with exception: {e}")
        traceback.print_exc()
        return f"Workflow failed with exception: {e}"
    finally:
        try:
            _save_shared_memory(shared_memory, memory_path)
            print(f"\nShared memory snapshot saved to: {memory_path}")
        except Exception as e:
            print(f"\nWarning: failed to save shared memory snapshot to {memory_path}: {e}")
