"""
Main script to run the LLM Agent Architecture for detecting software vulnerabilities at source code level.

This script sets up the necessary components, including loading environment variables,
parsing command-line arguments, and initializing the orchestrator agent. It then
executes the workflow to analyze a dataset of source code files for vulnerabilities.

Command-line Arguments:
    --dataset_path (str): path to the dataset directory containing vulnerable source files.
    --memory_path (str): path to the shared memory JSON file.
"""

import argparse
import os

if os.getenv("DEBUG_IMPORTS") == "1":
    import builtins
    import time

    _orig_import = builtins.__import__

    def _timed_import(name, globals=None, locals=None, fromlist=(), level=0):
        start = time.perf_counter()
        try:
            return _orig_import(name, globals, locals, fromlist, level)
        finally:
            dur_ms = (time.perf_counter() - start) * 1000
            if dur_ms >= 50:
                print(f"[import] {name}: {dur_ms:.1f} ms")

    builtins.__import__ = _timed_import

from agents_dir.agent_caller import run_workflow
from dotenv import load_dotenv

load_dotenv()

def main():
    """Main function to run the LLM Agent Architecture workflow."""
    
    parser = argparse.ArgumentParser(description="Use this script to run a multi-agent AI architecture with the goal of detecting software vulnerabilities at source code level and creating new CodeQL queries.")

    script_directory = os.path.dirname(os.path.abspath(__file__))
    json_file_path = os.path.join(script_directory, "data")


    parser.add_argument("--dataset_path", type=str, default=json_file_path, help="Path to the dataset directory containing the vulnerable source files.")
    parser.add_argument("--memory_path", type=str, default="agent_memory.json", help="Path to the shared memory JSON file.")

    args = parser.parse_args()
    
    try:
        final_message = run_workflow(
            dataset_path=args.dataset_path,
            memory_path=args.memory_path,
        )
        print("="*40)
        print("Final Message from the last Agent:")
        print("="*40)

        print(final_message)

    except Exception as e:
        print(f"\nWorkflow failed with exception: {str(e)}")

if __name__ == "__main__":
    main()
