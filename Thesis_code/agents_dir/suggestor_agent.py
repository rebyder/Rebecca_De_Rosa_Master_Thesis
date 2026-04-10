""" 
Module that defines the SuggestorAgent, a ReAct agent that reads the Analyzer Agent's results, 
identifies the detected vulnerabilities and creates:
    - a detailed report
    - suggestions for new improved and predictive CodeQL queries
    - structured reasonings (summary -> thought -> action)

Contains:
    - SuggestorInput: input task for the SuggestorAgent
    - SuggestorOutput: output task from the SuggestorAgent
    - SuggestorAgent: autonomous agent that executes analysis and realizes suggestions

Main functionalities:
    - step-by-step reasoning through ReActChain
    - tool call and creation
    - shared memory management
    - loading of existing CodeQL queries for ispiration  
"""

import json
import re
from typing import List, Set, Dict, Any, Optional
from pathlib import Path

from pydantic import Field
from agents_dir.base_agent import BaseAgent, ReActChain, SharedMemory, BaseTaskInput, BaseModel
from prompts import SUMMARY_TEMPLATE, THOUGHT_TEMPLATE, ACTION_TEMPLATE
from procedures.summ_procedure import SummaryProcedure
from procedures.action_procedure import ActionProcedure
from procedures.tought_procedure import ThoughtProcedure

MAX_SEARCHES_PER_CWE = 3
CWE_ALIASES: Dict[str, List[str]] = {
    "CWE-79": ["xss", "cross site scripting", "cross-site scripting"],
    "CWE-89": ["sql injection", "sqli", "sql-injection", "sqli"],
    "CWE-22": ["path traversal", "directory traversal"],
    "CWE-78": ["command injection", "os command injection", "rce"],
    "CWE-352": ["csrf", "cross site request forgery", "cross-site request forgery"],
    "CWE-434": ["unrestricted file upload", "file upload"],
    "CWE-502": ["deserialization", "unsafe deserialization"],
}


class SuggestorInput(BaseTaskInput):
    """
    SuggestorAgent input.
    
    Args:
        gap_analysis (str): analysis of the gaps between CodeQL and Analyzer agent.
        JSON string with structure:
            {
                "false_negatives_by_cwe": {
                    "CWE-89": [{"filename":..., "source_code":..., "agent_audit":...}]
                },
                "summary": {"top_missed_cwes": [...], "cwe_coverage": ...},
                "existing_queries": {"CWE-89": "query content..."}
            }
    """
    gap_analysis: str = Field(...)


class QueryProposal(BaseModel):
    """
    Improvement proposal for a new CodeQL query.
    
    Everything the CreatorAgent needs to create a new query.

    Args:
        cwe (str): target CWE.
        cwe_description (str): description of the target CWE.
        existing_queries_summary (str): what the current query already covers.
        gap_description (str): what pattern/API the current query misses.
        missing_sources (List[str]): AST source nodes to add.
        missing_sinks (List[str]): AST sink nodes to add.
        missing_sanitizers (List[str]): AST sanitizer nodes to add.
        proposed_additions (str): QL pseudo-code showing what to add.
        estimated_impact (str): qualitative FM reduction estimate.
        evidence_files (List[str]): filenames that motivate the proposal, with code snippets and agent audits.
        web_search_used (str): web search findings incorporated.
    """

    cwe: str = Field(...)
    cwe_description: str = Field(...)
    existing_queries_summary: str = Field(default="")
    gap_description: str = Field(...)
    missing_sources: List[str] = Field(default_factory=list)
    missing_sinks: List[str] = Field(default_factory=list)
    missing_sanitizers: List[str] = Field(default_factory=list)
    proposed_additions: str = Field(...)
    estimated_impact: str = Field(default="")
    evidence_files: List[str] = Field(default_factory=list)
    web_search_used: str = Field(default="")


class SuggestorOutput(BaseModel):
    """
    SuggestorAgent output.
    
    Args:
        processed_cwes (List[str]): list of processed CWEs.
        skipped_cwes (List[str]): CWEs with no existing query (creatorAgent generates from scratch).
        raw_report (str): human-readable concatenation of all proposals.
    """
    processed_cwes: List[str] = Field(default_factory=list)
    skipped_cwes: List[str] = Field(default_factory=list)
    raw_report: str = Field(default="")


class GenerateProposalTool(BaseModel):
    """"
    """
    cwe: str = Field(...)
    ready_reason: str = Field(default="")

class FinishToolSuggestor(BaseModel):
    """
    Termination signal: agent calls this when all CWEs have been processed.

    Args:
        summary (str): brief summary of what was accomplished.
    """
    summary: str = Field(...)


class SuggestorAgent(BaseAgent):
    """
    SuggestorAgent is a ReAct agent that generates CodeQL query suggestions.
    """

  
    def __init__(self, prompt_template: str, shared_memory: SharedMemory, tools: list, logpath: str=None):

        super().__init__(prompt_template=prompt_template, shared_memory=shared_memory, tools=tools, logpath=logpath)
       
    
        self.summ_procedure=SummaryProcedure(self.llm, SUMMARY_TEMPLATE)
        self.thought_procedure=ThoughtProcedure(self.llm, THOUGHT_TEMPLATE)
        self.action_procedure = ActionProcedure(self.llm, ACTION_TEMPLATE)

        self.max_steps: int = 30
        self.gap_analysis: dict = {}
        self.proposals: List[QueryProposal] = []
        self.processed_cwes: Set[str] = set()
        self.web_search_mem: Dict[str, str] = {}

    def _to_markdown_list(self, values: List[str]) -> str:
        if not values:
            return "- None"
        return "\n".join([f"- {item}" for item in values])

    def _normalize_text(self, text: str) -> str:
        return re.sub(r"[^a-z0-9]+", "", text.lower())

    def resolve_target_cwe(self, query: str, unique_cwes: Set[str]) -> Optional[str]:
        normalized_query = self._normalize_text(query)

        # 1) Direct CWE id match in query (e.g. "CWE-89", "cwe89")
        for cwe in unique_cwes:
            if self._normalize_text(cwe) in normalized_query:
                return cwe

        # 2) Alias/synonym match (e.g. "SQL injection" -> CWE-89)
        for cwe in unique_cwes:
            for alias in CWE_ALIASES.get(cwe, []):
                if self._normalize_text(alias) in normalized_query:
                    return cwe

        # 3) LLM fallback: semantic routing over only actionable CWEs
        try:
            cwe_list = sorted(unique_cwes)
            prompt = (
                "You must map a security search query to one CWE from a fixed list.\n"
                f"Allowed CWEs: {cwe_list}\n"
                f"Query: {query}\n\n"
                "Return only one token: the exact CWE id from the list, or NONE if unclear."
            )
            decision = (self.llm.invoke(prompt).content or "").strip().split()[0].strip(".,;:()[]{}\"'")
            if decision in unique_cwes:
                return decision
        except Exception:
            pass

        return None

    def build_markdown_report(
        self,
        proposals: List[QueryProposal],
        processed_cwes: List[str],
        skipped_cwes: List[str]
    ) -> str:
        lines: List[str] = [
            "# Suggestor Report",
            "",
            "## Summary",
            f"- Processed CWEs: {', '.join(processed_cwes) if processed_cwes else 'None'}",
            f"- Skipped CWEs: {', '.join(skipped_cwes) if skipped_cwes else 'None'}",
            "",
        ]

        for proposal in proposals:
            lines.extend([
                f"## {proposal.cwe}",
                "",
                "### Existing Coverage",
                proposal.existing_queries_summary or "Not provided.",
                "",
                "### Gap Identified",
                proposal.gap_description or "Not provided.",
                "",
                "### Missing Sources",
                self._to_markdown_list(proposal.missing_sources),
                "",
                "### Missing Sinks",
                self._to_markdown_list(proposal.missing_sinks),
                "",
                "### Missing Sanitizers",
                self._to_markdown_list(proposal.missing_sanitizers),
                "",
                "### Proposed Addition",
                proposal.proposed_additions or "Not provided.",
                "",
                "### Estimated Impact",
                proposal.estimated_impact or "Not provided.",
                "",
                "### Evidence Files",
                self._to_markdown_list(proposal.evidence_files),
                "",
            ])

        return "\n".join(lines).strip()

    def reset(self, task_input: SuggestorInput):
        """
        Resets the agent state for a new task.
        
        If the input is a SuggestorInput, it extracts and saves the SARIF report content
        as first observation and initializes the processed_cwes list
        
        Args:
            task_input (BaseTaskInput): task input, preferably SuggestorInput.
        """
        
        if not isinstance(task_input, SuggestorInput):
            return

            
        self.gap_analysis = json.loads(task_input.gap_analysis)
        self.proposals = []    
        self.processed_cwes = set()
        self.web_search_mem = {}

        summary = self.gap_analysis.get("summary", {})
        top_cwes = summary.get("top_missed_cwes", [])

        print(f"[Suggestor]: Total FN files: {summary.get("total_fn_files", 0)} ")
        print(f"CWEs to process: {top_cwes}")

        self.last_step.observation=(
            f"For each CWE: the existing CodeQL query is already provided in the gap analysis. "
            f"Use WebSearchTool only for additional API/library context if needed "
            f"and pass cwe='CWE-XX' in the tool call, "
            f"then call GenerateProposalTool when ready.\n"
            f"Call FinishToolSuggestor only after ALL CWEs are processed."
        )
        

    def summarize(self, query: str, text: str) -> str:
        if len(text)< 1000:
            return text

        summary_prompt = f"""
        From this search result for "{query}", extract only:
        - CodeQL class/predicate/library names
        - Python library method names relevant to the vulnerability
        - AST elements: Sources, Sinks, Sanitizers
        - TainTraking configuration patterns.

        Discard: navigation, ads, unrelated prose.
        Result: {text[:6000]}"""
        
        return self.llm.invoke(summary_prompt).content
   

    def get_fn(self, cwe: str) -> Dict[str, Any]:
        """"""
        fn_entries = self.gap_analysis.get("false_negatives_by_cwe", {}).get(cwe, [])


        examples, audits, filenames = [], [], []

        for entry in fn_entries:
            filename = entry.get("filename", "")
            source_path = entry.get("source_path", "")
            if filename:
                filenames.append(filename)

            if len(examples) < 3:
                try:
                    read_path = source_path or filename
                    source = Path(read_path).read_text(encoding='utf-8', errors="ignore")
                    if source not in examples:
                        examples.append(source)
                except OSError:
                    pass
            
            audit = entry.get("agent_audit", "")
            if audit and len(audits) < 3:
                audits.append(audit)


        return {
            "examples": examples,
            "audits": audits,
            "filenames": filenames,
            "existing_query": self.gap_analysis.get("existing_queries", {}).get(cwe, "No existing query availble.")
        }
    

    def generate_proposal(self, cwe: str) -> QueryProposal:
        """"""

        fn_data = self.get_fn(cwe)
        web_search = self.web_search_mem.get(cwe, "No web search available.")

        examples_text = "\n\n---\n".join([
            f"Example {i+1} ({fn_data['filenames'][i] if i<len(fn_data['filenames']) else '?'}):\n{code[:2000]}"
            for i, code in enumerate(fn_data["examples"])
        ]) or "No source code examples available"

        audits_text = "\n\n".join([
            f"Audit {i+1}: {audit}"
            for i, audit in enumerate(fn_data["audits"])
        ]) or "No audits available."

        prompt = f"""Role: You are a CodeQL expert. Improve an EXISTING CodeQL query.

        Context: 
        - Target cwe:{cwe}
        - Existing query: {fn_data["existing_query"][:3000]}
        - Source code that CodeQL missed: {examples_text}
        - AnalyzerAgent reasoning (why these ARE vulnerable): {audits_text}
        - Web search (API and CodeQL library info gathered): {web_search[:2000]}

        Task: Identify the GAP and produce a structured proposal with EXACTLY these sections:

        EXISTING COVERAGE:
        <one paragraph: sources, sinks, sanitizers the current query already handles>

        GAP IDENTIFIED:
        <one paragraph: the specific pattern or library construct that is missing>

        MISSING SOURCES:
        - <exact Python AST node, e.g. "FastAPI: Request.query_params.get() parameter">
        - ...

        MISSING SINKS:
        - <exact dangerous call, e.g. "SQLAlchemy: session.execute() with f-string argument">
        - ...

        MISSING SANITIZERS:
        - <pattern that prevents exploitation, e.g. "SQLAlchemy: bindparams() parameterized query">
        - ...

        PROPOSED ADDITION (Python-mapped AST pseudo-code, NOT CodeQL syntax yet):
        <the specific predicate or condition to add — describe what to modify and how>

        ESTIMATED IMPACT: <low / medium / high>

        Be CONCRETE. Cite real method signatures. Focus ONLY on what to ADD, not a full rewrite.
        """

        response = self.llm.invoke(prompt)
        raw_text = response.content

        section_markers = [
            "EXISTING COVERAGE", "GAP IDENTIFIED", "MISSING SOURCES", "MISSING SINKS", "MISSING SANITIZERS",
            "PROPOSED ADDITION", "ESTIMATED IMPACT"
        ]

        def extract(label: str) -> str:
            marker = label + ":"
            if marker not in raw_text:
                return ""
            start = raw_text.index(marker) + len(marker)
            nex_starts = [
                raw_text.index(m+":", start)
                for m in section_markers
                if m + ":" in raw_text[start:]
            ]
            end = min(nex_starts) if nex_starts else len(raw_text)
            return raw_text[start:end].strip()
        

        def extract_list(label: str) -> List[str]:
            block = extract(label)
            return [
                line.strip("- •").strip()
                for line in block.splitlines()
                if line.strip().startswith("-")
            ]
        
        return QueryProposal(
            cwe=cwe,
            cwe_description="",
            existing_queries_summary=extract("EXISTING COVERAGE"),
            gap_description=extract("GAP IDENTIFIED") or raw_text[:300],
            missing_sources=extract_list("MISSING SOURCES"),
            missing_sinks=extract_list("MISSING SINKS"),
            missing_sanitizers=extract_list("MISSING SANITIZERS"),
            proposed_additions=extract("PROPOSED ADDITION") or raw_text,
            estimated_impact=extract("ESTIMATED IMPACT"),
            evidence_files=fn_data["filenames"],
            web_search_used=web_search[:500]
        )


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

        scratchpad = self.shared_memory.to_messages()[-10:]
        instructions = self.prompt_template 

        summary_out = self.summ_procedure.run(instructions, scratchpad)
        summary = summary_out.summary

        thought_out =self.thought_procedure.run(summary, scratchpad, self.last_step)
        thought = thought_out.thought
        
        action_out = self.action_procedure.run(summary, scratchpad, self.last_step, thought, self.tools)
        action = action_out.action

        self.last_step = ReActChain.format(summary=summary, thought=thought, action=action)
        return self.last_step
    
    def run(self) -> SuggestorOutput:
        """
        Executed the entire reasoning cycle of the SuggestorAgent
        
        The method:
            - executes max_step iteractions maximum
            - calls tool depending on the decided action
            - checks if the final action is FinishToolSuggestor
            - created the finel SuggestorOutput report
        
        Returns:
            SuggestorOutput: contains the final report created by the agent
        
        Raises:
            TimeoutError: if the agent exceed max_steps.
        """


        summary = self.gap_analysis.get("summary", {})
        all_cwes: List[str] = summary.get("top_missed_cwes", [])

        unique_cwes = set(all_cwes)
        skipped = []
        search_count: Dict[str, int] = {}
        current_focus_cwe: Optional[str] = sorted(unique_cwes)[0] if unique_cwes else None
        
        if skipped:
            print(f"[Suggestor]: No existing query: {skipped} -> CreatorAgent generates from scratch")

        if not unique_cwes:
            return SuggestorOutput(
                processed_cwes=[], skipped_cwes=skipped,
                raw_report="No actionable CWEs."
            )
    
        print(f"[Suggestor] Starting. All cwes: {sorted(unique_cwes)} | max_steps: {self.max_steps}")
        last_observation = self.last_step.observation


        for step in range(self.max_steps):

            current_reasoning = self.step(last_observation)            
            current_action = current_reasoning.action

            if not current_action:
                last_observation =  (
                "\nERROR: not action decided."
                f"Pending CWEs: {unique_cwes - self.processed_cwes}. "
                "Use WebSearchTool to reasearch, GenerateProposalTool when ready, FinishToolSuggestor when all done."
                )
                self.update_memory(last_observation)
                continue
            
            action_name = current_action.__class__.__name__
            pending = unique_cwes - self.processed_cwes
            if pending and current_focus_cwe not in pending:
                current_focus_cwe = sorted(pending)[0]

            print(f"\n[{step}] {action_name} | Pending CWEs to analyse: {pending}")
            print(f"    Thought: {current_reasoning.thought[:100]}...")

            if action_name == "FinishToolSuggestor":
                if pending:
                    last_observation = (
                        f"BLOCKED: cannot finish yet. "
                        f"Pending CWEs: {pending}. "
                        f"Call GenerateProposalTool for each remaining CWE first or WebSearch in case you need insights about API/libraries."
                    ) 
                    self.update_memory(last_observation)
                    continue
                    
                raw_report = self.build_markdown_report(
                    proposals=self.proposals,
                    processed_cwes=list(self.processed_cwes),
                    skipped_cwes=skipped
                )
            
                self.shared_memory.set_data("suggestor_processed_cwes", list(self.processed_cwes))
                self.shared_memory.set_data("suggestor_skipped_cwes", skipped)
                print(f"[Suggestor] Done. Processed: {self.processed_cwes}")

                return SuggestorOutput(
                    processed_cwes=list(self.processed_cwes),
                    skipped_cwes=skipped,
                    raw_report=raw_report
                )
            
            if pending and action_name not in ("WebSearchTool", "GenerateProposalTool"):
                last_observation = (
                    f"Pending CWEs: {pending}. "
                    f"Use WebSearchTool to gather information, "
                    f"pass cwe='CWE-XX' in WebSearchTool, "
                    f"then GenerateProposalTool(cwe=...) when ready."
                )
                self.update_memory(last_observation)
                continue

            if action_name=="WebSearchTool":
                try:
                    result = current_action.run()
                    query = getattr(current_action, "query", "")
                    compressed = self.summarize(query, str(result))

                    explicit_cwe = getattr(current_action, "cwe", "").strip()
                    if explicit_cwe in unique_cwes:
                        target_cwe = explicit_cwe
                    elif current_focus_cwe in pending:
                        target_cwe = current_focus_cwe
                    else:
                        target_cwe = self.resolve_target_cwe(query, unique_cwes)

                    if target_cwe: 
                        existing = self.web_search_mem.get(target_cwe, "")
                        self.web_search_mem[target_cwe] = (existing + "\n\n" + compressed).strip()
                        search_count[target_cwe] = search_count.get(target_cwe, 0) + 1

                    cwe_searches = search_count.get(target_cwe, 0) if target_cwe else sum(search_count.values())

                    if target_cwe and cwe_searches >= MAX_SEARCHES_PER_CWE:
                        last_observation = (
                            f"WebSearchTool result for '{query}':\n{compressed}\n\n"
                            f"Search limit reached for {target_cwe}. "
                            f"Call GenerateProposalTool(cwe='{target_cwe}') now."
                        )
                    else:
                        last_observation = (
                            f"WebSearchTool result for '{query}':\n{compressed}\n\n"
                            f"If you have enough context, call GenerateProposalTool. "
                            f"Otherwise search more."
                        )
                       

                except Exception as e:
                    last_observation = f"WebSearchTool error: {e}. Try different query or proceed to GenerateProposalTool."
            
            elif action_name == "GenerateProposalTool":
                cwe = getattr(current_action, "cwe", "").strip()
                reason = getattr(current_action, "ready_reason", "")

                if not cwe or cwe not in unique_cwes:
                    last_observation = (
                        f"Invalid CWE '{cwe}'. Actionable CWEs: {sorted(unique_cwes)}. "
                        f"Call GenerateProposalTool with one of those."
                    )
                    self.update_memory(last_observation)
                    continue

                if cwe in self.processed_cwes:
                    last_observation = (
                        f"{cwe} already processed. "
                        f"Remaining: {unique_cwes - self.processed_cwes}."
                    )
                    self.update_memory(last_observation)
                    continue

                print(f"Generating proposal for {cwe}... (reason: {reason})")
                current_focus_cwe = cwe
                
                try:
                    proposal = self.generate_proposal(cwe)
                    self.proposals.append(proposal)
                    self.processed_cwes.add(cwe)

                    remaining = unique_cwes - self.processed_cwes
                    print(f"{cwe} done | Impact: {proposal.estimated_impact} | Remaining CWEs: {remaining}")

                    if remaining:
                        last_observation = (
                            f"SUCCESS: Proposal for {cwe} generated and stored.\n"
                            f"Remaining CWEs: {remaining}.\n"
                            f"Continue: call WebSearchTool if needed, then GenerateProposalTool for next CWE."
                        )
                    else: 
                        last_observation = (
                            f"SUCCESS: Proposal for {cwe} generated.\n"
                            "All CWEs processed. Call FinishToolSuggestor to finalize."
                        )
                
                except Exception as e:
                    fn_data = self.get_fn(cwe)
                    self.proposals.append(QueryProposal(
                        cwe=cwe,
                        gap_description=f"Generation error: {e}",
                        proposed_additions="Manual review required.",
                        evidence_files=fn_data["filenames"]
                    ))
                    self.processed_cwes.add(cwe)
                    last_observation = f"Error generating {cwe}: {e}, Placeholder stored. Continue with next CWE."
            
            else:
                last_observation = (
                    f"Unknown tool: {action_name}. "
                    f"Available: WebSearchTool, GenerateProposalTool and FinishToolSuggestor."
                )

            self.update_memory(last_observation)
        
        raise TimeoutError(
            f"Suggestor exceeded max_steps={self.max_steps}. "
            f"Processed: {self.processed_cwes} | Pending: {unique_cwes - self.processed_cwes}"
        )
