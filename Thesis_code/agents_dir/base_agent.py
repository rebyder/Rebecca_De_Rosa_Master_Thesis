"""
Module defining the base classes for autonomous agents using ReAct framework.
This module provides foundational classes for building autonomous agents that
utilize the ReAct (Reasoning and Acting) paradigm. It includes the definition of
the ReActChain class, which represents a single reasoning step in the agent's
scratchpad, as well as the SharedMemory class for managing the agent's memory.

It also defines the BaseAgent class, which serves as a base for creating
autonomous agents that can perform tasks using a large language model (LLM) and
a set of tools.

Principal classes:
    - ReActChain: represents a single reasoning step in the agent's scratchpad
    - SharedMemory: manages the agent's memory, including steps and data
    - BaseAgent: base class for creating autonomous agents
"""

from langchain_openai import ChatOpenAI
from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field
import json
import logging
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
class ReActChain():
    """Single ReAct (Reasoning and Acting) unit of agent scratchpad.

    Args:
        summary (str): The produced summary for the current chain
        thought (str): The produced thought for the current chain
        action (str): The produced action for the current chain
        observation (str): The resulting observation for the current chain
        error (str, optional): The error message in case of agent failure. 
            Defaults to 'None'.

    Attributes:
        summary (str): The produced summary for the current chain.
        thought (str): The produced thought for the current chain.
        action (str): The produced action for the current chain.
        observation (str): The resulting observation for the current chain.
        error (str): The error message in case of agent failure.

    Methods:
        format: Create a ReActChain instance with optional parameters.
        to_str: Convert the ReActChain to a formatted string representation.
        to_messages: Convert the ReActChain to a list of message dictionaries.
        to_log: Convert the ReActChain to a dictionary for JSON-formatted output.
    """

    def __init__(self, summary: str, thought: str, action: str, observation: str, error: str = 'None'):
        self.summary = summary  
        self.thought = thought  
        self.action = action 
        self.observation = observation  
        self.error = error 

    @classmethod 
    def format(cls, summary='', thought='', action='', observation='', error='None'):
        """Create a ReActChain instance with optional parameters.

        Args:
            summary (str, optional): The produced summary for the current chain. 
                Defaults to ''.
            thought (str, optional): The produced thought for the current chain. 
                Defaults to ''.
            action (str, optional): The produced action for the current chain. 
                Defaults to ''.
            observation (str, optional): The resulting observation for the current 
                chain. Defaults to ''.
            error (str, optional): The error message in case of agent failure. 
                Defaults to 'None'.

        Returns:
            ReActChain: A new instance of the ReActChain class.
        """
        return cls(
            summary=summary,
            thought=thought,
            action=action,
            observation=observation,
            error=error
        )

    def to_str(self): 
        """Convert the ReActChain to a formatted string representation.

        Returns:
            str: A string representation of the ReActChain, including thought, 
                action, and observation.
        """
        action = self.action
        tool = action.__class__.__name__ if action else 'None'

        text = f'Thought: {self.thought}\n'

        if self.action == '':
            text += f'Action: \n'
        else:
            text += f'Action: {tool}({action})\n'

        text += f'Observation: {self.observation}\n'

        return text

    def to_messages(self): 
        """Convert the ReActChain to a list of message dictionaries.

        Returns:
            list: A list of two dictionaries representing assistant and user messages.
        """
       
        action = self.action
        tool = action.__class__.__name__ if action else 'None'

        
        if self.action == '':
            assistant_msg = f'Thought: {self.thought}\nAction: '
        else:
            assistant_msg = f'Thought: {self.thought}\nAction: {tool}({action})'
        user_msg = f'Observation: {self.observation}'

       
        messages = [
            {'role': 'assistant', 'content': assistant_msg},
            {'role': 'user', 'content': user_msg}
        ]

        return messages

    def to_log(self):
        """Convert the ReActChain to a dictionary for JSON-formatted output.

        Returns:
            dict: A dictionary containing thought, action, observation, summary, 
                and error information.
        """
     
        action = self.action
        tool = action.__class__.__name__ if action else 'None'

        obj = {
            'thought': f'Thought: {self.thought}',
            'action': f'Action: {tool}({action})',
            'observation': f'Observation: {self.observation}',
            'summary': f'Summary: {self.summary}',
            'error': f'Error: {self.error}'
        }

        return obj


class SharedMemory(BaseModel): 

    steps: List[Any] = Field(default_factory=list)
    data: Dict[str, Any] = Field(default_factory=dict) 

    def to_messages(self, last: int = None):
        """Converts the scratchpad content to a list of messages.

        Args:
            last (int, optional): Number of the last execution steps to include.
                If None, all steps are included. Defaults to None.

        Returns:
            List[dict]: A list of message dictionaries, each representing a step
                in the ReAct chain.
        """
        messages = []
        if last is None:
            last = len(self.steps)
        else:
            last = min(last, len(self.steps))

        for chain in self.steps[-last:]:
            messages += chain.to_messages()

        return messages

    def to_log(self):
        """Converts the scratchpad content to a list of logs.

        Returns:
            List[dict]: A list of dictionaries, each representing a log entry
                for a single execution step in the ReAct chain.
        """
        logs = []
        for chain in self.steps:
            logs.append(chain.to_log())

        return logs
    

    def update(self, item: ReActChain): 
        self.steps.append(item)

    def set_data(self, key: str, value: Any):
        """Imposta un valore nella memoria dati condivisa."""
        self.data[key] = value

    def get_data(self, key: str, default: Any = None) -> Any:
        """Recupera un valore dalla memoria dati condivisa."""
        return self.data.get(key, default)
    

    def clear_steps(self):
        self.steps.clear()


    
    
class BaseTaskInput(BaseModel):
    """Base class representing the input for a task assigned to an agent."""
    

class BaseAgent():
    """Base class representing an autonomous agent.

    Args:
        prompt_template (str): the prompt template assigned to the agent.
        shared_memory (SharedMemory): the shared memory instance for the agent.
        tools (list): list of tools available to the agent.
        logpath (str, optional): path for logging agent activities. Defaults to None.
    
    Attributes:
        prompt_template (str): the prompt template assigned to the agent.
        shared_memory (SharedMemory): the shared memory instance for the agent.
        tools (list): list of tools available to the agent.
        logpath (str, optional): path for logging agent activities. Defaults to None.
        llm: the LLM model used by the agent.
        task (Optional[BaseTaskInput]): the current task assigned to the agent. Defaults to None.
        prompt (str): the prompt assigned to the current task.
        last_step (ReActChain): the last step in the agent's reasoning chain.
        start (bool): indicates whether a new task has started. Defaults to True.

    Methods:
        reset(task_input): resets the agent's state for a new task.
        update_memory(observation): updates the agent's shared memory with a new observation.
        write_logs(fpath): writes the agent's memory logs to a JSON file.       
    """

    def __init__(self, prompt_template: str, shared_memory: SharedMemory, tools: list, logpath: str=None):
        """Initializes the BaseAgent with the given parameters."""

        self.prompt_template = prompt_template # prompt assegnato all'agente
        self.shared_memory = shared_memory
        self.tools = tools
        self.logpath = logpath

        self.llm = ChatOpenAI(model='gpt-4o-mini', temperature=0)

        self.task: Optional[BaseTaskInput] = None 
        self.last_step = ReActChain.format()
        self.start = True # boolean per indicare se ha inizio o meno una nuova task

    def reset(self, task_input: BaseTaskInput): 
        """Resets the agent's state for a new task.

        Args:
            task (BaseTaskInput): The new task to be assigned to the agent.
        """
        self.task = task_input 
        # reinizializzazione dello state dell'agente
        self.prompt = self.prompt_template
        self.last_step = ReActChain.format()
        self.start=True

        task_context = (
            "TASK CONTEXT\n"
            "The following data represents the concrete task input you must analyze.\n"
            "Apply the workflow and rules defined above strictly.\n\n"
            f"{task_input.model_dump_json(indent=2)}"
        )

        self.last_step.observation = task_context
        self.shared_memory.update(self.last_step)

    def update_memory(self, observation: str):
        """Updates the agent's shared memory with a new observation.

        Args:
            observation (str): The new observation to be added to the shared memory.
        """
        self.last_step.observation = observation

        self.shared_memory.update(self.last_step)
        if self.logpath:
            try:
                self.write_logs(self.logpath)
            except Exception as e:
                logger.error(f"Failed to write the logs to a JSON file.")

    def write_logs(self, fpath: str):
        """Writes the agent's memory logs to a JSON file.

        Args:
            fpath (str): The file path where the logs should be written.
        """
        obj = {
            'steps': self.shared_memory.to_log()
        }
        try:
            os.makedirs(os.path.dirname(fpath), exist_ok=True)
            with open(f'{fpath}.json', 'w') as file:
                file.write(json.dumps(obj, indent=2, ensure_ascii=False))
            logger.info(f"Logs written to {fpath}.json")
        except Exception as e:
            logger.error(f"Error in writing logs into {fpath}.json: {e}.")
            raise

    def agent_finish(self, observation: str):
        """Finalizes the agent's task with a final observation.

        This method is called when the agent has completed its task.

        Args:
            observation (str): The final observation to be added to the shared memory.
        """
        self.update_memory(observation)

    def step(self, observation: str):
        """Performs a single step in the agent's reasoning process.

        This method should be implemented by subclasses to define the agent's behavior
        for each step of its task.

        Args:
            observation (str): The current observation for this step.

        Returns:
            ReActChain: The updated last step of the agent's reasoning chain.
        """
        raise NotImplementedError("The agents must implement this function.")
