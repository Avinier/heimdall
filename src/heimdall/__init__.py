"""
Heimdall - A Python security testing and web application vulnerability scanning framework
"""

__version__ = "0.1.0"
__author__ = "Avinier"

from .agents import PlannerAgent, ActionerAgent, ContextManagerAgent
from .tools.webproxy import WebProxy
from .tools.pagedata_extractor import PageDataExtractor
from .tools.browser import PlaywrightTools
from .tools.llms import LLM

__all__ = [
    "PlannerAgent",
    "ActionerAgent", 
    "ContextManagerAgent",
    "WebProxy",
    "PageDataExtractor",
    "PlaywrightTools",
    "LLM",
]

def main() -> None:
    print("Heimdall Security Testing Framework v" + __version__)
    print("Use 'heimdall --help' for usage information")
