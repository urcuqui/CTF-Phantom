from ctf_phantom.tools.base import Tool, ToolResult, ToolSpec
from ctf_phantom.tools.control import SUBMIT_FLAG_SPEC, TERMINATE_SPEC, SubmitFlagTool, TerminateTool
from ctf_phantom.tools.http import HTTP_REQUEST_SPEC, HttpTool, ScopeViolation

# The victim's fixed tool surface. Its hash is recorded per run and can be pinned.
TOOL_SPECS: tuple[ToolSpec, ...] = (HTTP_REQUEST_SPEC, SUBMIT_FLAG_SPEC, TERMINATE_SPEC)

__all__ = ["TOOL_SPECS", "HttpTool", "ScopeViolation", "SubmitFlagTool", "TerminateTool", "Tool", "ToolResult",
           "ToolSpec"]
