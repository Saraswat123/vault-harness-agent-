"""Offline scripted writer: returns queued drafts in order, repeating the last. Counts calls."""
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

DEFAULT_DRAFT = "This is the offline draft. Replace the script, or set a model key in .env."


class ScriptedWriter(BaseChatModel):
    drafts: list = [DEFAULT_DRAFT]
    calls: int = 0

    @property
    def _llm_type(self) -> str:
        return "scripted-writer"

    def _generate(self, messages, stop=None, run_manager=None, **kw):
        i = min(self.calls, len(self.drafts) - 1)
        self.calls += 1
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=self.drafts[i]))])
