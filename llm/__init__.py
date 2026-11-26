"""LLM integration layer supporting Local GPU Qwen2.5-3B + LoRA adapters and deterministic mode."""
from llm.engine import LLMEngine
from llm.json_utils import extract_json_payload

__all__ = ["LLMEngine", "extract_json_payload"]
