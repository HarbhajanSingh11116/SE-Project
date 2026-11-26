"""Unified LLM runtime supporting user's fine-tuned Qwen2.5-3B LoRA adapters (agent1, agent2),
base Qwen2.5-3B-Instruct, and a fast deterministic fallback for tests / CPU demos."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from config import AGENT1_ADAPTER_DIR, AGENT2_ADAPTER_DIR, BASE_MODEL_ID
from security.masking import mask_payload

logger = logging.getLogger(__name__)


class LLMEngine:
    """Manages local GPU 4-bit Qwen2.5-3B + PEFT adapters or deterministic offline execution."""

    def __init__(self, mode: str = "auto") -> None:
        """mode: 'auto' | 'local_gpu' | 'deterministic'"""
        self.requested_mode = mode
        self.active_mode = "deterministic"
        self.model = None
        self.tokenizer = None
        self.loaded_adapters: set[str] = set()
        self.load_error: str | None = None

        if mode == "local_gpu":
            self._try_load_local_gpu()
        elif mode == "auto":
            # In auto mode, defer heavy GPU loading until explicitly requested or available
            self.active_mode = "deterministic"

    def gpu_available(self) -> tuple[bool, str]:
        try:
            import torch

            if torch.cuda.is_available():
                name = torch.cuda.get_device_name(0)
                vram = round(torch.cuda.get_device_properties(0).total_memory / (1024**3), 2)
                return True, f"{name} ({vram} GB VRAM)"
            return False, "No CUDA GPU detected (CPU only)"
        except Exception as exc:
            return False, f"PyTorch not ready: {exc}"

    def _try_load_local_gpu(self) -> bool:
        try:
            import torch
            from peft import PeftModel
            from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

            if not torch.cuda.is_available():
                self.load_error = "CUDA GPU not available; falling back to deterministic mode."
                self.active_mode = "deterministic"
                return False

            self.tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_ID)
            load_kwargs: dict[str, Any] = {"device_map": "auto"}
            if "bnb-4bit" not in BASE_MODEL_ID.lower():
                load_kwargs["quantization_config"] = BitsAndBytesConfig(
                    load_in_4bit=True,
                    bnb_4bit_quant_type="nf4",
                    bnb_4bit_compute_dtype=torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16,
                    bnb_4bit_use_double_quant=True,
                )
            base_model = AutoModelForCausalLM.from_pretrained(BASE_MODEL_ID, **load_kwargs)

            a1_path = Path(AGENT1_ADAPTER_DIR)
            a2_path = Path(AGENT2_ADAPTER_DIR)
            if a1_path.exists():
                self.model = PeftModel.from_pretrained(base_model, str(a1_path), adapter_name="agent1")
                self.loaded_adapters.add("agent1")
                if a2_path.exists():
                    self.model.load_adapter(str(a2_path), adapter_name="agent2")
                    self.loaded_adapters.add("agent2")
            elif a2_path.exists():
                self.model = PeftModel.from_pretrained(base_model, str(a2_path), adapter_name="agent2")
                self.loaded_adapters.add("agent2")
            else:
                self.model = base_model

            self.model.eval()
            self.active_mode = "local_gpu"
            self.load_error = None
            return True
        except Exception as exc:
            logger.warning("Failed to load local GPU model: %s", exc)
            self.load_error = str(exc)
            self.active_mode = "deterministic"
            return False

    def generate(
        self,
        messages: list[dict[str, str]],
        adapter: str | None = None,
        max_new_tokens: int = 900,
        temperature: float = 0.2,
    ) -> tuple[str, dict[str, int]]:
        """Mask messages, invoke selected adapter (or base model), and return (response, mask_counts)."""
        safe_messages, mask_counts = mask_payload(messages)

        if self.active_mode != "local_gpu" or self.model is None or self.tokenizer is None:
            return "", mask_counts

        import torch

        if hasattr(self.model, "set_adapter") and hasattr(self.model, "disable_adapter"):
            if adapter and adapter in self.loaded_adapters:
                self.model.set_adapter(adapter)
                ctx_manager = None
            else:
                ctx_manager = self.model.disable_adapter()
        else:
            ctx_manager = None

        inputs = self.tokenizer.apply_chat_template(
            safe_messages,
            tokenize=True,
            add_generation_prompt=True,
            return_tensors="pt",
            return_dict=True,
        ).to(self.model.device)

        do_sample = temperature > 0.0
        gen_kwargs: dict[str, Any] = {
            "max_new_tokens": max_new_tokens,
            "do_sample": do_sample,
            "use_cache": True,
        }
        if do_sample:
            gen_kwargs["temperature"] = temperature

        with torch.no_grad():
            if ctx_manager is not None:
                with ctx_manager:
                    outputs = self.model.generate(**inputs, **gen_kwargs)
            else:
                outputs = self.model.generate(**inputs, **gen_kwargs)

        prompt_len = inputs["input_ids"].shape[1]
        decoded = self.tokenizer.decode(outputs[0][prompt_len:], skip_special_tokens=True)
        return decoded.strip(), mask_counts
