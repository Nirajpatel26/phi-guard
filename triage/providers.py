"""Single entry point for LLM calls, behind a small provider interface.

PHI_GUARD_LLM_PROVIDER = mock (default) | anthropic | openai
PHI_GUARD_LLM_MODEL    = model id override
ANTHROPIC_API_KEY / OPENAI_API_KEY

Only infrastructure findings (resource names, file paths, control text) are ever
sent to a provider. Runtime PHI alerts are never passed to this module.
Uses plain HTTPS via `requests` so no vendor SDK is required.
"""
from __future__ import annotations

import os
import textwrap
from typing import Protocol

import requests

DEFAULT_MODELS = {"anthropic": "claude-sonnet-5-5", "openai": "gpt-4.1-mini"}


class Provider(Protocol):
    name: str
    model: str

    def complete(self, system: str, user: str, context: dict) -> str: ...


class MockProvider:
    """Deterministic, offline. Builds the answer from mapping.yaml so the pipeline runs without a key."""

    name = "mock"
    model = "mock-template-v1"

    def complete(self, system: str, user: str, context: dict) -> str:
        import json

        f, c = context["finding"], context["control"]
        target = f.get("file") or ("main.tf" if c["remediation"]["format"] == "terraform" else "manifest.yaml")
        res = f["resource"]
        name = res.split(".", 1)[1] if "." in res and "/" not in res else res.rsplit("/", 1)[-1]
        parts = res.split("/")
        snippet_text = textwrap.dedent(c["remediation"]["snippet"]).rstrip().replace("<name>", name)
        if len(parts) >= 2:
            snippet_text = snippet_text.replace("<namespace>", parts[-1] if parts[0] == "Namespace" else parts[1])
        snippet = snippet_text.splitlines()
        diff = "\n".join([f"--- a/{target}", f"+++ b/{target}",
                          f"@@ {f['resource']} (line {f.get('line') or '?'}) @@",
                          *[f"+{line}" for line in snippet]])
        summary = (f"{f['resource']} fails {c['id']} ({c['title'].rstrip('.')}). {c['risk']} "
                   f"This maps to {c['citation']} ({c['safeguard']}). Detected by {f['engine']} check "
                   f"{f['check_id']}: {f.get('message') or 'see control description'}.")
        return json.dumps({
            "finding_id": f["finding_id"], "control_id": c["id"], "hipaa_citation": c["citation"],
            "severity": c["severity"], "risk_summary": summary[:1200],
            "suggested_fix": {"format": c["remediation"]["format"], "diff": diff},
            "confidence": "medium",
        })


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, api_key: str, model: str | None = None) -> None:
        self.api_key, self.model = api_key, model or DEFAULT_MODELS["anthropic"]

    def complete(self, system: str, user: str, context: dict) -> str:
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": self.model, "max_tokens": 1500, "temperature": 0, "system": system,
                  "messages": [{"role": "user", "content": user}]},
            timeout=60,
        )
        r.raise_for_status()
        return "".join(b.get("text", "") for b in r.json().get("content", []) if b.get("type") == "text")


class OpenAIProvider:
    name = "openai"

    def __init__(self, api_key: str, model: str | None = None) -> None:
        self.api_key, self.model = api_key, model or DEFAULT_MODELS["openai"]

    def complete(self, system: str, user: str, context: dict) -> str:
        r = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"authorization": f"Bearer {self.api_key}", "content-type": "application/json"},
            json={"model": self.model, "temperature": 0, "response_format": {"type": "json_object"},
                  "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]},
            timeout=60,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


def get_provider(name: str | None = None) -> tuple[Provider, str]:
    """Returns (provider, note). Falls back to mock (with a note) when a key is missing."""
    name = (name or os.getenv("PHI_GUARD_LLM_PROVIDER", "mock")).lower()
    model = os.getenv("PHI_GUARD_LLM_MODEL") or None
    if name == "anthropic":
        key = os.getenv("ANTHROPIC_API_KEY")
        if key:
            return AnthropicProvider(key, model), ""
        return MockProvider(), "ANTHROPIC_API_KEY not set; using mock provider"
    if name == "openai":
        key = os.getenv("OPENAI_API_KEY")
        if key:
            return OpenAIProvider(key, model), ""
        return MockProvider(), "OPENAI_API_KEY not set; using mock provider"
    if name != "mock":
        return MockProvider(), f"unknown provider {name!r}; using mock provider"
    return MockProvider(), ""
