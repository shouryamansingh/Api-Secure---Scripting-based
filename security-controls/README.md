# Security Controls — Modular Architecture

This folder defines **security controls** in a modular, reusable, and scalable way. Each control (e.g. HTTP Header Analysis) has its own directory with a standardized structure so it can be used by:

- **n8n** — Copy the prompt and wire input/output as per `input-schema` and `output-schema`.
- **This application** — Load config and prompt to run rule-based or AI-backed analysis.

## Standard control structure

Each control lives in its own folder under `security-controls/`:

```
security-controls/
  <control-id>/           e.g. http-header-analysis
    metadata.json         Control id, name, description, version
    config.json           Configuration (headers to check, severity rules, etc.)
    prompt.md             Full AI prompt (role, scope, input, output, criteria)
    input-schema.json     Expected input for this control
    output-schema.json    Expected output (for reports and downstream)
    README.md             How the control works and how to wire it
```

## Design principles

- **LLM-agnostic prompts** — Written so any model (OpenAI, Anthropic, Gemini, etc.) understands role, scope, input format, output format, and evaluation criteria.
- **Single responsibility** — One control = one security concern (e.g. HTTP headers only).
- **Contract-first** — Input and output are defined by schemas; logic and prompts align to them.
- **Reusable** — Same definition can drive n8n nodes, this app’s scanner, or future tools.

## Controls

| Control ID               | Description                                      |
|--------------------------|--------------------------------------------------|
| `http-header-analysis`   | HTTP/HTTPS response header security assessment  |

## Using a control in n8n

1. Open the control folder (e.g. `http-header-analysis/`).
2. Read `README.md` for the flow (fetch → prepare input → AI → parse output).
3. Use `prompt.md` in your AI/LLM node (copy the prompt and replace `INPUT_PLACEHOLDER` with your node’s output, e.g. `{{ $json.formattedHeaders }}`).
4. Ensure the node that runs before the LLM produces data matching `input-schema.json`.
5. Parse the LLM response according to `output-schema.json` and map into your report (e.g. Process Audit Results).

## Using a control in this app

- **Config** — `config.json` can drive which headers are checked and severity rules (see `scanner.py` and future AI module).
- **Prompt** — When AI is enabled, load `prompt.md`, replace `INPUT_PLACEHOLDER` with the current request’s formatted headers (and optional context), send to the LLM, then parse the response using `output-schema.json`.
