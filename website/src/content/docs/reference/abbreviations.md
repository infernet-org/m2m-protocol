---
title: Abbreviations
description: Key/value abbreviation tables for Token compression
---

# Abbreviation Tables

Complete reference for M2M Protocol Token compression mappings.

## Key Abbreviations

### Request Keys

| Original | Abbreviated | Context |
|----------|-------------|---------|
| `messages` | `m` | Chat messages array |
| `content` | `c` | Message content |
| `role` | `r` | Message role |
| `model` | `M` | Model identifier |
| `temperature` | `T` | Sampling temperature |
| `max_tokens` | `x` | Maximum output tokens |
| `top_p` | `p` | Nucleus sampling |
| `stream` | `s` | Enable streaming |
| `stop` | `S` | Stop sequences |
| `n` | `n` | Number of completions |
| `seed` | `se` | Random seed |
| `user` | `u` | User identifier |
| `frequency_penalty` | `f` | Frequency penalty |
| `presence_penalty` | `P` | Presence penalty |
| `logit_bias` | `lb` | Token biases |
| `logprobs` | `lp` | Log probabilities |
| `top_logprobs` | `tlp` | Top log probs count |
| `response_format` | `rf` | Response format |
| `tools` | `ts` | Tool definitions |
| `tool_choice` | `tc` | Tool selection |
| `functions` | `fs` | Function definitions |
| `function_call` | `fc` | Function call mode |

### Response Keys

| Original | Abbreviated | Context |
|----------|-------------|---------|
| `choices` | `C` | Response choices |
| `index` | `i` | Choice index |
| `message` | `m` | Response message |
| `delta` | `d` | Streaming delta |
| `finish_reason` | `fr` | Completion reason |
| `usage` | `U` | Token usage |
| `prompt_tokens` | `pt` | Input tokens |
| `completion_tokens` | `ct` | Output tokens |
| `total_tokens` | `tt` | Total tokens |
| `logprobs` | `lp` | Log probabilities |
| `created` | `cr` | Timestamp |
| `object` | `o` | Object type |
| `system_fingerprint` | `sf` | System fingerprint |

### Tool/Function Keys

| Original | Abbreviated | Context |
|----------|-------------|---------|
| `tool_calls` | `tc` | Tool call array |
| `function` | `fn` | Function definition |
| `name` | `n` | Function name |
| `arguments` | `a` | Function arguments |
| `type` | `t` | Tool type |
| `description` | `desc` | Tool description |
| `parameters` | `params` | Function parameters |
| `required` | `req` | Required parameters |
| `properties` | `props` | Parameter properties |

## Value Abbreviations

### Role Values

| Original | Abbreviated |
|----------|-------------|
| `system` | `s` |
| `user` | `u` |
| `assistant` | `a` |
| `function` | `f` |
| `tool` | `t` |

### Finish Reason Values

| Original | Abbreviated |
|----------|-------------|
| `stop` | `s` |
| `length` | `l` |
| `tool_calls` | `tc` |
| `content_filter` | `cf` |
| `function_call` | `fc` |

### Response Format Types

| Original | Abbreviated |
|----------|-------------|
| `text` | `t` |
| `json_object` | `j` |
| `json_schema` | `js` |

## Model Abbreviations

### OpenAI Models

| Original | Abbreviated |
|----------|-------------|
| `gpt-4o` | `4o` |
| `gpt-4o-mini` | `4om` |
| `gpt-4o-2024-11-20` | `4o1120` |
| `gpt-4o-2024-08-06` | `4o0806` |
| `gpt-4-turbo` | `4t` |
| `gpt-4-turbo-preview` | `4tp` |
| `gpt-4` | `4` |
| `gpt-4-32k` | `432k` |
| `gpt-3.5-turbo` | `35t` |
| `gpt-3.5-turbo-16k` | `35t16k` |
| `o1` | `o1` |
| `o1-mini` | `o1m` |
| `o1-preview` | `o1p` |
| `o3` | `o3` |
| `o3-mini` | `o3m` |

### Meta Llama Models

| Original | Abbreviated |
|----------|-------------|
| `meta-llama/llama-3.3-70b` | `ml3370` |
| `meta-llama/llama-3.3-70b-instruct` | `ml3370i` |
| `meta-llama/llama-3.1-405b` | `ml31405` |
| `meta-llama/llama-3.1-405b-instruct` | `ml31405i` |
| `meta-llama/llama-3.1-70b` | `ml3170` |
| `meta-llama/llama-3.1-70b-instruct` | `ml3170i` |
| `meta-llama/llama-3.1-8b` | `ml318` |
| `meta-llama/llama-3.1-8b-instruct` | `ml318i` |

### Mistral Models

| Original | Abbreviated |
|----------|-------------|
| `mistralai/mistral-large` | `mim-l` |
| `mistralai/mistral-large-latest` | `mim-ll` |
| `mistralai/mistral-medium` | `mim-m` |
| `mistralai/mistral-small` | `mim-s` |
| `mistralai/mixtral-8x7b` | `mimx87` |
| `mistralai/mixtral-8x22b` | `mimx822` |
| `mistralai/codestral-latest` | `micodl` |

### DeepSeek Models

| Original | Abbreviated |
|----------|-------------|
| `deepseek/deepseek-v3` | `ddv3` |
| `deepseek/deepseek-r1` | `ddr1` |
| `deepseek/deepseek-coder` | `ddc` |
| `deepseek/deepseek-chat` | `ddchat` |

### Qwen Models

| Original | Abbreviated |
|----------|-------------|
| `qwen/qwen-2.5-72b` | `qq2572` |
| `qwen/qwen-2.5-32b` | `qq2532` |
| `qwen/qwen-2.5-coder-32b` | `qqc32` |

## Default Values

Parameters with these values MAY be omitted during compression.

| Parameter | Default Value |
|-----------|---------------|
| `temperature` | `1.0` |
| `top_p` | `1.0` |
| `n` | `1` |
| `stream` | `false` |
| `frequency_penalty` | `0` |
| `presence_penalty` | `0` |
| `logit_bias` | `{}` |
| `stop` | `null` |
| `logprobs` | `false` |

## Compression Example

### Original Request

```json
{
  "model": "gpt-4o",
  "messages": [
    {"role": "system", "content": "You are helpful."},
    {"role": "user", "content": "Hello!"}
  ],
  "temperature": 1.0,
  "max_tokens": 100,
  "stream": false
}
```

### Compressed Request

```
#T1|{"M":"4o","m":[{"r":"s","c":"You are helpful."},{"r":"u","c":"Hello!"}],"x":100}
```

### Transformations Applied

1. `model` → `M`
2. `gpt-4o` → `4o`
3. `messages` → `m`
4. `role` → `r`
5. `system` → `s`
6. `content` → `c`
7. `user` → `u`
8. `max_tokens` → `x`
9. `temperature: 1.0` → omitted (default)
10. `stream: false` → omitted (default)
