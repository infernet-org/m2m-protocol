---
title: Chat Completion Example
description: Annotated wire format example for chat completion
---

# Wire Format Example: Chat Completion

## Request

### Original JSON (156 bytes)

```json
{
  "model": "gpt-4o",
  "messages": [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": "What is the capital of France?"}
  ],
  "temperature": 0.7,
  "max_tokens": 100
}
```

### M2M Compressed (98 bytes, 37% savings)

```
#T1|{"M":"4o","m":[{"r":"s","c":"You are a helpful assistant."},{"r":"u","c":"What is the capital of France?"}],"T":0.7,"x":100}
```

### Byte-by-Byte Breakdown

```
Offset  Bytes       Description
------  -----       -----------
0       23          '#' - Message identifier
1       54 31       "T1" - Algorithm tag (Token v1)
3       7C          '|' - Delimiter
4       7B          '{' - JSON object start
5-12    "M":"4o"    Model (abbreviated from "gpt-4o")
13      2C          ',' - Separator
14-95   "m":[...]   Messages array (abbreviated)
96      2C          ',' - Separator
97-104  "T":0.7     Temperature (abbreviated key)
105     2C          ',' - Separator
106-113 "x":100     Max tokens (abbreviated key)
114     7D          '}' - JSON object end
```

## Response

### Original JSON (312 bytes)

```json
{
  "id": "chatcmpl-abc123",
  "object": "chat.completion",
  "created": 1705520400,
  "model": "gpt-4o",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "The capital of France is Paris."
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 25,
    "completion_tokens": 8,
    "total_tokens": 33
  }
}
```

### M2M Compressed (189 bytes, 39% savings)

```
#T1|{"id":"chatcmpl-abc123","o":"chat.completion","cr":1705520400,"M":"4o","C":[{"i":0,"m":{"r":"a","c":"The capital of France is Paris."},"fr":"s"}],"U":{"pt":25,"ct":8,"tt":33}}
```

### Key Transformations

| Original | Compressed | Savings |
|----------|------------|---------|
| `"object"` | `"o"` | 5 chars |
| `"created"` | `"cr"` | 5 chars |
| `"model"` | `"M"` | 4 chars |
| `"gpt-4o"` | `"4o"` | 4 chars |
| `"choices"` | `"C"` | 6 chars |
| `"index"` | `"i"` | 4 chars |
| `"message"` | `"m"` | 6 chars |
| `"role"` | `"r"` | 3 chars |
| `"assistant"` | `"a"` | 8 chars |
| `"content"` | `"c"` | 6 chars |
| `"finish_reason"` | `"fr"` | 11 chars |
| `"stop"` | `"s"` | 3 chars |
| `"usage"` | `"U"` | 4 chars |
| `"prompt_tokens"` | `"pt"` | 11 chars |
| `"completion_tokens"` | `"ct"` | 15 chars |
| `"total_tokens"` | `"tt"` | 10 chars |

## Streaming Response

### Original SSE Events

```
data: {"id":"chatcmpl-abc123","object":"chat.completion.chunk","created":1705520400,"model":"gpt-4o","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}

data: {"id":"chatcmpl-abc123","object":"chat.completion.chunk","created":1705520400,"model":"gpt-4o","choices":[{"index":0,"delta":{"content":"The"},"finish_reason":null}]}

data: {"id":"chatcmpl-abc123","object":"chat.completion.chunk","created":1705520400,"model":"gpt-4o","choices":[{"index":0,"delta":{"content":" capital"},"finish_reason":null}]}

data: [DONE]
```

### M2M Compressed SSE

```
data: #T1|{"id":"chatcmpl-abc123","o":"chat.completion.chunk","cr":1705520400,"M":"4o","C":[{"i":0,"d":{"r":"a"},"fr":null}]}

data: #T1|{"id":"chatcmpl-abc123","o":"chat.completion.chunk","cr":1705520400,"M":"4o","C":[{"i":0,"d":{"c":"The"},"fr":null}]}

data: #T1|{"id":"chatcmpl-abc123","o":"chat.completion.chunk","cr":1705520400,"M":"4o","C":[{"i":0,"d":{"c":" capital"},"fr":null}]}

data: [DONE]
```

## Tool Call Example

### Original Request with Tools

```json
{
  "model": "gpt-4o",
  "messages": [
    {"role": "user", "content": "What's the weather in Paris?"}
  ],
  "tools": [
    {
      "type": "function",
      "function": {
        "name": "get_weather",
        "description": "Get weather for a location",
        "parameters": {
          "type": "object",
          "properties": {
            "location": {"type": "string"}
          },
          "required": ["location"]
        }
      }
    }
  ]
}
```

### Compressed

```
#T1|{"M":"4o","m":[{"r":"u","c":"What's the weather in Paris?"}],"ts":[{"t":"function","fn":{"n":"get_weather","desc":"Get weather for a location","params":{"t":"object","props":{"location":{"t":"string"}},"req":["location"]}}}]}
```
