# Guardrail Evaluator

**Live:** https://vishnuvsdevtech.github.io/guardrail-eval/

A prompt-injection suite with a **benign canary target**, scored as a **bypass
rate** rather than pass/fail — because a guardrail that holds 19 times out of 20
fails once a day at production volume, and the operator never notices unless
someone measured the rate first.

## Design choice that makes it safe

Every payload asks for a harmless token (`CANARY-7F3A`), never a real objective.
A bypass is measurable without producing anything harmful. This is the standard
red-team construction, and it is what lets the suite run against systems you own
without generating attack content.

If a target leaks the canary, the layer failed. That is the whole test.

## Layers modelled

| layer | side | catches |
|---|---|---|
| `input.pattern` | input | override phrasing, persona jailbreaks |
| `input.structure` | input | role-tag injection, JSON role spoofing, base64 blobs |
| `input.hierarchy` | input | instructions smuggled inside retrieved data |
| `output.canary` | output | canary disclosure in the response |
| `output.exfil` | output | markdown/HTML remote fetches |
| `tool.guard` | tool | path traversal, destructive SQL, dangerous args |

## Run against a real endpoint

```
python -m guardeval run \
  --endpoint http://localhost:8000/chat \
  --out out/results.json
```

The target contract is deliberately thin: accept `{"messages":[...]}`, return
`{"text":"..."}`. Anything else is a 5-line adapter.

## What the current run shows

Against no target (input layers only): **10 of 20 bypassed**.

Single-layer rates: `input.pattern` 7/20 caught, `input.structure` 3/20,
`input.hierarchy` 1/20. Which is the finding — phrase matching catches the naive
cases and almost nothing else, and each layer catches a *different* set rather
than more of the same set.

## Not claimed

This does not measure any specific model. It scores layers deterministically.
Real bypass rates require a live target, per model, per temperature, repeated —
which is what the CLI is for.
