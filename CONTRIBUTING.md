# Contributing to AegisIR

Contributions should prioritize correctness, safety and explainability over one-click destructive automation. Run `make test` and `make smoke` before submitting changes. Each new Linux collector requires bounded scope, warnings for missing coverage, sample fixture tests, no credential collection and operator help. Each rule requires a benign counterexample and evidence-linked explanation. Each response action requires independent security review, explicit authorization, rollback and verified outcome.

Do not commit live incident databases, personal information, malware binaries or secrets. Format Go files with `gofmt`; keep the Python engine compatible with Python 3.10+. Consult the documented threat model and project implementation roadmap.
