# Enterprise IAM Workspace Instructions

These instructions apply across the repository. Keep them lightweight so the detailed workflow can remain in the `karpathy-guidelines` skill.

## Core Expectations

- Make the smallest change that fully solves the request.
- Match existing code style, naming, and structure.
- Do not refactor unrelated code while fixing a targeted issue.
- If a request is ambiguous or has multiple reasonable interpretations, surface that clearly before making a risky choice.
- Prefer root-cause fixes over surface patches when the scope is still small and controlled.

## Verification

- Define a concrete success check for non-trivial changes.
- Run the narrowest relevant validation available, such as targeted tests, linting, or a build step.
- If validation cannot be run, say so and explain why briefly.

## Scope Control

- Remove any code your change makes unused.
- Leave pre-existing dead code or adjacent cleanup alone unless the task asks for it.
- Keep comments and documentation changes tightly tied to the behavior you changed.

For fuller guidance on planning, simplicity, and surgical edits, use the `karpathy-guidelines` skill.