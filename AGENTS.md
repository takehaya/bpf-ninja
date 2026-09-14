# Agent instructions

The OCR section below applies only when `.ocr/skills/SKILL.md` exists locally.
If it is absent, skip OCR-specific steps and review with the available tools.
Do not install OCR just to follow these instructions.

<!-- OCR:START -->
## Open Code Review Instructions

These instructions are for AI assistants handling code review in this project.

Always open `.ocr/skills/SKILL.md` when the request:
- Asks for code review, PR review, or feedback on changes
- Mentions "review my code" or similar phrases
- Wants multi-perspective analysis of code quality
- Asks to map, organize, or navigate a large changeset

Use `.ocr/skills/SKILL.md` to learn:
- How to run the 8-phase review workflow
- How to generate a Code Review Map for large changesets
- Available reviewer personas and their focus areas
- Session management and output format

Keep this managed block so `ocr init` can refresh the instructions.
<!-- OCR:END -->

## Optional private document workspace

Private documents live in the sibling `../bpf-ninja-private` repository.
Resolve this path relative to this repository's root.

Check whether that directory exists before following private workspace references.
If it is absent, ignore those references and continue normal work in this
repository. Do not clone it or request access just to follow these instructions.
If the user's task explicitly requires unavailable private material, report that
missing prerequisite for the task.

When the private repository is present, before creating, moving, editing, or
preparing publication of private documents,
read `../bpf-ninja-private/README.md` and follow
`../bpf-ninja-private/docs/private-document-workflow.md`.
That document is the shared procedure for people and agents, including ownership,
preservation, commit/push, cleanup, and completion reporting. Read it in each new
session handling these tasks; do not rely on previous conversation history.
Public implementation work follows CONTRIBUTING.md in this repository.
