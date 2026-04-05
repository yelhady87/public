# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Structure

This is a public portfolio repository. Each work item lives on its own branch — do not merge feature branches into `master`. The `master` branch holds only shared scaffolding (README, LICENSE, CLAUDE.md).

Current branches:
- `master` — shared scaffolding only
- `oauth_clients` — sample app to register OAuth clients

## Workflow

When adding a new work item:
1. Create a new branch off `master` (naming convention: `<topic>`, e.g. `oauth_clients`)
2. Develop the work item on that branch
3. Do not open PRs targeting `master` unless updating shared scaffolding
