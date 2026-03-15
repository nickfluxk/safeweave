---
name: secure-before-push
description: Use this skill automatically before any git commit, git push, or PR creation. Runs a full SafeWeave security scan and blocks unsafe code from being pushed. Triggers on git operations, code completion, and when the user says "commit", "push", "deploy", or "create PR".
---

# Secure Before Push

## Overview

Every code change must pass a SafeWeave security scan before it leaves your machine. No exceptions.

**Core principle:** Scan before you ship.

## When This Skill Activates

**ALWAYS before:**
- `git commit`
- `git push`
- Creating a pull request (`gh pr create`)
- Any variation: "commit this", "push it", "ship it", "deploy", "create a PR", "merge"
- Completing a feature or bugfix
- Running `/commit`

## The Workflow

```
BEFORE any git commit or push:

1. RUN: Use the scan_project MCP tool from SafeWeave
2. CHECK: Review findings for critical and high severity issues
3. DECIDE:
   - CRITICAL or HIGH findings → STOP. Fix them first. Re-scan.
   - MEDIUM findings → Warn the user, ask if they want to proceed
   - LOW/INFO only → Safe to proceed
4. ONLY THEN: Run the git command
```

## How To Scan

Call the SafeWeave MCP tool:

```
Tool: scan_project
```

Or for a single changed file:

```
Tool: scan_file
Arguments: { "file_path": "<path to changed file>" }
```

## Decision Matrix

| Severity | Action | Can Push? |
|----------|--------|-----------|
| CRITICAL | Fix immediately. Show remediation. Re-scan. | NO |
| HIGH | Fix immediately. Show remediation. Re-scan. | NO |
| MEDIUM | Warn user with details. Ask for confirmation. | User decides |
| LOW | Note in commit message if relevant. | YES |
| INFO | No action needed. | YES |

## What To Show The User

After scanning, present a concise summary:

```
Security scan results:
  0 critical | 0 high | 2 medium | 1 low

MEDIUM:
  - SQL injection risk in src/db.ts:45 (CWE-89)
  - Missing input validation in src/api.ts:23 (CWE-20)

Fix these before pushing? (y/n)
```

## If SafeWeave Is Not Configured

If the scan_project tool is not available:

1. Tell the user SafeWeave is not configured
2. Suggest: `npx safeweave-mcp` to set it up
3. Do NOT block the commit — just warn

## Fixing Findings

When the user chooses to fix:

1. Use `suggest_fix` tool with the finding ID to get remediation guidance
2. Apply the fix
3. Re-scan to verify the fix worked
4. Only then proceed with the git operation

## What NOT To Do

- Do NOT skip the scan because "it's a small change"
- Do NOT scan only some files — scan the whole project
- Do NOT ignore high/critical findings
- Do NOT run git push before the scan completes
- Do NOT ask "should I scan?" — just scan. The user installed this skill because they want automatic scanning.

## Integration With Other Skills

This skill works alongside other workflow skills:
- **verification-before-completion**: SafeWeave scan is part of verification
- **test-driven-development**: Security scan runs after tests pass, before commit
- **finishing-a-development-branch**: Scan before merge/PR

## The Bottom Line

Ship secure code. Every time. Automatically.
