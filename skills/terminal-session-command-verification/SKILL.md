---
name: "terminal-session-command-verification"
description: "Run shell commands through a persistent interactive terminal session with read-back verification before reporting results."
---

# Terminal Session Command Verification

Use this when driving a persistent interactive shell (e.g. the `openclaw:core:terminal` tool with `open` / `input` / `read` actions) instead of one-shot command execution.

## Procedure

1. Open the session once with the working directory set; keep the returned `sessionId` for all later calls. Criterion: the open result returns `ok: true` and a `sessionId`.
2. Send each command with `input`, ending the data with a newline. Criterion: the input call returns success.
3. Read the session output with `read` before treating the command as done. Criterion: the echoed command line matches exactly what you sent and the expected output or a fresh prompt appears after it.
4. Inspect the echoed line for corruption. Persistent sessions can carry leftover partial input from earlier aborted work, which gets prepended to your command (observed: a stray `ed` prefix produced `bash: ed: command not found` and the real command never ran). Criterion: the echoed line starts with your command, not with unexpected leading text.
5. If the echo is corrupted or a `command not found` / syntax error appears, resend the identical command once and re-read. Criterion: the resent command echoes cleanly and completes.
6. Never report a command's result without having read output that shows it actually executed. Criterion: every claimed outcome (commit created, push succeeded, PR URL) is backed by a line in the read output.
7. When the task ends, note any state the session left behind (diverged local branch, uncommitted files) for the user. Criterion: the final message lists leftover state or states there is none.

## Guardrails

- Reuse one session per task; do not open parallel sessions for the same job.
- A rejected `git push` to a protected branch (`GH006` / required status checks) means branch plus pull request, not a retry of the same push.
