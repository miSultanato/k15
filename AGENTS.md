# AGENTS.md

## Purpose
k15 turns a directory of static files into a bootable x86-64 HTTPS server image. Its public scope is a small, deliberately limited, TLS 1.3-only static server. This file contains only public project guidance.

## Security invariants
- Security must never be lowered; any change affecting packet handling, TLS, cryptography, memory safety, executable memory, boot, or HTTP parsing requires careful threat-oriented review.
- Preserve the deliberately constrained product scope. Do not add a general-purpose OS, shell, filesystem, dynamic application runtime, or outbound network capability.
- Do not weaken TLS, cryptographic checks, constant-time behavior, memory protections, or fail-stop behavior for convenience or size without explicit project-owner approval.
- Treat all network input as hostile. Review bounds, parser state, lengths, integer arithmetic, and state transitions.
- Never commit private keys, certificates, generated images, or contents of build/cert directories.

## Working method
- Read README.md and the relevant sections of docs/commands.md, docs/internals.md, docs/server.md, docs/pitfalls.md and bench/README.md before changing the corresponding area.
- Keep AGENTS.md short; put implementation details, history, measurements and pitfalls in their canonical docs.
- Preserve reproducible tests appropriate to the change. Distinguish local tests, external test suites, CI and production observations.
- Do not claim security or performance from inspection alone; state the exact evidence and limitations.
- Do not take the public service offline, deploy an image, reset/delete a server, or run cost-incurring load tests without explicit authorization.
- Review generated artifacts and secrets carefully; do not expose credentials in logs or commits.

## Git and automation
- Check branch, working tree and exact commit before editing.
- Follow the repository's existing contribution rules and branch protection; do not bypass review.
- For this public repository, do not add workflows or triggers, deploy, or publish changes without explicit approval.
