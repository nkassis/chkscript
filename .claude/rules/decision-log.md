---
paths: docs/decisions-*.md
---

# Writing the decision log

The reader is a senior engineer who has not seen the code, has ten minutes, and is deciding whether to trust the author. Write for them, not for the commit history.

## What earns an entry

A decision goes in the log only if all three hold:

1. A competent engineer could reasonably have chosen otherwise.
2. Reversing it later would cost more than a day.
3. The reason is not already implied by an earlier decision or the stack.

Everything else belongs in a commit message, a docstring, or nowhere. "Added pydantic" is not a decision. "Contract models are pydantic rather than dataclasses so JSON Schema is generated, not hand-written" might be, if someone could argue for the other side.

If a reader could not disagree with the entry, it is not a decision. Cut it.

When a fork passes all three tests and the alternatives are real, invoke `/decide` before writing the code or the entry. Do not pick.

## Shape of an entry

Under 150 words. Numbered, number never reused.

- **Title** states the choice, not the topic. "Relay is a single-active consumer", not "Relay design".
- **Why** in one or two sentences, with the constraint that forced it.
- **Instead of** names the alternative that was seriously considered and the specific reason it lost. One alternative is usual. Do not list options nobody weighed.
- **Cost** states what we gave up or what this makes harder. Every decision has one. An entry with no cost is incomplete.
- **Status** is Accepted, or Superseded by N (or by a named PR when no decision replaces it). Never delete or rewrite an entry; add a new one and mark the old one.

## Voice

- Active, declarative, present tense. "The relay acks after publish." Not "it was decided that".
- Name numbers that drove the choice (2.0 s budget, delivery limit 5). Leave out numbers that didn't.
- No hedging, no "best practice", no "for flexibility". If the reason is a guess, say it is a guess and what would confirm it.
- Do not restate what the code does. State why it does it that way.
- No narrative of how the decision was reached, no dates, no "after discussion".

## When to write

Draft the entry when the decision is made, before the code. Revise it at PR time. Include new or changed entries in the PR summary so they get reviewed like code. After drafting, cut a third.
