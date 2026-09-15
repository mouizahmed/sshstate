# sshstate

## Comments

Do not write comments in Go code. None.

The only comments in this repository are the two license header lines every
file starts with:

```go
// Copyright (C) 2026 Mouiz Ahmed
// SPDX-License-Identifier: AGPL-3.0-only
```

and `//go:build` constraints where a file needs one.

This includes doc comments on exported identifiers, comments inside test
functions explaining what an assertion proves, and one-line notes above a
tricky expression. Write code whose names and structure carry the meaning
instead. If something genuinely cannot be understood without prose, it belongs
in `docs/`, not beside the code.

Comments bloat the codebase and every context window that reads it.

## Commits

Subject line only, no body. Author is `Mouiz Ahmed <mouiza@my.yorku.ca>` and
nobody else: no `Co-Authored-By`, no generation notices, no session links, no
trailers of any kind.

Split work into small commits and verify each one builds and tests green on its
own. Do not push; the user pushes.

## Testing

Mutation-check anything load-bearing: break the code the test names and confirm
the test fails. A test that passes with the invariant removed is recorded as a
defect in `docs/defects.md`, not quietly fixed.
