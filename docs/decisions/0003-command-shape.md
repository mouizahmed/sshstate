# 0003 — Flat verbs, positional subjects

Accepted 2026-09-15.

## Context

The brief §3.1 sketches `sshstate server connect <url>`, `sshstate rotation
status` and `sshstate rotation resume` — two-word subcommands — while every
other verb in the same list is flat. The implementation shipped `connect` rather
than `server connect`, without recording why.

Separately, three verbs that act on one record disagreed about where the record
goes: `resolve <id>` and `revoke <id>` took it positionally, and
`trust --approve <id>` took it as a flag. `trust` was the newest and the odd one
out.

Rotation is still unwritten. Settling the shape now costs nothing; settling it
after `rotation status` exists means either living with an inconsistency or
breaking a verb people have started using.

## Decision

**Verbs are flat.** `connect`, not `server connect`. Rotation will be `rotate`,
`rotation-status` and `rotation-resume` — three flat verbs rather than a `rotation`
group.

**The subject is positional. Flags are options.** `sshstate trust <id>...`
replaces `--approve`; `--all` remains, because "every pending observation" is not
a subject. Every verb that names one record now reads the same way:

```
sshstate resolve <conflict-id> [--resurrect]
sshstate revoke  <device-id>   [--yes]
sshstate remove  <alias>       [--yes]
sshstate trust   <id>...       | --all
```

**A subject may be given by unique prefix.** Record ids are 128 bits of
hexadecimal and are read off a listing, not typed from memory. `resolve`,
`revoke`, `trust` and `remove-key` accept any unambiguous prefix; an ambiguous
one is refused and the candidates are listed. Keys additionally accept a
fingerprint or a comment, because those are what the user recognises.

Full ids keep working everywhere, so anything already scripted is unaffected.

## Consequences

This is an amendment to §3.1's command list: `server connect` and the
`rotation` subcommand group are withdrawn in favour of flat verbs, and `trust`
gains a positional form.

`--approve` is gone rather than deprecated. It shipped in this milestone and has
never been in a release, so nothing outside this repository can depend on it.

Prefix matching means a subject that is unique today can become ambiguous later,
when a second record shares its prefix. That is the correct failure: the command
refuses and names both, rather than picking one. Scripts that want stability
should use full ids, which is what the listings print.
