# Contributing

Keep user guides, architecture documentation, and reproducible public examples
in this repository. Keep unpublished drafts, internal issue notes, review memos,
and raw research data in a separate private repository.

The reserved private paths are listed in `.public-content-policy.json` and
excluded by `.gitignore`. Published papers and talks belong under
`docs/publications/<name>/`. Prepare a separate public version and copy only
explicitly selected files; do not merge a private branch or its history.
Check embedded speaker notes, document metadata, links, and build dependencies
before pushing a publication branch. A public draft PR is already public.

Install the local checks after cloning (Python 3 and Lefthook are required):

```sh
lefthook install
python3 scripts/check-public-content.py --index
python3 scripts/check-public-content.py --head HEAD
```

The existing Lefthook configuration checks the index before a commit and reads
the exact refs passed by Git before a push. It checks every newly introduced
commit, including files added and subsequently deleted. New branches and tags
are checked relative to the fixed history baseline in the policy, not a guessed
upstream branch. That baseline leaves historical cleanup as a separate task;
the tip of every ref is always checked. Missing history causes a failure.

The `Public content` workflow runs the same check in CI. CI runs after upload;
local checks and keeping drafts outside the public checkout provide the earlier
protection. These path checks do not identify private content copied under a
different name, and local hooks can be bypassed. Review publication content
before uploading it. Private credentials are never needed to build or test the
public repository.

Run the guard's tests with:

```sh
python3 -m unittest discover -s scripts/tests -p 'test_public_content.py'
```

## Bytecode golden

`pkg/kunai/dsltest/testdata/golden` pins the bytecode kunai emits for every
filter the spec vectors compile and for a curated list (the evaluation filter
set, the tc load matrix, and a few netfilter and set filters). `go test ./...`
compares against it, so a refactor that should not change the output needs no
extra step.

When a change is meant to move bytecode or warnings, run `make golden-update`
and commit the result. It prints each filter that moved, with its instruction
counts and which part changed (`code` for the instructions, `meta` for the
capture length, set extractions and warnings). The curated `.asm` files show
the change as text. `make golden-diff GOLDEN_BASE=main` prints the text diff
of every filter between the base and the working tree, so a reviewer can check
the filters the manifest lists only by hash; an added or removed filter shows
in full against an empty file. The diff leaves out instruction
indexes, so inserted instructions do not renumber the rest of the program;
`GOLDEN_DIFF_INDEX=1` keeps them. To tell the outcomes apart in a script, run
`./scripts/golden-diff.sh BASE` directly: it exits 0 when no filter moved, 1
when one did, and 2 on an error such as a base without the golden test. make
reports any failing recipe as status 2. Adding spec vectors with
`make lean-gen` also needs `make golden-update`, because each new filter gets
a manifest line.

## Command and protocol references

Run `make docs-update` after changing command metadata or public protocol help,
then review `docs/ja/cli/generated/`. `make docs-check` and the normal Go tests
compare the checked-in references without writing them or loading BPF.
The generator uses urfave/cli v3 help and documentation interfaces; keep command
constructors fresh and do not execute capture or map-management actions.
Update the manually authored constraints and examples when behavior changes.
A generated flag table is not a substitute for those explanations.
