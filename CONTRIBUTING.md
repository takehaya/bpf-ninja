# Contributing

Keep user guides, architecture documentation, and reproducible public examples
in this repository. Keep unpublished drafts, internal issue notes, review memos,
and raw research data in a separate private repository.

For maintainers, the private repository is `bpf-ninja-private`, checked out
alongside `bpf-ninja`. From this public repository's root, start with
`../bpf-ninja-private/README.md`; it identifies the storage locations and links
to `docs/private-document-workflow.md` inside the private repository. Follow
that workflow when creating, moving, or preparing publication of private
documents. The private repository requires access granted to its collaborators.

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
