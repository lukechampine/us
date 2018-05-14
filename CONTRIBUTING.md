# Contributing

Thank you for your interest in contributing to the `us` project.

The golden rule of contributing is: **Propose what you plan to do before you
do it.** Submitting a big PR with no warning is bad manners. It imposes social
pressure on the maintainer to accept the PR, regardless of its quality,
because to reject the PR means discarding the hard work of the contributor. Of
course, if a bad PR is accepted, the quality of the project suffers.
Discussing potential changes in advance can prevent these lose-lose
situations. If the contributor and maintainer disagree on something, they can
arrive at a decision before any code is written, saving everyone time and
frustration.

This rule does not apply to small PRs. Small PRs are more likely to be
accepted, and if they are rejected, the amount of wasted effort isn't terribly
large. Please note, however, that "small" in this context does not mean "under
100 lines of code changed." Adding a test, correcting a bunch of spelling
errors, or running existing code through a linter are all small PRs, even
though they may change hundreds of lines. Conversely, you may invest days of
effort optimizing a 50-line function, only to find out later that your
optimization backfires under real-world conditions, or that the function was
slated to be removed entirely as part of a larger refactor. Use your best
judgment when deciding what counts as "small," but when in doubt, err on the
side of caution and propose your change first.

The preferred method of proposing a change is to open a GitHub issue with the
`Proposal` prefix, e.g. `Proposal: new chunk caching algorithm`. The issue
should contain a description of the problem being addressed and a basic
outline of how you intend to fix it. You can propose changes via other
channels, like Discord, but GitHub is preferred because it leaves a permanent
record of the discussion that can be referenced later.

You are also welcome to propose changes that you do not intend to implement
yourself. Instead of `Proposal`, prefix these with `Suggestion`, e.g.
`Suggestion: allow custom User-Agent string`. A suggestion does not need to be
a feature request; it can propose refactoring a function, expanding
documentation, or any other issue relevant to the project, e.g. `Suggestion:
add spellcheck pre-commit hook`. Also note that, unlike proposals, suggestions
do not need to include an implementation plan.


## Finding something to work on

Check the issue tracker for bugs. If you see one you'd like to work on, be
sure to announce your intent on the issue thread. Issues marked `Suggestion`
are good targets as well, but again, announce your intent. Since suggestions
may not include an implementation plan, you should specify one in the issue
thread and discuss it with the maintainer before writing any code.


## Code and commit hygiene

Run `make lint` before submitting your PR. You will need
[`gometalinter`][meta]. In general, try to mimic the style of surrounding
code. Go's [CodeReviewComments][crc] is a good resource.

Git commits should follow the seven rules in [How to Write a Git Commit
Message][commit]. Also, prefix each commit message with the package(s) it
affects, e.g. `proto: Reduce SectorMerkleRoot allocations`. Lastly, put any
references to issues (e.g. `Fixes #1234`) in the GitHub issue body, **not** in
the commit message. This prevents an issue from being referenced over and over
by the same commit when amending/rebasing.

Don't be afraid to rebase heavily when modifying a PR in response to review
comments. Avoid commits with messages like `Address review comments`. These
should be squashed into previous commits. [`fixup` and `autosquash`][fixup]
are your friends here.


[meta]: https://github.com/alecthomas/gometalinter
[crc]: https://github.com/golang/go/wiki/CodeReviewComments
[commit]: https://chris.beams.io/posts/git-commit
[fixup]: https://fle.github.io/git-tip-keep-your-branch-clean-with-fixup-and-autosquash.html
