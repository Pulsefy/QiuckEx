## Summary

This PR contains the source fix for the QuickEx contract work on this branch, without the generated fuzz snapshot artifacts that were previously polluting the branch history.

## What changed

- Removed generated JSON snapshot noise from the branch history and remote branch state.
- Kept only the relevant source changes needed for the contract fix.
- Ensured the branch is aligned to the current target branch and ready for review.

## Validation

- Rust contract tests were run and passed on the relevant quickex contract scope.
- Clippy and formatting checks were validated on the cleanup branch.

## Notes

- The branch history was rewritten to remove generated snapshot files from the pushed remote branch.
- This keeps the PR focused on the actual code changes rather than generated artifacts.
