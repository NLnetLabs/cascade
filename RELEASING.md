# Prepare
- think of a release &lt;NAME&gt;
- add new O/S versions in `pkg/rules/packages-to-build.yml` if needed
- update `Changelog.md` with the release date, version X.Y.Z[-NNN], &lt;NAME&gt; and release summary

# Make a release branch and test packaging
- `git checkout -b release-vX.Y.Z[-xxx]`
- `cargo update`
- bump application version in `Cargo.toml` to X.Y.Z[-xxx]
- `cargo check` (to bump the application version in Cargo.lock)
- `pushd doc/manual`
- `make man`
- `popd`
- `git add Cargo.toml Cargo.lock Changelog.md pkg/rules/packages-to-build.yml doc/manual/build/man/*.*`
- `git commit`
- `git push`
- `./act-wrapper --rm` - make sure that the integration tests pass
- in GH UI invoke the packaging workflow on the release branch
- make a PR for the branch and mention the workflow run URL in the descrption
- review the PR and ensure the workflow succeeds
- dog food: upgrade cascade.nlnetlabs.nl using a package attached as an output artifact to
  the workflow run
- merge the release branch to main

# Merge and release
- `git checkout main`
- `git tag -a -m "Release vX.Y.Z[-xxx] '<NAME>'"`
- Verify that the release tag version is the same as the Cargo.toml version but with a `v` prefix
- `git push --tags`
- GH should automatically run the packaging workflow again creating run NNNNNNNN
- if successful:
  - `publish_helper.sh --dry-run https://github.com/NLnetLabs/cascade/actions/runs/NNNNNNNN`
  - `publish_helper.sh https://github.com/NLnetLabs/cascade/actions/runs/NNNNNNNN`
- create a GH release with tag vX.Y.Z[-NNN] and title 'X.Y.Z[-NNN] <NAME>"
- close the GH milestone for this release (if any)
- announce via post in the Cascade topic on https://community.nlnetlabs.nl/.
  - remember to tag it as #release.

# Prepare for development
- `git checkout -b prep-for-dev`
- bump application version in `Cargo.toml` to next minor version with suffix `-dev`
- `cargo check` (to also bump the application version in `Cargo.lock`)
- `git add Cargo.toml Cargo.lock`
- `git commit`
- `git push`
- make a PR for the branch
- review the PR and ensure the workflow succeeds
- merge the `prep-for-dev` branch to main
- create a GH milestone for the next release (if needed)

# Final steps
- Upgrade cascade.nlnetlabs.nl to the now published released package.
  - This shouldn't involve any actual changes as it should be the same package as was
    already upgraded using a workflow output artifact above, but does check that the
    package is actually available on packages.nlnetlabs.nl as expected

TODO: Add crates.io related publishing steps.
