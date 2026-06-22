# Prepare
- think of a release name
- add new O/S versions in pkg/rules/packages-to-build.yml if needed
- update Changelog.md with the release date, name and release summary

# Make a release branch and test packaging
- git checkout -b release-vX.Y.Z[-xxx]
- cargo update
- bump application version in Cargo.toml
- cargo check (to bump the application version in Cargo.lock)
- pushd doc/manual
- make man
- popd
- git add Cargo.toml Cargo.lock Changelog.md pkg/rules/packages-to-build.yml doc/manual/build/man/*.*
- git commit
- git push
- in GH UI invoke the packaging workflow on the release branch
- make a PR for the branch and mention the workflow run URL in the descrption
- review the PR and ensure the workflow succeeds
- dog food: upgrade cascade.nlnetlabs.nl using a package attached as an output artifact to
  the workflow run
- merge the release branch to main

# Merge and release
- git checkout main
- git tag
- git push --tags
- GH should automatically run the packaging workflow again creating run NNNNNNNN
- if successful:
  - publish_helper.sh --dry-run https://github.com/NLnetLabs/cascade/actions/runs/NNNNNNNN
  - publish_helper.sh https://github.com/NLnetLabs/cascade/actions/runs/NNNNNNNN
- create a GH release for the tag based on Changelog.md
- announce via post in the Cascade topic on https://community.nlnetlabs.nl/.
  - remember to tag it as #release.

# Prepare for development
- git checkout -b prep-for-dev
- bump application version in Cargo.toml to -dev
- cargo check (to bump the application version in Cargo.lock)
- git add Cargo.toml Cargo.lock
- git commit
- git push
- make a PR for the branch
- review the PR and ensure the workflow succeeds
- merge the prep-for-dev branch to main

# Final steps
- Upgrade cascade.nlnetlabs.nl to the now published released package.
  - This shouldn't involve any actual changes as it should be the same package as was
    already upgraded using a workflow output artifact above, but does check that the
    package is actually available on packages.nlnetlabs.nl as expected

TODO: Add crates.io related publishing steps.
