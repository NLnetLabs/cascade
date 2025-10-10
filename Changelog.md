# Changelog

<!-- Changelog template (remove empty sections on release of a version)
## Unreleased version

Released yyyy-mm-dd.

### Breaking changes
### New
### Bug fixes
### Other changes
### Documentation improvements
### Known issues
### Acknowledgements
-->

## Unreleased version

Released yyyy-mm-dd.

### Breaking changes


### New


### Bug fixes

- Resume the pipeline when a new zone is loaded by @bal-e and @ximon18 ([#153])
- Set default CLASS for loaded zone files to IN by @mozzieongit ([#164])
- Fix home directory for useradd cascade in packages by @mozzieongit ([#171])

### Other changes

- Remove non-existing variable in example review script comment by @jpmens
  ([#196])
- Set homepage and documentation properties in Cargo.toml by @maertsen
  (98d988d0)


### Documentation improvements

- Add documentation about integrating with a SmartCard-HSM by @jpmens ([#191])
- Make it clear that state is human-readable but not writable by @mozzieongit
  and @maertsen ([#188])
- Explicitly mention the need for config reload in the config file format man
  page by @mozzieongit ([#181])
- Use proposed/testing names where appropriate by @ximon18 ([#170])
- Remove a broken link by @ximon18 (bbae66af)
- Fix the "unit-time" policy setting documentation by @jpmens ([#167])
- Document that some policy options also require a restart by @mozzieongit
  (6cdc126)

### Known issues


### Acknowledgements

Many thanks go to @jpmens and @bortzmeyer for trying out the alpha release of
Cascade and extensively reporting the issues they found.


[#153]: https://github.com/NLnetLabs/cascade/pull/153
[#164]: https://github.com/NLnetLabs/cascade/pull/164
[#167]: https://github.com/NLnetLabs/cascade/pull/167
[#170]: https://github.com/NLnetLabs/cascade/pull/170
[#171]: https://github.com/NLnetLabs/cascade/pull/171
[#181]: https://github.com/NLnetLabs/cascade/pull/181
[#188]: https://github.com/NLnetLabs/cascade/pull/188
[#191]: https://github.com/NLnetLabs/cascade/pull/191
[#196]: https://github.com/NLnetLabs/cascade/pull/196


## 0.1.0-alpha 'Globen'

Released 2025-10-07

Initial release
