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
### Other changes
### Documentation improvements
### Known issues
### Acknowledgements


## 0.1.0-alpha2 "Cascader la vertu'

Released 2025-10-17.

### New

- Added a `cascade health` CLI subcommand by @ximon18 ([#208])
- Added a `cascade status` CLI subcommand by @ximon18 ([#211])
- Add CASCADE_SERVER_IP and CASCADE_SERVER_PORT environment variables for
  review hooks by @mozzieongit ([#213])

### Bug fixes

- Resume the pipeline when a new zone is loaded by @bal-e and @ximon18 ([#153])
- Fix confusing error message when `dnst` is missing by @mozzieongit ([#158])
- Fix panic when started via systemd due to "No such device or address" by
  @mozzieongit ([#163])
- Set default CLASS for loaded zone files to IN by @mozzieongit ([#164])
- Fix home directory for useradd cascade in packages by @mozzieongit ([#171])
- Crashes when server not specified by @mozzieongit ([#172])
- "The TTL of the RRSIG exceeds the value of its Original TTL field" by
  @ximon18 ([#174])
- Fix error on startup "Could not load the state file: invalid type: map,
  expected a string" by @mozzieongit ([#184], [#189])
- Ensure `dnst keyset` warnings are logged and included in zone history
  by @ximon18 ([#207])
- Fix "Cannot acquire the queue semaphore" causing signing to be cancelled
  by @ximon18 ([#209])

### Other changes

- Introduce stdout/stderr log targets to replace using File to log to stdout by
  @mozzieongit ([#176])
- Check for compatible `dnst` on startup by @mozzieongit ([#180])
- Use MultiThreadedSorter for faster sorting before signing by @ximon18
  ([#219])
- Set homepage and documentation properties in Cargo.toml by @maertsen
  (98d988d0)

### Documentation improvements

- Add documentation about integrating with a SmartCard-HSM by @jpmens ([#191])
- Make it clear that state is human-readable but not writable by @mozzieongit
  and @maertsen ([#188])
- Explicitly mention the need for config reload in the config file format man
  page by @mozzieongit ([#181])
- Use proposed/testing names where appropriate by @ximon18 ([#170])
- Fix the "unit-time" policy setting documentation by @jpmens ([#167])
- Remove non-existing variable in example review script comment by @jpmens
  ([#196])
- Add an intro to DNSSEC and a Glossary by @alexanderband ([#206]) 
- Don't fail to show signing statistics for a finished signing operation when
  a signing operation was subsequently aborted by @ximon18 ([#210])
- Improve documentation about review hooks by @mozzieongit ([#216])
- Simplify review script example mention need for faster sorting before
  signing by @mozzieongit ([#218])
- Add key management documentation by @Philip-NLnetLabs ([#225])
- Add approve/reject to cascade-zone man page by @ximon18 ([#227])
- Note steps required to upgare an alpha version of Cascade by @ximon18 ([#230])
- Document that some policy options also require a restart by @mozzieongit
  (6cdc126)
- Remove a broken link by @ximon18 (bbae66af)

### Acknowledgements

Many thanks go to @jpmens and @bortzmeyer for trying out the alpha release of
Cascade and extensively reporting the issues they found.

[#153]: https://github.com/NLnetLabs/cascade/pull/153
[#158]: https://github.com/NLnetLabs/cascade/pull/158
[#163]: https://github.com/NLnetLabs/cascade/pull/163
[#164]: https://github.com/NLnetLabs/cascade/pull/164
[#167]: https://github.com/NLnetLabs/cascade/pull/167
[#170]: https://github.com/NLnetLabs/cascade/pull/170
[#171]: https://github.com/NLnetLabs/cascade/pull/171
[#172]: https://github.com/NLnetLabs/cascade/pull/172
[#174]: https://github.com/NLnetLabs/cascade/pull/174
[#176]: https://github.com/NLnetLabs/cascade/pull/176
[#180]: https://github.com/NLnetLabs/cascade/pull/180
[#181]: https://github.com/NLnetLabs/cascade/pull/181
[#184]: https://github.com/NLnetLabs/cascade/pull/184
[#188]: https://github.com/NLnetLabs/cascade/pull/188
[#189]: https://github.com/NLnetLabs/cascade/pull/189
[#191]: https://github.com/NLnetLabs/cascade/pull/191
[#196]: https://github.com/NLnetLabs/cascade/pull/196
[#206]: https://github.com/NLnetLabs/cascade/pull/206
[#207]: https://github.com/NLnetLabs/cascade/pull/207
[#208]: https://github.com/NLnetLabs/cascade/pull/208
[#209]: https://github.com/NLnetLabs/cascade/pull/209
[#210]: https://github.com/NLnetLabs/cascade/pull/210
[#211]: https://github.com/NLnetLabs/cascade/pull/211
[#213]: https://github.com/NLnetLabs/cascade/pull/213
[#216]: https://github.com/NLnetLabs/cascade/pull/216
[#217]: https://github.com/NLnetLabs/cascade/pull/217
[#218]: https://github.com/NLnetLabs/cascade/pull/218
[#225]: https://github.com/NLnetLabs/cascade/pull/225
[#227]: https://github.com/NLnetLabs/cascade/pull/227
[#230]: https://github.com/NLnetLabs/cascade/pull/230


## 0.1.0-alpha 'Globen'

Released 2025-10-07

Initial release
