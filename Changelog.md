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

### Bug fixes

- A zone configured for unsigned review no longer fails to sign. ([#398] by
  @ximon18)

### Other changes

- Prefix cascaded `--help` output with a one line description of the
  application. ([#409] by @ximon18)
- Improve integration tests framework ([#401] by @mozzieongit)

### Documentation improvements

- Document that `--daemonize` changes CWD to / ([#387] by @jpmens)
- Use a more appropriate `log-target` example file path. ([#411] by @ximon18)
- Specify both binary crates to build from source ([#423] by @mozzieongit)

[#387]: https://github.com/NLnetLabs/cascade/pull/387
[#398]: https://github.com/NLnetLabs/cascade/pull/398
[#401]: https://github.com/NLnetLabs/cascade/pull/401
[#409]: https://github.com/NLnetLabs/cascade/pull/409
[#411]: https://github.com/NLnetLabs/cascade/pull/411
[#423]: https://github.com/NLnetLabs/cascade/pull/423

## 0.1.0-alpha5 'Colline de la Croix'

Released 2025-11-21.

### Breaking changes

- `cascade config reload` has been removed.  Configuration can only be reloaded
  by restarting Cascade.  The command was never fully supported, since changes
  to many configuration settings would be ignored.  ([#330] by @bal-e)

### New

- `cascade debug change-logging` can be used to change how Cascade logs
  information at runtime, which is a useful debugging aid.  This functionality
  was previously provided by `cascade config reload`.  ([#330] by @bal-e)

- `cascade status keys` now prints information about DNSSEC keys and rollovers,
  across all known zones.  It will prioritize keys with the soonest rollover
  actions. ([#288] by @tertsdiepraam)

### Bug fixes

- Changes to the `[key-manager]` section in zone policy will now propagate those
  changes into existing zones for that policy.  ([#355] by @Philip-NLnetLabs)

- The threads spawned by Cascade are now named `cascade-worker` instead of
  generic names like `tokio-worker`.  ([#356] by @tertsdiepraam)

### Documentation improvements

- Note incompatibility with NitroKey v2.0.0 PKCS#11 module ([#357] by @ximon18)

- Note file access limitations for review scripts ([#358] by @tertsdiepraam)

### Acknowledgements

Our continued thanks to @jpmens, @bortzmeyer, and @gryphius for trying out
Cascade.

[#330]: https://github.com/NLnetLabs/cascade/pull/330
[#330]: https://github.com/NLnetLabs/cascade/pull/330
[#288]: https://github.com/NLnetLabs/cascade/pull/288
[#355]: https://github.com/NLnetLabs/cascade/pull/355
[#356]: https://github.com/NLnetLabs/cascade/pull/356
[#357]: https://github.com/NLnetLabs/cascade/pull/357
[#358]: https://github.com/NLnetLabs/cascade/pull/358

## 0.1.0-alpha4 'Mont-Royal'

Released 2025-11-07.

### New

- The stdout/stderr of review scripts is now logged ([#281] by @tertsdiepraam)
- Cascade now logs its version number on startup ([#286] by @tertsdiepraam)
- Cascade outputs more colorful logs ([#287] by @tertsdiepraam)

### Bug fixes

- Zone parsing errors now cause a soft-halt instead of a hard-halt ([#280] by @tertsdiepraam)
- Signing statistics now present accurate values related to NSEC(3) ([#271] by @bal-e)

### Other changes

- Use `tracing-subscriber` for logging ([#287] by @tertsdiepraam)

### Documentation improvements

- Document Cascade's dependency on OpenSSL ([#277] by @AlexanderBand)

### Acknowledgements

Our continued thanks to @jpmens, @bortzmeyer, and @gryphius for trying out
Cascade.

[#271]: https://github.com/NLnetLabs/cascade/pull/271
[#277]: https://github.com/NLnetLabs/cascade/pull/277
[#280]: https://github.com/NLnetLabs/cascade/pull/280
[#281]: https://github.com/NLnetLabs/cascade/pull/281
[#286]: https://github.com/NLnetLabs/cascade/pull/286
[#287]: https://github.com/NLnetLabs/cascade/pull/287


## 0.1.0-alpha3 'Rue des Cascades'

Released 2025-10-24.

### Breaking changes

- Cascade now loads configuration files when it (re)starts, instead of waiting
  for an explicit `cascade config reload` command. ([#258] by @bal-e)

### Bug fixes

- The Cascade CLI only produces color output on terminals, while respecting
  relevant environment variables. Previously it would unconditionally output
  color, even when called from a script or in a pipeline. ([#256] by
  @tertsdiepraam)

- Errors from `cascade keyset` will no longer halt the pipeline ([#265] by
  @tertsdiepraam)

- Resolve systemd startup failure ([#233] by @ximon18)

### Documentation improvements

- General refinement ([#239], [#240], [#241], [#257], [#263], [#264] by
  @AlexanderBand)
- Expand HSM documentation ([#236], [#246], [#259] by @jpmens)
- Add man page for `kmip2pkcs11` ([#260] by @mozzieongit)

### Acknowledgements

Many thanks go to @jpmens and @bortzmeyer for trying out the alpha release of
Cascade and extensively reporting the issues they found, even contributing
documentation.

[#233]: https://github.com/NLnetLabs/cascade/pull/233
[#236]: https://github.com/NLnetLabs/cascade/pull/236
[#239]: https://github.com/NLnetLabs/cascade/pull/239
[#240]: https://github.com/NLnetLabs/cascade/pull/240
[#241]: https://github.com/NLnetLabs/cascade/pull/241
[#246]: https://github.com/NLnetLabs/cascade/pull/246
[#256]: https://github.com/NLnetLabs/cascade/pull/256
[#257]: https://github.com/NLnetLabs/cascade/pull/257
[#258]: https://github.com/NLnetLabs/cascade/pull/258
[#259]: https://github.com/NLnetLabs/cascade/pull/259
[#260]: https://github.com/NLnetLabs/cascade/pull/260
[#263]: https://github.com/NLnetLabs/cascade/pull/263
[#264]: https://github.com/NLnetLabs/cascade/pull/264
[#265]: https://github.com/NLnetLabs/cascade/pull/265


## 0.1.0-alpha2 'Cascader la vertu'

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
- Pre-create /etc/cascade/policies when installing via DEB/RPM package ([#233])
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
[#219]: https://github.com/NLnetLabs/cascade/pull/219
[#225]: https://github.com/NLnetLabs/cascade/pull/225
[#227]: https://github.com/NLnetLabs/cascade/pull/227
[#230]: https://github.com/NLnetLabs/cascade/pull/230
[#233]: https://github.com/NLnetLabs/cascade/pull/233


## 0.1.0-alpha 'Globen'

Released 2025-10-07

Initial release
