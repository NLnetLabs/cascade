# Testing Cascade

## Unit tests

Unit tests can be run as usual for Rust projects using `cargo test`:

1. `cargo test`
1. `cargo test --no-default-features`
1. `cargo test --all-features`

## Integration/System testing with `act`

The GitHub Action workflow in `.github/workflows/system-tests.yml` is primarily
for use with https://github.com/nektos/act and has been tested using the full
image (`catthehacker/ubuntu:full-latest`).

### TL;DR

Run all tests with:

- Docker: `act --network default -W .github/workflows/system-tests.yml`
- Podman: `act --network podman -W .github/workflows/system-tests.yml`

Run a single test with:

- Docker: `act --network default -W .github/workflows/system-tests.yml --job your-test`
- Podman: `act --network podman -W .github/workflows/system-tests.yml --job your-test`

Optionally start a standalone artifact server to deduplicate compilation
between tests (see below, "Standalone artifact server...").

### Network requirement (why --network default)

In the test environment, Unbound needs to bind to localhost:53, which is not
possible with act's default network. This is because localhost:53 is already in
use by your system's stub resolver (probably systemd-resolved). Instead of
act's default network selection (which instructs Docker/Podman to use the
[host's](https://docs.docker.com/engine/network/drivers/host/) network), you
need to specify a different container network to use. Docker and Podman each
provide default networks (not to be confused with act's default network
selection, which is Docker/Podman's `host` network). Docker's default
network is called `default`, while Podman's default network is called `podman`.
Therefore, you need to use `act --network default` on Docker, and `act
--network podman` on Podman.

### Standalone artifact server for use with --network (optional)

In a non-host network, act cannot access its own artifact server (that would be
started using the `--artifact-server-path` option). Therefore, Jannik has
hacked together a standalone artifact server binary that uses the existing act
artifact server code (https://github.com/mozzieongit/act). You can run that
server in a separate container on the same network (see the README of
https://github.com/mozzieongit/act) and have act use that artifact server.

Using an artifact server is optional. Using an artifact server enables the
testing workflow to only build Cascade and dnst once (see "Building from
source..." below), upload the generated binaries as artifacts, and download
them for use in each test job.

If you are not using an artifact server, you will get error messages like
below, which you can ignore. The test jobs will continue as normal and build
Cascade and dnst from source at the start of each test job. You might want to
disable a job's dependency on the `build` job while running your tests to
remove the then unnecessary build step.

```
[System/Integration tests/Build the project for use by the later tests]   ❗  ::error::Failed to CreateArtifact: Unable to make request: EHOSTUNREACH%0AIf you are using self-hosted runners, please make sure your runner has access to all GitHub endpoints: https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#communication-between-self-hosted-runners-and-github
[System/Integration tests/Build the project for use by the later tests] Failed but continue next step
[System/Integration tests/Build the project for use by the later tests]   ❌  Failure - Main Upload built binaries [4.19147036s]
```


### Building from source (once or always)

The `build` job builds the project and uploads the target directory as an
artifact for use by the other jobs to deduplicate the compilation step.
If fetching the pre-built fails in the other jobs, they will just build them
from source. This means that the workflow is still usable without an artifact
server.

### Running single jobs/tests

You can run single jobs with act using the `--job` option. However, if the job
has the `needs` option set to depend on other jobs, those jobs will always be run
before. If you want to test/debug your test without always re-building the
source, you could comment out the `needs: build` option, build once using `act ...
--job build` and then use `act ... --job your-test` to only run your test. If
there is no artifact server available, the code will still always be built from
source.


### Limitations

#### No init or systemd

Act runs the workflow in a container without init or systemd. Therefore, when
running other daemons, you either need to make use of their appropriate
daemonization features, or handle background jobs yourself.

Maybe running act with `--container-options --init` would work to add a dumb
init process, but isn't verified, yet.

#### All nameservers on the same address

Currently, it is not possible to add additional listener addresses on the
loopback (or any) network device in the `act` container. Therefore, all
nameservers are listening on 127.0.0.1 on different ports:

- Unbound: 127.0.0.1:53
- Primary NSD: 127.0.0.1:1055
- Secondary NSD: 127.0.0.1:1054
- Bind (authoritative for `.test`): 127.0.0.1:1053

It might be possible to change this in future versions of this setup with the
`--container-options --cap-add=NET_ADMIN` option for act, but this needs to be
tried out.


### Managing act's verbosity

act prints a lot of information on the terminal. To reduce or manage the amount
of text printed you can:

- Use act's `--concurrent-jobs 1` option to limit the number of jobs run by act
  at once, which will avoid interlacing output of different jobs.
- Use the `--quiet` option to disable logging of output from steps, which
  reduces the amount of output generated by act. However, by using this option
  you might miss valuable output when a test fails and have to re-run the test.
- Write the output to a file with `act ... 2>&1 | tee /tmp/act.log` (optionally
  using `unbuffer` from the `expect` package; left as an excercise for the
  user)

### Miscellaneous notes

- By default, tests are run using a debug build for both Cascade and dnst.
  - This can be changed per test using the `build-profile` environment variable.
- `cascade`, `cascaded`, and `dnst` are added to the `$PATH`.

### Example test job

You can find the example test job at the top of the workflow file
`.github/workflows/system-tests.yml`.
