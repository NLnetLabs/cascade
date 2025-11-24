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
possible with act's default network (act uses host networking by default). This
is because localhost:53 is already in use by your system's stub resolver
(probably systemd-resolved). Therefore, you need to specify a different network
to use: `act --network default` on Docker, or `act --network podman` on Podman.

### Standalone artifact server for use with --network (optional)

In a non-host network, act cannot access its own artifact server (that would be
started using the `--artifact-server-path` option). Therefore, Jannik has
hacked together a standalone artifact server binary that uses the existing act
artifact server code (https://github.com/mozzieongit/act). You can run that
server in a separate container on the same network (see the README of
https://github.com/mozzieongit/act) and have act use that artifact server.

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

### Example test job

```yml
  job-name:
    name: Run tests with resolvers/namerservers
    runs-on: ${{ matrix.os }}
    needs: build
    strategy:
      matrix:
        os: [ubuntu-latest]
        rust: [stable] # see build job
    steps:
    - name: Checkout repository
      uses: actions/checkout@v4
    - name: Prepare the system test environment
      uses: ./.github/actions/prepare-systest-env
      with:
        artifact-name: ${{ format('cascade_{0}_{1}_{2}', github.sha, matrix.os, matrix.rust) }}
    # - name: Only download/build the binaries without setting up the test environment
    #   uses: ./.github/actions/download-or-build
    #   with:
    #     artifact-name: ${{ format('cascade_{0}_{1}_{2}', github.sha, matrix.os, matrix.rust) }}
    - run: target/debug/cascade --version
    ### RUN YOUR TESTS HERE
    # # Optional, the container gets cleaned up anyway (at least in act)
    # - name: Stop the setup
    #   run: scripts/manage-test-environment.sh stop
```
