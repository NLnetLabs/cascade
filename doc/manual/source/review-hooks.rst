Review Hooks
============

Cascade offers two review hook points in its signing pipeline for automated zone validation by user provided review scripts.
These review hooks can be used to perform any validation the user requires to ensure their zone is correct at all stages, using any (3rd-party) tools desired.

A review script in Cascade is a custom program created by the user (and configured in the zone's policy as shown below in `Configuring a review hook`_) that performs the desired validation and signals approval or rejection to Cascade via the program's exit code.
An exit code of 0 means the zone is approved, and any other exit code means the zone is rejected.

The first review hook is available after a zone is loaded by Cascade before it is signed.
The second review hook is available after the zone is signed and not yet published.
The review script can approve or reject a zone at either of these stages.

If a review script approves the zone, then that version of the zone will continue through the pipeline as usual.
If a review script rejects the zone instead, then that version of the zone will be halted and not proceed further.
However, a subsequently loaded version of the zone will be processed and traverse the pipeline as usual, unless it too is rejected by a review script.

A review script receives relevant information about the zone in environment variables listed in the :ref:`policy file manual <policy-loaded-review-cmd>`.
The review script then needs to use the address provided in the environment variables to fetch the zone via AXFR and perform the required checks.

Configuring a review hook
-------------------------

To configure a review hook, you set the review :option:`required = true <required = false>` policy option, and specify the review script using the :option:`cmd-hook <cmd-hook = "">` option in the :ref:`[loader.review] <policy-loaded-review>` and/or :ref:`[signer.review] <policy-signed-review>` policy file sections.

Review scripts (or programs) are called using ``sh -c``, so you can provide arguments to your review script, e.g.: :option:`cmd-hook = "script.sh --stage unsigned" <cmd-hook = "">`.

Manual Review
-------------

You can also enable manual review by setting the review :option:`required = true <required = false>` option under :ref:`[loader.review] <policy-loaded-review>` or :ref:`[signer.review] <policy-signed-review>` without providing a :option:`cmd-hook <cmd-hook = "">` command.

If no hook command is provided, but review is required, manual approval or rejection has to be performed using the CLI commands ``cascade zone approve`` or ``cascade zone reject``.

Example
-------

In this example we will use `validns <https://codeberg.org/DNS-OARC/validns>`_ to validate the unsigned zone, and `dnssec-verify <https://bind9.readthedocs.io/en/v9.20.13/manpages.html#dnssec-verify-dnssec-zone-verification-tool>`_ to validate the signed zone.

To do this, we need to write a shell script that fetches the zone using AXFR and performs the relevant checks. Let's save the following review script\ [1]_ as ``/usr/local/bin/cascade-review.sh``:

.. code-block:: sh

    #!/usr/bin/env sh

    set -e

    logger -p daemon.notice -t cascade "Validating ${CASCADE_ZONE} of serial ${CASCADE_SERIAL} from ${CASCADE_SERVER}"

    tmp_zone=$(mktemp /tmp/cascade_zone.XXXXXXXXXX)
    # Clean up when leaving
    trap  "rm -f ${tmp_zone}; exit 1" 1 2 3 15
    trap  "rm -f ${tmp_zone}" EXIT

    # Unfortunately, dig logs some errors on standard output... Nothing to do there
    dig @${CASCADE_SERVER_IP} -p ${CASCADE_SERVER_PORT} "${CASCADE_ZONE}" AXFR > ${tmp_zone}

    # Using `validns` to check the unsigned zone
    # and `dnssec-verify` to check the signed zone
    if [ "$1" = "unsigned" ]; then
        # validns does not handle Ed25519
        validns -z "${CASCADE_ZONE}" -p all ${tmp_zone}
    else
        dnssec-verify -q -o "${CASCADE_ZONE}" ${tmp_zone}
    fi

.. versionchanged:: 0.1.0-alpha2
   Updated the example to use the new ``CASCADE_SERVER_IP`` and
   ``CASCADE_SERVER_PORT`` environment variables.`

Next, we update the zone's policy to use the review script for both stages:

.. code:: toml

    # Keep the other settings in the policy as is ...

    [loader.review]
    required = true
    cmd-hook = "/usr/local/bin/cascade-review.sh unsigned"

    [signer.review]
    required = true
    cmd-hook = "/usr/local/bin/cascade-review.sh"


.. [1] Original review script example by Stéphane Bortzmeyer on `GitHub <https://github.com/NLnetLabs/cascade/issues/198#issuecomment-3389957031>`_
