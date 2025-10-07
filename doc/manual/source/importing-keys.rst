Importing Keys
==============

When migrating from an existing DNSSEC signing solution to Cascade one typically wants to avoid zone(s) becoming DNSSEC invalid.

Any migration strategy requires importing keys from the old signer into the new signer.

Keys can be imported in one of two ways:
  - Using them for signing but otherwise not managing them. This is appropriate when the keys are used for multiple zones but migration is not being done at this point for all of them and so the old signer will continue to need to use them.
  - Taking ownership of them. Cascade will delete them when they are no longer needed.

In both cases the keys remain where they are. Actually moving keys out of the existing signer may be possible but the process, if possible, is vendor specific and not documented here.

Key import is done as part of adding a zone and can be from files or from an HSM.

The :doc:`man/cascade-zone` manual page documents the various `--import-` arguments that can be used to import keys when adding a zone.

.. Tip::

   When importing a PKCS#11 HSM key and accessing the HSM via :program:`kmip2pkcs11` you will need to suffix public key ID arguments that you pass to ``cascade zone add --import-xxx-kmip`` with ``_pub`` private key IDs with ``_priv``. Otherwise :program:`kmip2pkcs11` will fail to find the keys.
