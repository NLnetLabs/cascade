Importing Keys
==============

When migrating from an existing DNSSEC signing solution to Cascade one typically wants to avoid zone(s) becoming DNSSEC invalid.

Any migration strategy requires importing keys from the old signer into the new signer.

Cascade will use imported keys but will *not* delete them when they are no longer needed.

Moving keys out of the existing signer may be possible but the process is vendor specific and not documented here.

Key import is done as part of adding a zone and can be from files or from an HSM.

The :doc:`man/cascade-zone` manual page documents the various `--import-` arguments that can be used to import keys when adding a zone.

.. Tip::

   When importing a PKCS#11 HSM key and accessing the HSM via :program:`kmip2pkcs11` you will need to suffix public key ID arguments that you pass to ``cascade zone add --import-xxx-kmip`` with ``_pub`` private key IDs with ``_priv``. Otherwise :program:`kmip2pkcs11` will fail to find the keys.
