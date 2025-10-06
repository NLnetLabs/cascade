Review Hooks
============

Cascade offers automated zone pre-publication checks via its review hooks.
Review hook points are available for reviewing a zone after it has been
loaded but not yet signed, and after it has been signed but not yet published.
If a review hook approves the zone then that version of the zone will continue through the pipeline as usual.
If a review hook rejects the zone then that version of the zone will NOT proceed further. A subsequently loaded version of the zone will be processed through the pipeline as usual unless it too is rejected.

Review can also be enabled without a hook command. In this case manual approval or rejection will be required using the CLI commands ``cascade zone approve`` or ``cascade zone reject``.

The hooks can be configured in the zone policy file in the
:ref:`[loader.review] <policy-loaded-review>` and :ref:`[signer.review]
<policy-signed-review>` sections.
