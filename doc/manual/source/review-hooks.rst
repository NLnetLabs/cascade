Review Hooks
============

Cascade offers automated zone pre-publication checks via its review hooks.
Review hook points are available for reviewing a zone after it has been
loaded but not yet signed, and after it has been signed but not yet published.

The hooks can be configured in the zone policy file in the
:ref:`[loader.review] <policy-loaded-review>` and :ref:`[signer.review]
<policy-signed-review>` sections.
