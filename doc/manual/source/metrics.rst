Metrics
=======

Prometheus metrics for Cascade are available via Cascade's HTTP API under the
``/metrics`` path. The available metrics are documented below.

State Metrics
-------------

These metrics apply to Cascade as a whole.

- ``zones_configured`` (gauge): Number of zones known to Cascade.
- ``zones_loaded`` (gauge): Number of zones loaded by Cascade.
- ``zones_active`` (gauge): Number of active zones.
- ``zones_unsigned`` (gauge): Number of unsigned zones.
- ``zones_signed`` (gauge): Number of signed zones.
- ``zones_published`` (gauge): Number of published zones.
- ``zones_halted`` (gauge): Number of halted zones.

Per Zone Metrics
----------------

These metrics are available for each zone. The metrics have a label that
specifies the zone name.

- ``xfr_requests_to_upstream_attempted`` (gauge): Number of zone transfers
  attempted by Cascade towards the upstream primary.
- ``xfr_requests_to_upstream_succeeded`` (gauge): Number of succesful zone
  transfers by Cascade towards the upstream primary.
- ``zone_loaded_last_successful_records`` (gauge): Number of records loaded in
  last successful zone transfer or zonefile load.
- ``zone_loaded_last_successful_size_bytes`` (gauge): Number of bytes loaded in
  last successful zone transfer or zonefile load.
- ``zone_loaded_last_records`` (gauge): Number of records loaded in last
  attempted zone transfer or zonefile load.
- ``zone_loaded_last_size_bytes`` (gauge): Number of bytes loaded in last
  attempted zone transfer or zonefile load.
- ``zone_last_successful_load_duration_seconds`` (gauge): Duration of the last
  successful load for this zone.
- ``zone_last_successful_sign_duration_seconds`` (gauge): Duration of the last
  successful signing operation for this zone.
- ``zone_last_load_duration_seconds`` (gauge): Duration of the last load for
  this zone.
- ``zone_last_sign_duration_seconds`` (gauge): Duration of the last signing
  operation for this zone.
