# Changelog

## Next Release

* Use protocol numbers instead of protocol names in `ipset` commands. Fixes errors on platforms which do not read `/etc/protocols`
* Do not forward responses if firewall configuration fails, reply with `ServerError` instead. This prevents mismatching state between DNS client and firewall, which can lead to connection errors which are hard to recover from, when the DNS client caches responses itself.
* Attempted to decrease release binary size
* Updated dependencies

## v1.1.1 (2021-05-24)

* Fixed documentation for the feature introduced in v1.1.0

## v1.1.0 (2021-05-24)

* It is now possible to specify wildcards when filtering domains

## v1.0.0 (2021-05-24)

First Release
