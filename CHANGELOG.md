# Changelog

## Next Release

## v1.2.2 (2023-12-27)

* Increased minimum Rust version from 1.64.0 to 1.81.0
* Updated dependencies

## v1.2.1 (2022-05-20)

* Fixed issue where a wildcard allow rule of the form `~> *` would not allow DNS requests to pass through for all domains
* Updated dependencies

## v1.2.0 (2022-03-27)

* Add block rules (`[client IP address or subnet] -| [domain]` or `[client IP address or subnet] -| [domain] = [ip address]`)
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
