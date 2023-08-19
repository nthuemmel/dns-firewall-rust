# dns-firewall

[![Build Status](https://github.com/nthuemmel/dns-firewall-rust/actions/workflows/main.yml/badge.svg?branch=master)](https://github.com/nthuemmel/dns-firewall-rust/actions/workflows/main.yml?query=branch%3Amaster)
[![crates.io](https://img.shields.io/crates/v/dns-firewall.svg)](https://crates.io/crates/dns-firewall)

`dns-firewall` is a filtering DNS proxy server integrating into `iptables` firewalls written in Rust.

Whereas regular firewalls can only filter by destination IP address, this server can filter by destination domain name instead.
It restricts outbound traffic of clients according to an allowlist.
It can, for instance, be installed on a router to ensure that a set of managed servers or virtual machines only open connections to intended destinations, filtering out telemetry or other unwanted traffic.

## Usage Tutorial

1. **Install the server**
    
    * If you are on Debian / Ubuntu 20.04+, you can install the latest pre-built package from [the Releases page](https://github.com/nthuemmel/dns-firewall-rust/releases/latest)
	* Otherwise, follow the [instructions below on how to build and install it](#building)

2. **Prepare your firewall**

    `dns-firewall` uses a combination of `iptables` and `ipset` to dynamically manage firewall rules. Make sure you have both installed (on Ubuntu: `sudo apt update && sudo apt install -y iptables ipset`).

    Designate a chain that will be managed by `dns-firewall`, for example `DNSALLOWLIST`. `ACCEPT` rules will be created in this chain by the program. Note that any user-created rules will be removed from the chain on program start.

    **It is your responsibility to block all traffic that has passed through the chain without being accepted**. You can use either `DROP` or `REJECT` rules as usual.

    Example for the `FORWARD` chain:

    ```bash
    iptables -N DNSALLOWLIST
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -j DNSALLOWLIST
    iptables -A FORWARD -j LOG
    iptables -A FORWARD -j REJECT
    ```

    You can also filter traffic from localhost in the `OUTPUT` chain, but `dns-firewall` really is designed to be used on routers as part of the `FORWARD` chain.

3. **Configure the server**

    Open `/etc/dns-firewall/acl` in a text editor, and configure access rules:

    ```
    # General format to grant access to a domain: [client IP/subnet] -> [domain]:[protocol]:[port]
	# To only allow DNS requests without adding firewall exceptions, use: [client IP/subnet] ~> [domain]
	# Everything after # will be treated as comments and ignored.

	127.0.0.1      -> github.com:TCP:443
	92.168.1.10    -> *.example.com:UDP:655  # You can use subdomain wildcards
	2001:0db8:85a3:0000:0000:8a2e:0370:7334 -> example.com:TCP:22

	192.168.2.0/24 -> download.docker.com:TCP:443
	192.168.2.0/24 -> registry-1.docker.io:TCP:443
	192.168.2.0/24 -> auth.docker.io:TCP:443
	192.168.2.0/24 -> production.cloudflare.docker.com:TCP:443

	192.168.1.10   ~> mail.local   # Only allow DNS requests, don't add firewall rules
	192.168.1.1    ~> *            # Using wildcard is possible too, to allow all DNS requests
   
    92.168.1.10    -| wpad.example.com              # Always block access to 'wpad.example.com', even if there is a more general wildcard allow rule
    10.0.0.8       -| ads.example.com = 127.0.0.1   # Always resolve 'ads.example.com' to 127.0.0.1, does not add firewall exception
    ```
	
	Open `/etc/dns-firewall/config.env` in a text editor. Edit at least the following lines:

	```
	upstream=192.168.1.1
	chain=DNSALLOWLIST
	```

	* `upstream=<IP address>` - IPv4 or IPv6 address of the upstream DNS resolver. This upstream server is considered trustworthy, its responses will not be validated or filtered!
	* `chain=<name>` - name of the `iptables` and/or `ip6tables` firewall chain you chose in step 2, into which dynamic rules will be inserted.

4. **Run the server**

	Run `sudo systemctl start dns-firewall`

	An application log (and any startup errors) will be printed to stderr. Use `sudo systemctl status dns-firewall` to look at potential errors.

5. **Reconfigure your DNS resolvers**

	You have to ensure the filtered hosts are using the `dns-firewall` proxy server, for example by configuring it as DNS server either statically or as part of DHCP.

## Building

**Prerequisites:**

* [Rust](https://www.rust-lang.org/tools/install) (v1.66+)
* When creating debian packages: [cargo-deb](https://crates.io/crates/cargo-deb) (`cargo install cargo-deb`)

**Building:**

```
cargo build --release
```

**Packaging:**

* Debian package: `cargo deb`

**Installing:**

* Option 1: Install the package created in the last step. This is the easiest
* Option 2: While there is no install target, you can just copy the compiled binary to a suitable place and create the necessary config files manually.
    It is highly recommended to use systemd to manage the proxy server, as it is easiest way to manage the required permissions without running as root.
    The files in `dist/shared` are a good starting point.

## How it works

1. Incoming client requests will be filtered according to the access control list.
    If the client is not allowed to resolve the domain name, the server returns RCODE `REFUSED` immediately.
    Otherwise, it remembers the allowed destination sockets for the requested domain name.
2. The server forwards client requests to the upstream server and awaits its response.
3. The server invokes `ipset` to add ephemeral firewall rules for the resolved IP address(es) and remembered destination sockets.
4. The server returns the resolved address to the client.

## Configuration

**Application Options:**

The server is configured either via command line arguments or environment variables.
When using systemd, the environment variables can be loaded from a configuration file (`/etc/dns-firewall/config.env`).
All options can be queried by running `dns-firewall --help`. Help output:

```
dns-firewall 1.2.1

USAGE:
    dns-firewall [OPTIONS] --acl-file <acl-file> --firewall <backend> --upstream <upstream>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --acl-file <acl-file>                  Path to the Access Control List (ACL) file [env: ACL_FILE=]
        --firewall <backend>                   Firewall backend [env: FIREWALL=]  [possible values: none, iptables]
        --bind <bind>                          IP address to bind proxy server to [env: BIND=]  [default: 127.0.0.53]
        --bind-port <bind-port>                Port to bind proxy server to [env: BIND_PORT=]  [default: 537]
        --chain <chain>                        Firewall chain (iptables backend only) [env: CHAIN=]
        --max-connections <max-connections>    Maximum number of concurrent connections [env: MAX_CONNECTIONS=]
                                               [default: 100]
        --max-rule-time <max-rule-time>        Maximum duration of firewall rules, in seconds; may override TTL [env:
                                               MAX_RULE_TIME=]
        --min-rule-time <min-rule-time>        Minimum duration of firewall rules, in seconds; may override TTL [env:
                                               MIN_RULE_TIME=]  [default: 5]
        --timeout <timeout>                    Connection timeout, in seconds [env: TIMEOUT=]  [default: 10]
        --upstream <upstream>                  IP address of the upstream server [env: UPSTREAM=]
        --upstream-port <upstream-port>        Port of the upstream server [env: UPSTREAM_PORT=]  [default: 53]
```

**Access Control List:**

The access control list file, by default `/etc/dns-firewall/acl`, contains allow rules.
By default (if the file is empty), all requests will be blocked.

The file must contain one rule on each line, with empty lines or comments (`# This is a comment`) being ignored.
Rule syntax:

* `[client IP address or subnet] -> [domain]:[protocol]:[port]`

  Allows DNS queries of A or AAAA records and network connections from the client to the given `[domain]:[protocol]:[port]` triple.

    * `[client IP address or subnet]` must be an IPv4 or IPv6 address or subnet in CIDR notation.
    * `[domain]` must be a fully qualified domain name (FQDN) or wildcard address (`*.example.com` to match subdomains of `example.com` (`example.com` itself excluded!) or `*` to match any domain).
    * `[protocol]` must be either `TCP` or `UDP`.
    * `[port]` must be a single port in the range 1 - 65535.

* `[client IP address or subnet] ~> [domain]` or `[client IP address or subnet] ~> *`

  Allows arbitrary DNS requests to the given FQDN or wildcard address (`[domain]`).
  Note the `~>` arrow (instead of `->`)!
  Does not affect firewall configuration.

* `[client IP address or subnet] -| [domain]` or `[client IP address or subnet] -| [domain] = [ip address]`

  Explicitly blocks access to the given FQDN or wildcard address (`[domain]`).
  This may override more general allow rules.
  If an `[ip address]` is specified, accesses will remain blocked in the firewall, but the domain will be resolved locally to the specified static IPv4 or IPv6 address.
  Without an `[ip address]`, the DNS server will return RCODE `REFUSED`.
  Returning an IP address, such as `127.0.0.1` may be helpful in cases where clients are unable to handle `REFUSED` DNS responses gracefully.


## Logging

**Application Log:**

The application log is printed to `stderr`.  After startup, it may look like this:

```
[INFO ] Using iptables backend, chain "DNSALLOWLIST"
[ERROR] '/usr/sbin/ip6tables -F DNSALLOWLIST' failed: [exit code: 3] modprobe: ERROR: could not insert 'ip6_tables': Operation not permitted
    ip6tables v1.8.4 (legacy): can't initialize ip6tables table `filter': Table does not exist (do you need to insmod?)
    Perhaps ip6tables or your kernel needs to be upgraded.
[WARN ] No IPv6 rules will be created.
[INFO ] Server started!
```

Note that in the example environment, IPv6 was disabled at boot time, therefore `dns-firewall` will not be able to insert IPv6 rules.
IPv4 will work fine though.

During execution, only hard errors will be logged to the application log.
Messages that are related to incoming requests will go into the access log instead.

**Access Log:**

An access log will be printed to `stdout`.
With systemd, use `sudo journalctl -f -u dns-firewall` to follow it.
It looks like this:

```
192.168.4.58 -> [61785] r3.o.lencr.org
192.168.4.58 <- [61785] r3.o.lencr.org [149.126.86.73]:TCP:80 TTL:20
192.168.4.54 ~> [40720] this-domain-does-not.exist
192.168.4.54 <! [40720] Upstream returned error (OPCODE StandardQuery, RCODE NameError)
192.168.4.54 ~> [23619] mail.local
192.168.4.54 <~ [23619]
```

Syntax is as follows:

* `[client IP] -> [[request-id]] [domain]` Forwarding request with an allowed destination to upstream
* `[client IP] ~> [[request-id]] [domain]` Forwarding allowed DNS request to upstream (without firewall integration)
* `[client IP] |> [[request-id]] [domain]` Blocked client request
* `[client IP] |> [[request-id]] [domain] [[resolved-ip-address]]` Resolved domain locally to the given IP address, firewall not affected
* `[client IP] !> [[request-id]] [errormessage]` Malformed client request / processing error
* `[client IP] <! [[request-id]] [errormessage]` Malformed upstream response / upstream sent an error
* `[client IP] <~ [[request-id]]` Forwarding upstream DNS response to client, firewall not affected
* `[client IP] <- [[request-id]] [domain] [[resolved-ip-address]]:[protocol]:[port] TTL:[ttl]` Forwarding upstream DNS response to client, reconfigured firewall

## Questions?

* **What about nftables / \<insert firewall name here>?**
  
	Currently not supported. Upvote / create a corresponding issue if you'd like to see this feature, or, preferably, open a pull request.

* **Do I have to run the server as root?**

	You should not run the server as root, for obvious reasons.
	`dns-firewall` requires permissions to reconfigure the firewall, though.
  	These are covered by the `CAP_NET_ADMIN` and `CAP_NET_RAW` capabilities.
  	Additionally, write access to `/run/xtables.lock` is required.
    The easiest way to grant these permissions is to use a systemd service ([`dist/shared/lib/systemd/system/dns-firewall.service`](dist/shared/lib/systemd/system/dns-firewall.service))
  
* **For how long will generated firewall rules stay?**
  
	`dns-firewall` uses `ipset`'s built-in timeout capabilities to automatically remove entries when the domain's DNS TTL expires. The TTL can be overridden by using the `min-rule-time` and `max-rule-time` parameters.

* **How's performance?**

    I haven't measured it. It is sufficient for the (low-traffic) use case that I have.
    The server uses asynchronous I/O, but each firewall reconfiguration will start a new process.
    The number of concurrent operations is bounded by the `--max-connections` parameter.
    Memory usage should be low (it's around 3.3 MiB for me after an uptime of 12 days).

## License

Licensed under either of

* Apache License, Version 2.0
  ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license
  ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

## Maintenance

### Run Tests

```
cargo check --locked --all-targets
cargo test --locked
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
```

### Fix Clippy Issues

```
cargo clippy --locked --all-targets --fix --allow-dirty --allow-staged
```

### Update Dependencies

Use [cargo-edit](https://crates.io/crates/cargo-edit) (`cargo install cargo-edit`) to update versions of all dependencies in `Cargo.toml`:

```
cargo upgrade --compatible --incompatible
cargo update
```

### Release

1. Update version in `Cargo.toml` and `README.md`
2. Update version & release date in `CHANGELOG.md`
3. Create packages (`cargo deb`)
4. Commit changes
5. Tag commit with version
