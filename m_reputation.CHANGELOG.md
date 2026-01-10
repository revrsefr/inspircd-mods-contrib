# m_reputation changelog

This file documents notable changes to the `m_reputation` module.

The dates use the server/local development timeline.

## 2026-01-10

### Changed

- Reputation keys are now based on a configurable CIDR prefix rather than the full IP string.
  - Default: `ipv6prefix="64"` (group IPv6 privacy/rotating addresses by /64)
  - Default: `ipv4prefix="32"` (keep existing IPv4 behaviour)

### Added

- New config options on the main `<reputation>` tag:
  - `ipv6prefix` (0–128)
  - `ipv4prefix` (0–32)
- `/REPUTATION >N` to list users whose score is strictly greater than `N`.
- Extended ban `score:>N` (and `y:>N`) to match users whose score is strictly greater than `N`.

### Fixed

- `/REPUTATION <ip>` lookups and `/REPUTATION <ip> <value>` updates now normalise the IP to the configured prefix, so manual oper actions match automatic scoring.
- SpanningTree ENCAP replication (`REPUTATION`) now normalises keys, ensuring all servers converge on the same entry.
- Legacy flatfile database entries are migrated on load by normalising stored IP keys to the configured prefix.

### Notes

- Setting `ipv6prefix="128"` disables IPv6 aggregation (one entry per IPv6 address). This is more conservative for VPN/DC shared ranges, but is easier to evade when clients rotate IPv6 privacy addresses.
