# Etonify sing-tun patch inventory

Upstream base: `SagerNet/sing-tun` at `5c2edb183cc92eb190d41c04dedfa5519ca3e78c`.
Local-repair baseline: `bb49d6fa49afd191a642debf8a3229fdc18639b0`.
Module path remains `github.com/sagernet/sing-tun`; Etonify Core uses an exact
gitlink and an exact-version local Go replacement, not a moving branch.

## Selected upstream backports

Applied on the local-repair baseline, without replacing it with upstream/dev:

- `ce08a18fce4448081938ff71466c13e3e9ed94aa`: blocking memory-TUN inbound writes.
- `09dd03de313656f6a72424c308148d07523e50c4`: asynchronous flow judgement,
  bounded held-packet queues and stack-specific resume paths.
- `0c41c360144be8bd3131cd2f0202a3d6b737fe62`: exempt TPROXY-marked connections
  from redirect-port rejection.
- `611d83b7a57b4719be45581eb674942ff561de6c`: immediately expire explicitly
  closed forward flows so subsequent packets can be judged again.

The NAT quarantine, fragment coverage, single-owner shutdown and batched
loopback-hairpin write path remain in place.

## Local repairs

- Judgement replay observes network-reset generations before installing or
  resuming held packets, even when the stack has not called Flush yet.
- Dispatcher shutdown has one owner. Repeated/concurrent Close cannot detach
  or release a shared allocator twice, and a closed dispatcher cannot attach.
- Fragment associations track unique eight-byte cells in a fixed 1024-byte
  bitmap. Duplicates/overlaps cannot falsely complete the datagram; duplicate
  first fragments do not erase coverage or extend the fixed 30-second expiry.
  Capacity stays 4096 entries (4 MiB of coverage plus map/entry overhead).
- Released UDP selectors remain quarantined for four minutes. Reverse/mapping
  references are removed; permissive mapping/filtering policy is preserved.
  An active allocator has one guarded expiry timer, also cleaning reservations
  without subsequent traffic. On final Close physical reservations are freed
  exactly once before the registry entry can be replaced. Logical quarantine
  survives a new dispatcher on the same still-live Port.
- Retired cleanup and active expiry are generation-guarded. The global registry
  reserves at most 1024 slots for active plus retired allocators; exhaustion
  refuses new distinct Ports rather than evicting unexpired protection.

## Boundaries and maintenance

The four-minute window is finite: UDP has no wire-level generation identifier,
so replies arriving after reuse beyond that window cannot always be distinguished.
Protection is scoped to the same live Port, not an unrelated replacement object.
Short selector ranges can temporarily exhaust during repeated resets; this is
explicit backpressure, not permission to reuse a protected selector.

Run `go test -race -count=20 -run '^TestEtonify' .` for these regressions.
Full upstream platform tests additionally require privileges/network support.
This fork does not claim to fix every upstream or Android connectivity issue.
Before changing the upstream base, review the small production patch and rerun
the fork regressions, core packet-level tests, strict pin and provenance gates.
