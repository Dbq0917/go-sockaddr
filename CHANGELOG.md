## Unreleased

### Improvements

* Add `InterfaceCache`, a self-validating cache of the host's interface
  addresses, and route the package-level `GetAllInterfaces` through it.
  Repeated selections no longer pay for a full interface enumeration, while
  address additions and removals are reflected by the very next selection.
* Add `GetUsableInterfaces`/`GetUsableIP` helpers that rank candidate
  addresses (default route first, virtual/bridge interfaces such as docker0
  last, loopback/down/link-local excluded).
* Add `InvalidateInterfaceCache` to force the package-level cache to
  re-enumerate on the next read.

### Changes

### Fixed

* A process that started before DHCP handed out a lease no longer keeps
  returning an empty address selection until restart: an empty selection is
  never cached, so the next selection observes the address as soon as it
  arrives.
* `IfAddrAttr` now falls back to the underlying `SockAddr` attributes (e.g.
  `address`) instead of returning an empty string for unknown names.

### Security
