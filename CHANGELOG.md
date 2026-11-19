## Unreleased

### Improvements

* `GetInterfaceIP` and `GetInterfaceIPs` now order candidates by usability
  (default route first, then address type, then network size) and never
  select addresses from interfaces that are down.  Interfaces are
  re-enumerated on every call so cached results can't select an address that
  has gone offline.
* Added `AllowLoopback` option to explicitly allow loopback candidates in
  `GetInterfaceIP` and `GetInterfaceIPs` for special scenarios.
* Added `IfWithoutLoopback` helper to filter out loopback addresses and
  addresses attached to loopback interfaces.

### Changes

### Fixed

* `GetInterfaceIPs` no longer returns loopback addresses (e.g. `127.0.0.1`)
  first when the interface enumeration order places a loopback alias ahead of
  routable addresses, which caused services in containers to bind to an
  address unreachable from outside.  Loopback addresses and addresses on
  loopback interfaces are now excluded by default.

### Security
