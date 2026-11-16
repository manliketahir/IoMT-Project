# E2 threat model and scope

This states what the E2 experiment assumes about the attacker, so the results
in `results/summary-final.csv` are read against the right picture. It was
added after review raised three points: a per-source limit can be bypassed by
many sources; sockets that open TCP but never send CONNECT may still hold a
slot; and the two mitigations are tested one at a time, not combined. Each is
answered below and, where it needed evidence, by an added run.

## Attacker

- **One attacker host.** Every attack in the main sweep comes from a single
  source address (`127.0.0.2`), distinct from the patients (`127.0.0.1` for
  the collector, `127.0.0.{i+2}` per patient). The connection-exhaustion
  stimulus in `src/attack_conn_exhaust.py` binds all of its sockets to that
  one source. So the headline E2a result is for a **single-source** flood.
- **On-path to the broker port.** The attacker can open TCP connections to the
  broker's listener (1883 plain, or 8883 TLS). It is not assumed to hold a
  valid client certificate, which is what the E2b mutual-TLS control turns
  into the defense.
- **Patients already connected.** In every cell the patients connect and begin
  publishing before, or as, the attack starts (`run.py` starts the attacker
  ~0.5 s before the patient publishers). The connection cap therefore protects
  slots the patients already hold. A flood that arrives during a mass patient
  reconnection is out of scope for the main sweep.

## What each control actually bounds

- **`max_connections` (E2a cap) is global, not per-source.** It bounds the
  total connection table regardless of how many sources attack. The cap is set
  to 100, above the largest legitimate population (60 patients + 1 collector =
  61) and below the volume the harness opens, so it leaves ~39 slots for
  everything else. This is why patient delivery stays at PDR 1.0 under attack:
  the patients hold their 61 slots and the flood can only compete for the
  remainder.
- **The per-source rate limit (`src/ratelimit.sh`, nftables) is per-source by
  construction.** The rule keys on `ip saddr` with a per-source meter at
  5 new connections/second, burst 10. This throttles one source. It does
  **not** throttle a distributed attacker: N sources each get their own meter
  and each stays under the limit. The `results/distributed/` run measures this
  directly — total established connections rise roughly with the number of
  sources, confirming the rate limit is bypassed, while the global cap still
  bounds the total.

## Scope statement for the report

> E2 evaluates a single attacker host against a broker whose legitimate
> population is already connected. Under this model the connection cap plus
> per-source rate limit (E2a) keep patient delivery at PDR 1.0, and mutual TLS
> plus the ACL (E2b) refuse forged and unauthorized publishes. A distributed
> (botnet) attacker is explicitly out of the per-source rate limit's scope: the
> rate limit is bypassed by many sources, and only the global connection cap
> continues to bound the connection table. Combining both halves is the
> deployable posture and is evaluated separately as the hardened configuration
> (`mosquitto/hardened.conf`, results under `results/e2c/`).
