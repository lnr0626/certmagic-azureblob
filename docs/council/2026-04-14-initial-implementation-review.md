# Council Review: CertMagic Azure Blob Storage Plugin

**Date:** 2026-04-14
**Scope:** Full implementation review of `certmagic-azureblob` — correctness, architecture, test coverage, production-readiness

## Reviewers

| Reviewer | Agent | Model | Lens |
|----------|-------|-------|------|
| Code Review | `code-review` | Haiku 4.5 | Correctness, bugs, concurrency |
| Greybeard | `greybeard` | Sonnet | Architecture, distributed systems, scalability |
| Bar Raiser | `bar-raiser` | Sonnet | Test coverage, missing scenarios |
| Cross-check | `general-purpose` | GPT-5.3 Codex | Independent holistic review |

## Consensus Concerns

Issues raised independently by 2+ reviewers.

### 1. Renewal failure doesn't signal lock loss (3/4 reviewers)

**Raised by:** Greybeard, Bar Raiser, Cross-check

If `RenewLease` fails repeatedly (network partition, Azure outage), the lease expires silently while the lock holder continues its critical section. No warning, no callback, no way for CertMagic to know the lock is gone.

**Impact:** Split-brain — two nodes issue certificates for the same domain simultaneously. With Let's Encrypt's 5 duplicate cert/week limit, this burns rate limit quota.

**Mitigating context:** CertMagic's own `FileStorage` has the same limitation. Azure enforces server-side mutual exclusion, so the actual overlap window is small (lease expiry → new acquire → old holder hasn't noticed). CertMagic's docs acknowledge this risk for any timeout-based lock.

**Recommendation:** Track consecutive renewal failures. After 2+ failures, log at WARN level with "lock may be lost" message. This is the minimum viable fix for v1. A "lock lost" channel/callback is a future improvement.

**Priority:** Fix before production use

### 2. No startup validation of connection string / Azure connectivity (3/4 reviewers)

**Raised by:** Greybeard, Cross-check, Code Review (implicitly via container ensure race)

`Provision()` creates the `ConnStringProvider` but never validates that the connection string works or Azure is reachable. Caddy starts successfully with a bad config, and the first TLS handshake fails.

**Recommendation:** Add `caddy.Validator` interface — `Validate()` calls `containerClient(ctx)` to verify connectivity. Also validates `connection_string` is non-empty for JSON/API configs (Caddyfile parsing already enforces this).

**Priority:** Fix before production use

### 3. Container ensure-once has a TOCTOU race (3/4 reviewers)

**Raised by:** Code Review, Greybeard, Cross-check (implicitly)

The check-then-act pattern releases the mutex before calling `ensureContainer`, allowing multiple goroutines to attempt container creation concurrently on first access.

**Impact:** Benign in practice — `ensureContainer` handles `ContainerAlreadyExists`. Wastes API calls on cold start but doesn't cause incorrect behavior.

**Recommendation:** Hold mutex across the ensure call (simple, correct, and the hot path is still fast after first call).

**Priority:** Easy fix, do it now

### 4. Missing test coverage for critical lock paths (2/4 reviewers)

**Raised by:** Bar Raiser, Cross-check

Three P0 test gaps:
- `Unlock` after lease expiry returns `nil` (not an error) — validates defensive error handling
- Lock renewal actually keeps lock alive beyond lease duration — proves the goroutine works
- `releaseLocks()` releases all held locks — proves shutdown cleanup works

**Priority:** Fix before production use

## Notable Non-Consensus Concerns

High-signal issues raised by a single reviewer.

### 5. `List` should return error for nonexistent prefixes (Cross-check only)

**Claim:** CertMagic expects `fs.ErrNotExist` for missing prefixes from `List()`.

**Assessment:** After checking the CertMagic source, `List` is documented to return an empty slice for missing prefixes, not `fs.ErrNotExist`. Other implementations (S3, GCS) also return empty slices. The current behavior (`[]string(nil), nil`) is correct. **Dismissed.**

### 6. `Stat` prefix check drops `NextPage` errors (Cross-check only)

**Claim:** If the prefix listing fails (permissions, outage), the error is swallowed and converted to `fs.ErrNotExist`.

**Assessment:** Valid concern. The code does `if err == nil && len(page.Segment.BlobItems) > 0` which silently converts API errors to "not found." Should propagate the error instead of masking it.

**Priority:** Fix (small)

### 7. No lease ID validation after acquire (Code Review only)

**Claim:** If `AcquireLease` returns success with nil `LeaseID`, the code proceeds with an empty lease ID and all renewals fail silently.

**Assessment:** Defensive coding concern — the Azure SDK won't return nil LeaseID on success in practice. But a one-line guard (`if resp.LeaseID == nil`) is cheap insurance.

**Priority:** Easy fix, do it now

### 8. Lock blob accumulation (Greybeard only)

Lock blobs (`locks/*`) are created but never cleaned up. Over time, thousands of zero-byte blobs accumulate for every domain ever managed.

**Recommendation:** Document Azure Blob lifecycle management policy as the recommended cleanup strategy. Don't add delete-on-unlock (adds latency to hot path).

**Priority:** Document now, implement cleanup later if needed

### 9. Caddyfile parser accepts partial tokens (Cross-check only)

`fmt.Sscanf("%d", "30x")` parses as 30 without error.

**Assessment:** Minor — users won't typically write `30x`. Could use `strconv.Atoi` for strictness, but low priority.

**Priority:** Later

### 10. `Exists` prefix check drops errors too (inferred from #6)

Same pattern as `Stat` — prefix listing errors are silently converted to `false`.

**Priority:** Fix alongside #6

## Disagreements

### `List` error behavior for missing prefixes

Cross-check claims `List` should return `fs.ErrNotExist`. Other reviewers did not raise this. CertMagic's contract and peer implementations (S3, GCS) return empty slices. **Resolved in favor of current behavior.**

### Lock blob cleanup strategy

Greybeard suggests documenting Azure lifecycle policies. No other reviewer raised this. The concern is valid for large-scale deployments but not blocking for v1.

## Recommendation

**Proceed with changes.** The plugin is architecturally sound. The locking strategy is correct for CertMagic's use case. Fix the consensus issues before claiming production-ready.

## Action List

### Must-fix before production

| # | Item | Source | Effort |
|---|------|--------|--------|
| 1 | Add consecutive renewal failure tracking + WARN logging | Consensus | 20 min |
| 2 | Add `Validate()` for startup connectivity check | Consensus | 15 min |
| 3 | Fix container ensure-once TOCTOU (hold mutex across call) | Consensus | 10 min |
| 4 | Validate lease ID after acquire | Code Review | 5 min |
| 5 | Propagate errors in `Stat`/`Exists` prefix checks instead of masking | Cross-check | 15 min |
| 6 | Add P0 integration tests (unlock after expiry, renewal keeps lock, releaseLocks) | Bar Raiser | 30 min |

### Follow-up later

| # | Item | Source | Effort |
|---|------|--------|--------|
| 7 | Document lock blob accumulation + Azure lifecycle policy | Greybeard | 15 min |
| 8 | Use `strconv.Atoi` for lease_duration parsing | Cross-check | 5 min |
| 9 | Add managed identity / DefaultAzureCredential support | Greybeard | 2-3 hrs |
| 10 | Observability — metrics for lock contention, renewal health | Greybeard | 2-3 hrs |
