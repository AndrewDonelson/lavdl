# Linux Age Distributed Ledger (LADL) — Age Verification Service
## Test-Driven Development Design Document

**Project:** ladl  
**Repository:** github.com/AndrewDonelson/ladl  
**Depends On:** [Strata L4](https://github.com/AndrewDonelson/Strata)  
**Status:** Design / Pre-Implementation  
**Version:** 0.1.0  

---

## Table of Contents

1. [Legal Foundation](#legal-foundation)
2. [Overview](#overview)
3. [Privacy Model](#privacy-model)
4. [Age Groups and Verification Levels](#age-groups-and-verification-levels)
5. [Binary Modes](#binary-modes)
6. [Identity System](#identity-system)
7. [Verification Flows](#verification-flows)
8. [API Reference](#api-reference)
9. [Core Data Structures](#core-data-structures)
10. [Test Plan](#test-plan)
    - [Unit Tests](#unit-tests)
    - [Integration Tests](#integration-tests)
    - [End-to-End Tests](#end-to-end-tests)
11. [Error Handling](#error-handling)
12. [Implementation Order](#implementation-order)

---

## Legal Foundation

### The Legal Privacy Argument is Sound

LADL is designed around a four-layer protection stack that maps directly to Fourth Amendment doctrine. Each layer independently raises the bar for any party attempting to link a UUID to a real person.

**Layer 1 — Public ledger tells you nothing actionable.**
`d2` attached to a UUID is not PII under any current legal definition. It identifies no one. You cannot subpoena a UUID and compel the disclosure of a person's identity from it, because no such linkage exists in any reachable system.

**Layer 2 — UUID-to-person link doesn't exist on the network.**
There is no database, no registry, no join table anywhere on the LADL that maps a UUID to an identity. The link exists only on the local machine that generated it. An adversary with full read access to every ledger node in the world learns nothing about who any UUID belongs to.

**Layer 3 — Physical or legal access to the machine is required.**
To go from UUID → person you need either the machine in hand or a court order compelling the machine owner to produce it. That requires a warrant, and warrants require probable cause. This is *Carpenter v. United States* (2018) territory — the Supreme Court has already ruled that digital data tied to a person's identity and location requires a warrant, rejecting the third-party doctrine as applied to pervasive digital records.

**Layer 4 — `ladl status` is the only oracle.**
Even with machine access, a forensically aware user could have their `~/.config/ladl/identity.key` on an encrypted volume or a detached device. The UUID is derived from the keypair — no keypair, no mapping. Physical possession of the machine does not guarantee recovery of the UUID-to-person link.

**The practical result:** a website gets `d2` and complies with California AB 2273. Law enforcement gets `d2` and a UUID and has nothing without a warrant and physical or compelled machine access. The user retains meaningful control at every layer.

> *The authors believe age verification mandates of this kind represent government overreach into private online activity. That said, LADL represents the correct balance — full legal compliance with the minimum possible privacy cost to users.*

---

## Overview

`ladl` is a single Go binary that implements a privacy-preserving, decentralized age verification service for Linux. It binds a user's age attestation to their local Linux account, assigns them a permanent, non-reversible UUID, and publishes an anonymous record to the Linux Age Distributed Ledger (LADL) — a peer-to-peer gossip network built on Strata L4.

Any website or application can query the LADL with a UUID and receive exactly two bytes in return: the age group and verification level. No name, birthdate, document data, or IP address is ever stored on the ledger.

**Response format:** `{group}{level}` — e.g. `d2`, `c1`, `-0`

**Single binary, two modes:**
- Default (no flags): local service daemon — handles verification for users on this machine
- `--ledger`: full LADL node — additionally stores the full chain, syncs with peers, and serves the public query API

---

## Privacy Model

### What the LADL stores (per UUID)

The ledger stores only what is needed to produce the two-byte response. Internally, the L4Record payload is:

```json
{
  "g": "d",
  "l": 2,
  "t": "2024-11"
}
```

`g` = age group (one lowercase letter), `l` = verification level (0–3), `t` = coarse timestamp (month + year only).

### What the public query returns

```
d2
```

Two bytes. Plain text. No JSON, no schema, no field names. The consuming application interprets the response using the encoding table below.

### What the LADL never stores

- Name
- Birthdate or full date of birth
- Document number or document type
- IP address of user or verifying machine
- Linux username or UID
- Machine ID
- Any linkage between two UUIDs

### UUID Privacy Guarantee

A UUID is derived from the user's Ed25519 public key. It is a one-way derivation — given a UUID, it is computationally infeasible to reverse to the keypair or to the Linux user account. The only party that can associate a UUID with a real person is the user themselves.

---

## Age Groups and Verification Levels

### Response Encoding

The public query response is always exactly two bytes: `{group}{level}`.

```
{UUID}:{group}{level}
123e4567-e89b-12d3-a456-426614174000:d2
```

### Age Group Codes

| Byte | Label | Range | Use Case |
|------|-------|-------|----------|
| `-` | No record | — | UUID registered, no age claim made |
| `a` | Under 13 | 0–12 | COPPA territory; no adult content |
| `b` | Teen | 13–17 | Minor; no adult content or purchases |
| `c` | Adult | 18–20 | Adult content; no alcohol or cannabis |
| `d` | Full Adult | 21+ | No restrictions |

### Verification Level Codes

| Byte | Name | Description | Trust |
|------|------|-------------|-------|
| `0` | Unverified | Account exists; no age claim made | None |
| `1` | Self-Attested | User declared their own age group | Low |
| `2` | Document-Assisted | Local OCR verified a government ID; document never left the machine | Medium |
| `3` | Verifiable Credential | Cryptographic proof from a W3C VC issuer | High |

### Query Response Semantics

| Response | HTTP Status | Meaning |
|----------|-------------|---------|
| `d2` | 200 | Full adult, document-verified |
| `c1` | 200 | Adult (18–20), self-attested |
| `-0` | 200 | Registered, no age claimed |
| *(empty)* | 404 | UUID not known to this ledger |

**404 vs `-0`:** A 404 means the UUID has never been registered. A `-0` means the user created an identity but has not yet completed any verification step. Apps treat both as deny, but can use the distinction to decide whether to prompt the user to register (`404`) or to complete verification (`-0`).

Level 1 is the default. Upgrading to Level 2 or 3 is user-initiated and irreversible without a new revocation and re-registration.

### Application Threshold Logic

Apps receive the two bytes and apply their own threshold. Strata and LADL have no opinion on what constitutes an acceptable group or level.

```
got "d2" → group d >= c? yes. level >= 1? yes. → allow
got "c1" → group c >= c? yes. level >= 2? no.  → deny (site requires document verification)
got "b1" → group b >= c? no.                   → deny
got "-0" → no group.                            → deny, prompt to complete verification
404      → unknown UUID.                        → deny, prompt to register
```

---

## Binary Modes

### Peer Mode (default, no flags)

```
ladl [--port 7743] [--config /etc/ladl/config.yaml]
```

- Runs as a systemd service
- Exposes a **localhost-only** HTTP API on `127.0.0.1:7743`
- Alternatively exposes a Unix domain socket at `/run/ladl/ladl.sock`
- Handles verification for all users on this machine
- Participates in LADL gossip (reads and publishes) if Strata L4 is configured
- Does **not** store the full chain or expose a public-facing API

### Ledger Mode

```
ladl --ledger [--port 7743] [--config /etc/ladl/config.yaml]
```

- Everything in peer mode **plus**:
- Stores the full LADL block chain locally
- Exposes a **public** HTTP API on all interfaces (`0.0.0.0:7743`)
- Serves block sync requests from other nodes
- Rate-limits public queries (100 req/min per IP, 1000/hr)

### CLI Commands

```
ladl verify                  # initiate or update verification for current user
ladl status                  # show local and public status for current user
ladl uuid                    # print current user's UUID only
ladl export-identity         # export encrypted keypair backup
ladl import-identity <file>  # import keypair (restores UUID from previous install)
ladl revoke                  # revoke current user's LADL record
ladl version                 # print build version and Strata L4 version
```

### `ladl status` Output Format

```
$ ladl status

Local:   123e4567-e89b-12d3-a456-426614174000  d2  (confirmed)
Public:  123e4567-e89b-12d3-a456-426614174000  d2  (synced 4 min ago)
```

No internet connection:
```
Local:   123e4567-e89b-12d3-a456-426614174000  d2  (confirmed)
Public:  unreachable — showing cached local status
```

Not yet registered:
```
Local:   no identity found — run 'ladl verify' to get started
```

Registered but unverified:
```
Local:   123e4567-e89b-12d3-a456-426614174000  -0  (pending verification)
Public:  123e4567-e89b-12d3-a456-426614174000  -0
```

---

## Identity System

### Keypair Generation

On first `ladl verify` call for a user:
1. Service generates an Ed25519 keypair
2. Private key stored at `~/.config/ladl/identity.key` (mode 0600, owned by user)
3. Public key stored at `~/.config/ladl/identity.pub` (mode 0644)
4. UUID derived as: `hex(SHA256(pubkey))` formatted as RFC 4122 UUID v5-style string

### UUID Derivation

```
UUID = format_uuid(SHA256(ed25519_public_key_bytes)[:16])
```

The UUID is stable as long as the keypair exists. It does not depend on the machine, the distro, or the Linux UID — only on the keypair.

### System-Level Binding

The `ladl` daemon runs with elevated privileges to resolve the calling user's Linux UID. It maintains a system-level mapping at `/etc/ladl/uid_map` (mode 0600, root-owned):

```
<uid>:<sha256(uid + machine_id + system_salt)> → identity_file_path
```

This mapping prevents one Linux user from claiming another user's identity file. The system salt is generated at install time and stored in `/etc/ladl/salt` (mode 0400, root-owned).

### Export / Import

**Export:**
```
ladl export-identity --output ~/ladl-backup.key
```
Prompts for a passphrase. Produces an AES-256-GCM encrypted file containing the private key. UUID can be fully restored from this file on any Linux machine.

**Import:**
```
ladl import-identity ~/ladl-backup.key
```
Prompts for passphrase. Decrypts and installs the keypair. Service queries LADL to confirm the UUID's existing verification level, skipping re-verification if already confirmed.

---

## Verification Flows

### Level 1 — Self-Attestation

```
User runs: ladl verify

1. ladl prompts: "Select your age group: a) Under 13  b) Teen  c) Adult  d) 21+"
2. User selects group
3. ladl generates keypair if not present
4. ladl constructs L4Record:
     { uuid, app_id: "ladl", payload: { g: "d", l: 1, t: "2024-11" }, ... }
5. ladl signs with user keypair (UserSig)
6. ladl publishes to LADL via Strata L4
7. ladl prints: UUID and two-byte status confirmation (e.g. "d1")
```

### Level 2 — Document-Assisted (Local OCR)

```
User runs: ladl verify --level 2

1. ladl prompts for document image path (JPEG or PNG)
2. ladl runs Tesseract OCR locally (subprocess call to tesseract binary)
3. OCR parser extracts date of birth field from document text
4. ladl computes age from DOB; determines age group letter
5. Document image and raw OCR text are immediately zeroed and deleted
6. ladl sets l: 2 in the L4Record payload
7. Record is signed with user keypair (UserSig provides Level 2 proof)
8. ladl publishes to LADL
9. Original document image is never written to disk by ladl —
   user provides path to their own pre-existing file
```

**Supported document types for OCR:**
- Driver's license (US formats, heuristic field detection)
- Passport (ICAO MRZ line parsing)
- National ID card (generic date field detection)

### Level 3 — Verifiable Credential (Future)

Placeholder implementation. Service accepts a W3C VC JSON-LD document, verifies the issuer's signature using the public DID in the `issuer` field, extracts the age claim, and records `l: 3`. No VC content is sent to the LADL.

---

## API Reference

### Local API (Peer Mode, localhost only)

All local API endpoints are restricted to `127.0.0.1` or the Unix socket `/run/ladl/ladl.sock`. Requests from any other origin return `403`.

#### `GET /status`

Returns the current user's local and public verification status in human-readable form. This is the programmatic equivalent of `ladl status`.

**Response:**
```json
{
  "uuid":   "123e4567-e89b-12d3-a456-426614174000",
  "local":  "d2",
  "public": "d2",
  "public_synced_at": "2024-11",
  "public_reachable": true
}
```

`local` and `public` are always the two-byte format. If public is unreachable, `public` echoes the local value and `public_reachable` is `false`.

#### `GET /uuid`

Returns only the current user's UUID. Suitable for applications that need to pass the UUID to a remote service.

**Response:**
```
123e4567-e89b-12d3-a456-426614174000
```

Plain text, no JSON wrapper.

#### `POST /verify`

Initiates or upgrades verification. For Level 1, body specifies the age group letter. For Level 2, body specifies the document image path.

**Request (Level 1):**
```json
{ "group": "d", "level": 1 }
```

**Request (Level 2):**
```json
{ "level": 2, "document_path": "/home/user/id_scan.jpg" }
```

**Response:** Two bytes, plain text.
```
d2
```

#### `POST /revoke`

Revokes the current user's LADL record. Requires `{ "confirm": true }` in the body.

**Response:**
```json
{ "revoked": true, "uuid": "123e4567-e89b-12d3-a456-426614174000" }
```

---

### Public API (Ledger Mode only)

#### `GET /q/{uuid}` — Primary Query Endpoint

The sole public endpoint for age verification queries. Returns exactly two bytes, plain text.

```
GET /q/123e4567-e89b-12d3-a456-426614174000
```

| Scenario | HTTP Status | Body |
|----------|-------------|------|
| Known UUID, verified | 200 | `d2` |
| Known UUID, unverified | 200 | `-0` |
| UUID never registered | 404 | *(empty)* |
| UUID revoked | 410 | *(empty)* |

**410 Gone** for revoked UUIDs signals to apps that the user deliberately withdrew — distinct from never having registered (404). Apps treat both as deny.

**Rate limits:** 100 requests/minute per IP, 1,000 requests/hour per IP. Exceeding returns `429` with a `Retry-After` header.

**Example shell client:**
```bash
result=$(curl -s "https://ldl.ubuntu.com:7743/q/$UUID")
# result is "d2", "-0", or empty (check HTTP status for 404/410)
```

#### `GET /peers`

Returns known LADL peer addresses. Used by nodes during bootstrap and peer discovery.

**Response:**
```json
{
  "peers": [
    { "address": "ldl.fedoraproject.org:7743", "node_id": "abc123...", "block_height": 94201 }
  ]
}
```

#### `POST /sync`

Internal P2P endpoint used by Strata L4 transport for block synchronization. Not intended for application use.

---

## Core Data Structures

```go
// VerificationPayload is stored as the Payload of the Strata L4Record.
// Field names are deliberately terse — this is the only data on the public ledger.
type VerificationPayload struct {
    G string `json:"g"` // age group: "-" | "a" | "b" | "c" | "d"
    L int    `json:"l"` // verification level: 0 | 1 | 2 | 3
    T string `json:"t"` // coarse timestamp: "YYYY-MM"
}

// TwoByteResponse is the canonical response returned by GET /q/{uuid}.
// It is always exactly two bytes: group letter + level digit.
// Example: "d2", "c1", "-0"
type TwoByteResponse string

// UserIdentity represents a local user's ladl identity.
type UserIdentity struct {
    UUID      string    `json:"uuid"`
    PublicKey string    `json:"public_key"` // hex-encoded Ed25519 public key
    CreatedAt time.Time `json:"created_at"`
    LinuxUID  int       `json:"-"`          // never serialized
}

// LocalRecord is the full local state stored in the user's config directory.
type LocalRecord struct {
    Identity    UserIdentity
    Payload     VerificationPayload
    Confirmed   bool      // true once LADL quorum is reached
    LastSyncAt  time.Time
}

// FormatTwoBytes produces the canonical two-byte string from a payload.
// Returns "-0" for empty group. Always lowercase.
func FormatTwoBytes(p VerificationPayload) TwoByteResponse {
    g := p.G
    if g == "" {
        g = "-"
    }
    return TwoByteResponse(fmt.Sprintf("%s%d", g, p.L))
}
```

---

## Test Plan

---

### Unit Tests

#### `internal/identity/identity_test.go`

| Test | Description | Expected |
|------|-------------|----------|
| `TestGenerateKeypair` | Generate new identity keypair | Non-nil pub and priv keys |
| `TestDeriveUUID_Deterministic` | Derive UUID from same pubkey twice | Identical UUIDs |
| `TestDeriveUUID_Unique` | Derive UUID from two different pubkeys | Different UUIDs |
| `TestDeriveUUID_Format` | Derived UUID | Valid RFC 4122 format |
| `TestSaveLoadIdentity` | Save identity to temp dir, reload | Round-trip equality |
| `TestLoadIdentity_NotFound` | Load from non-existent path | Returns `ErrIdentityNotFound` |
| `TestLoadIdentity_WrongPermissions` | Identity file readable by other users | Returns `ErrInsecurePermissions` |
| `TestSystemBinding_UniquePerUID` | Generate system binding for UID 1000 and 1001 | Different binding hashes |
| `TestSystemBinding_Deterministic` | Generate binding for same UID twice | Same hash |

---

#### `internal/identity/export_test.go`

| Test | Description | Expected |
|------|-------------|----------|
| `TestExportEncrypts` | Export identity with passphrase | Output file is not plain keypair bytes |
| `TestImportDecrypts` | Export then import with correct passphrase | Keypair matches original |
| `TestImportWrongPassphrase` | Import with wrong passphrase | Returns `ErrDecryptionFailed` |
| `TestExportImport_UUIDPreserved` | Export, import, derive UUID | UUID matches original |
| `TestExport_CreatesFile` | Export to specified path | File exists at path |
| `TestImport_OverwriteExisting` | Import when identity already exists | Prompts for confirmation (mock prompt returns false → no overwrite) |

---

#### `internal/verification/level1_test.go`

| Test | Description | Expected |
|------|-------------|----------|
| `TestLevel1_ValidGroup_D` | Submit group "d" | Returns payload with `g:"d"`, `l:1` |
| `TestLevel1_AllGroups` | Submit each of a, b, c, d | All accepted; correct letter stored |
| `TestLevel1_InvalidGroup` | Submit group "x" | Returns `ErrInvalidAgeGroup` |
| `TestLevel1_UppercaseRejected` | Submit group "D" (uppercase) | Returns `ErrInvalidAgeGroup`; groups are lowercase only |
| `TestLevel1_EmptyGroup` | Submit empty group | Returns `ErrInvalidAgeGroup` |
| `TestLevel1_TimestampFormat` | Check `t` field | Matches `"YYYY-MM"` pattern |
| `TestLevel1_ProducesSignedRecord` | Level 1 verification flow | Returned L4Record has UserSig set |
| `TestLevel1_TwoByte_Output` | Level 1 for group "d" | `FormatTwoBytes` returns `"d1"` |

---

#### `internal/verification/level2_test.go`

| Test | Description | Expected |
|------|-------------|----------|
| `TestLevel2_OCR_ValidDriversLicense` | Run OCR on test fixture DL image | Extracts DOB, computes correct group letter |
| `TestLevel2_OCR_ValidPassportMRZ` | Run OCR on test fixture passport | Parses MRZ DOB correctly |
| `TestLevel2_OCR_NoDOBFound` | Run OCR on blank image | Returns `ErrDOBNotFound` |
| `TestLevel2_OCR_UnreadableImage` | Pass binary garbage as image | Returns `ErrOCRFailed` |
| `TestLevel2_DocumentNotRetained` | Run Level 2 flow | No document data in returned record or local state |
| `TestLevel2_GroupFromDOB_Exactly18` | DOB yields person aged exactly 18 | Group is `"c"` |
| `TestLevel2_GroupFromDOB_Exactly21` | DOB yields person aged exactly 21 | Group is `"d"` |
| `TestLevel2_GroupFromDOB_Under13` | DOB yields person aged 10 | Group is `"a"` |
| `TestLevel2_LevelInPayload` | Complete Level 2 flow | Payload has `l:2` |
| `TestLevel2_TwoByte_Output` | Level 2 for group "d" | `FormatTwoBytes` returns `"d2"` |
| `TestLevel2_TesseractUnavailable` | Tesseract not installed | Returns `ErrTesseractNotFound` with install hint |

---

#### `internal/verification/level3_test.go`

| Test | Description | Expected |
|------|-------------|----------|
| `TestLevel3_ValidVC_AcceptedStructure` | Well-formed W3C VC JSON | Parsed without error |
| `TestLevel3_InvalidIssuerSig` | VC with tampered issuer signature | Returns `ErrVCInvalidSignature` |
| `TestLevel3_MissingAgeClaim` | VC without age or birthdate claim | Returns `ErrVCMissingAgeClaim` |
| `TestLevel3_LevelInPayload` | Valid VC flow | Payload has `l:3` |
| `TestLevel3_NoVCDataInRecord` | Complete Level 3 flow | Returned L4Record payload contains no VC fields |

---

#### `internal/format/twobyte_test.go`

| Test | Description | Expected |
|------|-------------|----------|
| `TestFormatTwoBytes_D2` | Payload `{g:"d", l:2}` | Returns `"d2"` |
| `TestFormatTwoBytes_A0` | Payload `{g:"a", l:0}` | Returns `"a0"` |
| `TestFormatTwoBytes_EmptyGroup` | Payload `{g:"", l:0}` | Returns `"-0"` |
| `TestFormatTwoBytes_AlwaysLowercase` | All valid group values | Output is always lowercase |
| `TestFormatTwoBytes_Length` | Any valid payload | Length is always exactly 2 |
| `TestParseTwoBytes_Valid` | Parse `"d2"` | Returns `{g:"d", l:2}` |
| `TestParseTwoBytes_Unverified` | Parse `"-0"` | Returns `{g:"-", l:0}` |
| `TestParseTwoBytes_Invalid` | Parse `"X9"` | Returns `ErrInvalidTwoByteResponse` |
| `TestParseTwoBytes_WrongLength` | Parse `"d"` or `"d21"` | Returns `ErrInvalidTwoByteResponse` |

---

#### `internal/api/local_api_test.go`

| Test | Description | Expected |
|------|-------------|----------|
| `TestStatusEndpoint_Verified` | GET /status for verified user | 200; `local` and `public` fields are two-byte strings |
| `TestStatusEndpoint_Unverified` | GET /status for user with no identity | 200; `local` is `"-0"` |
| `TestStatusEndpoint_PublicUnreachable` | GET /status, ledger unreachable | 200; `public_reachable: false`, `public` echoes local |
| `TestUUIDEndpoint` | GET /uuid | 200; plain text UUID, no JSON wrapper |
| `TestVerifyEndpoint_Level1` | POST /verify `{group:"d", level:1}` | 200; body is `"d1"` |
| `TestVerifyEndpoint_Level2` | POST /verify `{level:2, document_path:...}` | 200; body is two-byte result |
| `TestVerifyEndpoint_MissingBody` | POST /verify with empty body | 400 |
| `TestVerifyEndpoint_InvalidLevel` | POST /verify with `level:9` | 400 |
| `TestVerifyEndpoint_UppercaseGroup` | POST /verify with `group:"D"` | 400; only lowercase accepted |
| `TestRevokeEndpoint` | POST /revoke with `confirm:true` | 200; revocation record published |
| `TestRevokeEndpoint_NoConfirm` | POST /revoke without confirm | 400 |
| `TestRevokeEndpoint_NotVerified` | POST /revoke with no prior verification | 404 |
| `TestLocalAPI_RejectsRemoteOrigin` | Request from non-localhost IP | 403 |

---

#### `internal/api/ledger_api_test.go`

| Test | Description | Expected |
|------|-------------|----------|
| `TestQueryEndpoint_Found` | GET /q/{uuid} for known, verified UUID | 200; body is two-byte string e.g. `"d2"` |
| `TestQueryEndpoint_Unverified` | GET /q/{uuid} for registered-unverified UUID | 200; body is `"-0"` |
| `TestQueryEndpoint_NotFound` | GET /q/{unknown-uuid} | 404; empty body |
| `TestQueryEndpoint_Revoked` | GET /q/{revoked-uuid} | 410; empty body |
| `TestQueryEndpoint_ResponseIsPlainText` | Check Content-Type header | `text/plain; charset=utf-8` |
| `TestQueryEndpoint_ResponseLength` | Measure response body for any known UUID | Exactly 2 bytes |
| `TestPeersEndpoint` | GET /peers | 200 with peers JSON array |
| `TestRateLimiting_PerMinute` | Exceed 100 req/min from same IP | 429 with `Retry-After` header |
| `TestRateLimiting_PerHour` | Exceed 1000 req/hr from same IP | 429 with `Retry-After` header |
| `TestRateLimiting_Resets` | Wait for rate limit window | Requests accepted again |
| `TestLedgerAPI_NotAvailableInPeerMode` | Call /q on peer-mode instance | 501 |

---

### Integration Tests

#### `test/integration/verify_flow_test.go`

| Test | Description | Expected |
|------|-------------|----------|
| `TestFullFlow_Level1` | Fresh user → verify level 1 → status → query via LADL | UUID matches; LADL returns `"d1"` |
| `TestFullFlow_Level2` | Fresh user → verify level 2 with fixture image → query LADL | LADL returns `"d2"` |
| `TestUpgrade_L1_to_L2` | Verified at Level 1 → run `ladl verify --level 2` | LADL record updates; query returns `"d2"` |
| `TestRevoke_Then_Reverify` | Verify → revoke → re-verify | New UUID issued; old UUID returns 410; new UUID queryable |
| `TestIdentityExport_Import` | Verify on node A → export → import on node B → query | Same UUID on both nodes; same two-byte result |
| `TestMultiUser_SameMachine` | Two Linux users, each verify independently | Different UUIDs; each queries correctly |

---

#### `test/integration/ladl_sync_test.go`

Two `ladl` instances connected over loopback (one peer, one ledger).

| Test | Description | Expected |
|------|-------------|----------|
| `TestVerify_PropagatesTo_Ledger` | Verify on peer node | Ledger node answers `/q/{uuid}` within sync interval |
| `TestRevoke_PropagatesTo_Ledger` | Revoke on peer node | Ledger node returns 410 for that UUID |
| `TestQuery_Peer_Asks_Ledger` | Query unknown UUID on peer node | Peer fetches from ledger, returns two-byte result |
| `TestLedger_ServesPublicQuery` | Verify on peer, query public API on ledger | Returns correct two-byte plain text |
| `TestLedger_TwoLedgerNodes_Consistency` | Two ledger nodes, verify on one | Both nodes return identical two-byte result after sync |

---

### End-to-End Tests

These tests run against a live local cluster (3 nodes: 1 peer + 2 ledger) and are tagged `//go:build e2etests`.

| Test | Description | Expected |
|------|-------------|----------|
| `TestE2E_VerifyAndQuery` | Verify via CLI, query via curl `/q/{uuid}` | Two-byte plain text response |
| `TestE2E_RevokeAndQuery` | Verify, revoke, query | 410 from ledger API |
| `TestE2E_LedgerNodeFailover` | Verify, kill one ledger node, query other | Same two-byte result from surviving ledger |
| `TestE2E_Level2_RealOCR` | Level 2 with a real test fixture document | Correct group letter extracted and published |
| `TestE2E_RateLimit_Observed` | Hammer `/q/{uuid}` from single IP | 429 with `Retry-After` at expected threshold |
| `TestE2E_NewNodeJoins_Syncs` | Start third ledger node after 50 records exist | New node syncs all 50; queries correct |
| `TestE2E_CLI_Status_Output` | Run `ladl status` as a real Linux user | Two lines: Local and Public, each with UUID and two-byte result |
| `TestE2E_ShellClient_Curl` | `curl /q/{uuid}` and inspect response | Body is exactly 2 bytes; Content-Type is text/plain |

---

## Error Handling

```go
var (
    // Identity errors
    ErrIdentityNotFound      = errors.New("ladl: no identity found for this user; run 'ladl verify'")
    ErrInsecurePermissions   = errors.New("ladl: identity file has insecure permissions")
    ErrDecryptionFailed      = errors.New("ladl: failed to decrypt identity backup (wrong passphrase?)")
    ErrIdentityExists        = errors.New("ladl: identity already exists; use --force to overwrite")

    // Verification errors
    ErrInvalidAgeGroup       = errors.New("ladl: group must be a, b, c, or d (lowercase)")
    ErrDOBNotFound           = errors.New("ladl: could not locate date of birth in document")
    ErrOCRFailed             = errors.New("ladl: OCR processing failed")
    ErrTesseractNotFound     = errors.New("ladl: tesseract binary not found; install with: apt install tesseract-ocr")
    ErrVCInvalidSignature    = errors.New("ladl: verifiable credential signature is invalid")
    ErrVCMissingAgeClaim     = errors.New("ladl: verifiable credential does not contain an age claim")

    // Response format errors
    ErrInvalidTwoByteResponse = errors.New("ladl: response must be exactly 2 bytes in format {group}{level}")

    // API errors
    ErrRemoteRequestDenied   = errors.New("ladl: local API only accepts requests from localhost")
    ErrRateLimitExceeded     = errors.New("ladl: rate limit exceeded")
    ErrLedgerModeRequired    = errors.New("ladl: this endpoint requires --ledger mode")

    // LADL errors (wrap Strata L4 errors)
    ErrLADLUnavailable       = errors.New("ladl: LADL is unreachable; record saved locally, will sync when available")
    ErrLADLRecordRevoked     = errors.New("ladl: this UUID has been revoked on the LADL")
)
```

---

## Implementation Order

```
Stage 1: Identity keypair generation, UUID derivation, save/load
         → Tests: TestGenerateKeypair, TestDeriveUUID_*, TestSaveLoad*

Stage 2: System-level UID binding and salt generation
         → Tests: TestSystemBinding_*

Stage 3: Identity export/import (AES-256-GCM encrypted backup)
         → Tests: TestExport*, TestImport*

Stage 4: Two-byte format — FormatTwoBytes, ParseTwoBytes
         → Tests: internal/format/twobyte_test.go (all)

Stage 5: Level 1 verification flow
         → Tests: TestLevel1_*

Stage 6: Local API endpoints: /status, /uuid, /verify (level 1), /revoke
         → Tests: TestStatusEndpoint_*, TestUUIDEndpoint, TestVerifyEndpoint_*, TestRevokeEndpoint*

Stage 7: Level 2 verification — Tesseract OCR integration, DOB parsing, group derivation
         → Tests: TestLevel2_*

Stage 8: Strata L4 integration — publish VerificationPayload, query, revoke
         → Tests: TestVerify_PropagatesTo_Ledger, TestRevoke_PropagatesTo_Ledger

Stage 9: Ledger mode — /q/{uuid} plain text API, 404/410 semantics, rate limiting, /peers
         → Tests: TestQueryEndpoint_*, TestRateLimiting_*, TestPeersEndpoint

Stage 10: Full integration flows — multi-user, cross-node sync
          → Tests: test/integration/*

Stage 11: Level 3 placeholder — VC parsing and signature verification
          → Tests: TestLevel3_*

Stage 12: End-to-end cluster tests
          → Tests: test/e2e/*

Stage 13: systemd unit file, install script, man page, README
```

---

## Systemd Unit File (Reference)

```ini
[Unit]
Description=ladl — Linux Age Distributed Ledger Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/ladl --config /etc/ladl/config.yaml
Restart=on-failure
RestartSec=5s
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

---

## Configuration Reference

```yaml
# /etc/ladl/config.yaml

service:
  port: 7743
  socket: "/run/ladl/ladl.sock"
  log_level: "info"               # "debug" | "info" | "warn" | "error"

verification:
  default_level: 1
  ocr:
    tesseract_path: "/usr/bin/tesseract"
    lang: "eng"
    supported_documents:
      - "drivers_license"
      - "passport"
      - "national_id"

strata:
  l4:
    enabled: true
    mode: "peer"                  # Set to "ledger" for full node
    port: 7743
    sync_interval: "30s"
    max_peers: 50
    quorum: 3
    bootstrap_peers:
      - "ldl.ubuntu.com:7743"
      - "ldl.fedoraproject.org:7743"
      - "ldl.linuxmint.com:7743"
      - "ldl1.ladl.org:7743"
      - "ldl2.ladl.org:7743"
    dns_seed: "peers.ladl.org"
```

---

*Document version 0.1.0 — subject to revision as implementation begins.*