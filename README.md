# PODCHAIN

**Cryptographic proof-of-delivery protocol for Nigerian logistics APIs.**

PODCHAIN provides cryptographically verifiable, tamper-evident, non-repudiable proof of delivery for API-based logistics platforms. It is designed specifically for the Nigerian last-mile logistics context.

---

## Libraries

| Library | Runtime | Purpose |
|---|---|---|
| `podchain` | Bun / TypeScript | Server-side protocol library |
| `podchain_flutter` | Flutter / Dart | Mobile-side signing library |
| `podchain-demo-api` | Bun | Demo logistics API (evaluation only) |
| `podchain-demo-app` | Flutter | Demo rider application (evaluation only) |

---

## How It Works

### 1. Key Registration
On first launch, the rider's mobile app generates an ECDSA P-256 key pair. The private key is stored in the device's hardware-backed secure storage and never leaves the device. The public key is registered with the logistics platform.

### 2. Delivery Signing
When the rider completes a delivery, the app constructs a signed payload containing:
- The task ID and rider ID
- A SHA-256 hash of the GPS coordinates
- A RecipientToken (tier-dependent recipient acknowledgement)
- The signing timestamp

The payload is signed with the rider's private key using ECDSA P-256.

### 3. Server Verification
The platform verifies the signature against the registered public key, validates the RecipientToken, consumes it (preventing replay), and stores the Proof Certificate in a SHA-256 hash chain.

### 4. Proof Certificate
The resulting Proof Certificate is cryptographically verifiable by any party with read access and satisfies Nigerian Evidence Act 2011 s.84 admissibility requirements.

---

## RecipientToken Tiers

| Tier | Name | Recipient Action | Use Case |
|---|---|---|---|
| 1 | Passive Token | None | Low-value deliveries, no smartphone |
| 2 | OTP | Share 6-digit code (or scan QR) | Standard deliveries |
| 3 | Two-Sided Signing | Sign via browser WebCrypto | High-value deliveries |

---

## Quick Start

### Server (`podchain`)

```bash
cd podchain
bun install
```

```typescript
import { PodChain } from 'podchain';
import { SQLiteAdapter } from 'podchain/adapters/sqlite';
import { Database } from 'bun:sqlite';

const podchain = new PodChain({
  storage: new SQLiteAdapter(new Database('proofs.db')),
});

// Register a rider's public key (from their mobile app)
await podchain.registerKey({ riderId: 'rider_001', publicKey: jwkPublicKey });

// Create a task and get the RecipientToken
const task = await podchain.createTask({
  riderId: 'rider_001',
  recipientName: 'Chidi Okeke',
  recipientPhone: '+2348012345678',
  deliveryAddress: '14 Broad Street, Lagos',
  tier: 2, // OTP scheme
});
// task.otp — dispatch to recipient via SMS

// Verify a submitted proof and issue a Proof Certificate
const certificate = await podchain.verifyAndStore({
  taskId: task.taskId,
  riderId: 'rider_001',
  payload: req.body.payload,    // canonical JSON from rider app
  signature: req.body.signature, // base64url ECDSA signature
});

// Verify the hash chain integrity
const report = await podchain.verifyChain();
console.log(report.chainIntact); // true
```

### Mobile (`podchain_flutter`)

```yaml
# pubspec.yaml
dependencies:
  podchain_flutter:
    path: ../podchain_flutter
```

```dart
import 'package:podchain_flutter/podchain_flutter.dart';

final podchain = PodChainFlutter(
  riderId: 'rider_001',
  onSubmit: (proof) async {
    final res = await http.post(
      Uri.parse('$baseUrl/tasks/${proof.taskId}/complete'),
      body: jsonEncode({
        'riderId': proof.riderId,
        'payload': proof.payload,
        'signature': proof.signature,
      }),
    );
    return res.statusCode == 200;
  },
);

// First launch — generate key and register
final publicKey = await podchain.generateOrRetrievePublicKey();
await platformApi.registerKey(riderId: 'rider_001', publicKey: publicKey);

// At delivery — sign and submit
final proof = await podchain.signDelivery(
  taskId: 'task_abc123',
  recipientProof: otpCode, // obtained from recipient
  coordinates: DeliveryCoordinates(latitude: 6.5244, longitude: 3.3792),
);

// Or — when offline, queue for later submission
await podchain.signAndQueue(
  taskId: 'task_xyz789',
  recipientProof: passiveToken,
  coordinates: currentLocation,
);
// Queue drains automatically when connectivity restores
```

---

## Running the Demo API

```bash
cd podchain-demo-api
bun install
bun run src/index.ts
# Server starts on http://localhost:3000
```

### API Endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/riders/register` | Register a rider's public key |
| POST | `/tasks` | Create a delivery task |
| GET | `/tasks/:id/recipient-token` | Get token status for a task |
| POST | `/tasks/:id/complete` | Submit a signed delivery proof |
| GET | `/tasks/:id/proof` | Retrieve a Proof Certificate |
| GET | `/chain/verify` | Verify hash chain integrity |
| GET | `/confirm/:id?nonce=X` | Tier 3 recipient signing page |
| POST | `/confirm/:id/sign` | Tier 3 recipient confirmation |

---

## Running Tests

```bash
# Server library tests
cd podchain
bun test

# Flutter library tests
cd podchain_flutter
flutter test
```

---

## Architecture

```
[Rider App]          [podchain_flutter]      [podchain + Demo API]      [SQLite]
    │                       │                         │                     │
    │── signDelivery() ────►│                         │                     │
    │                       │── ECDSA sign ──────────►│                     │
    │                       │                         │── verifySignature()  │
    │                       │                         │── validateToken()    │
    │                       │                         │── computeChainHash() │
    │                       │                         │── saveProof() ──────►│
    │◄─────────────── Proof Certificate ─────────────◄│                     │

[Recipient]                             (Tier 3 only)
    │── opens deep link ───────────────►[WebCrypto signing page]
    │                                         │── POST /confirm/:id/sign ──►│
```

---

## Security Properties

| Property | Mechanism |
|---|---|
| Delivery agent non-repudiation | ECDSA P-256 signature, hardware-backed private key |
| Recipient acknowledgement | Tiered RecipientToken (Passive / OTP / Two-Sided) |
| Replay attack prevention | Single-use token consumption; task-scoped proof registry |
| Tamper evidence | SHA-256 hash chain over all Proof Certificates |
| GPS privacy | Coordinates stored as SHA-256 hash (NDPA 2023 compliance) |
| Offline resilience | Client-side signing queue with 24-hour submission window |

---

## Known Limitations

- **Collusion**: If a recipient willingly shares an OTP before receiving a package, PODCHAIN cannot detect this cryptographically. The QR display variant of Tier 2 and the Tier 3 two-sided scheme significantly raise the practical barrier. PODCHAIN provides strong attribution, not collusion prevention.
- **GPS spoofing**: Coordinates are signed as claimed, not verified. Server-side velocity checks are recommended as a complementary control.
- **Tier 3 requires recipient action**: If the recipient does not complete the WebCrypto signing step, the delivery cannot be completed under Tier 3. An operational fallback policy is required.

---

## Legal Context

PODCHAIN-generated Proof Certificates are designed to satisfy:
- **Evidence Act 2011 (Nigeria)** — Section 84 computer-generated evidence requirements
- **Cybercrimes Act 2015 (Nigeria)** — Electronic record integrity requirements
- **NDPA 2023 (Nigeria)** — Data minimisation (coordinate hashing)

---

## Thesis

This implementation is the primary research deliverable for:

> *"Implementation of a Cryptographic Proof-of-Delivery Protocol for Non-Repudiation in Nigerian Logistics APIs"*  
> Masters in Information Technology (Cybersecurity), MIVA Open University

---

## Licence

MIT
