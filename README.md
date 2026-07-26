# TrustLink — Android prototype: QR + NFC + biometrics + Gemini risk analysis

Kotlin / Jetpack Compose prototype demonstrating three-factor strong authentication, with a
Gemini-powered anti-fraud engine in the loop.

## The authentication loop

```
1. QR code    ──► challenge issued by the remote service: {v, sid, nonce, origin, exp}
2. NFC        ──► proof of possession: the tag UID is hashed (salted SHA-256) and compared
                  to the enrolled fingerprint. The raw UID is never stored nor transmitted.
3. Biometrics ──► BiometricPrompt + CryptoObject unlocks a hardware-backed EC P-256 key
                  (StrongBox when available) which signs
                  "trustlink/v1|sid|nonce|origin|tagFingerprint|ts".
4. Gemini     ──► 0-100 risk score and ALLOW / CHALLENGE / DENY verdict, derived from
                  contextual signals only (never biometrics, never the raw UID).
```

The signature remains the only cryptographic proof of identity: Gemini is **advisory** and can
only harden the decision (DENY blocks access), never relax it. Without an API key, a local
rule-based engine takes over with the same thresholds.

## Modules

| File | Responsibility |
|---|---|
| `security/KeystoreManager.kt` | Non-exportable EC P-256 key, `setUserAuthenticationRequired(true)`, `AUTH_BIOMETRIC_STRONG`, invalidated when a new biometric is enrolled |
| `security/BiometricSigner.kt` | `BiometricPrompt` with `CryptoObject(Signature)` — signing is impossible without biometric confirmation |
| `nfc/NfcController.kt` | NFC foreground dispatch, salted SHA-256 fingerprint of the tag UID |
| `qr/QrChallengeScanner.kt` | Scanning via Google Code Scanner (no camera permission), challenge parsing and validation |
| `ai/GeminiRiskAnalyzer.kt` | `generateContent` call (`gemini-flash-lite-latest`, `responseMimeType: application/json`) with rule-based fallback |
| `data/EnrollmentStore.kt` | `EncryptedSharedPreferences`: tag fingerprint, public key, authentication history |
| `AuthViewModel.kt` | Loop orchestration and state machine |

## Configuration

```properties
# local.properties
sdk.dir=/path/to/Android/Sdk
GEMINI_API_KEY=your_key
```

The key is injected into `BuildConfig.GEMINI_API_KEY`. Without a key the app runs in
local-rules mode.

> In production the Gemini call belongs **server-side**: an API key shipped inside an APK is
> extractable. It lives client-side here to keep the prototype self-contained.

## Build

```bash
./gradlew :app:assembleDebug      # debug APK
./gradlew :app:testDebugUnitTest
```

Requires the Android SDK (platform 34, build-tools 34) and JDK 17.

## Trying the flow

1. Install the APK on a **physical device with NFC and an enrolled biometric** (emulators have
   no NFC).
2. Tap "Enroll my NFC tag", then hold an NFC card/badge against the phone.
3. Generate a test QR code containing, for example:
   ```json
   {"v":1,"sid":"s-1","nonce":"9f2c1b","origin":"https://demo.trustlink.fr","exp":4102444800}
   ```
4. Tap "Authenticate" → scan the QR code → tap the same NFC tag → confirm with biometrics.
5. The screen shows the signed assertion and the risk assessment.

Failure cases worth trying: tap a **different** NFC tag (→ DENY), use a QR code whose `exp` is
in the past (→ expired challenge), cancel the biometric prompt.

The UI is in English by default and localized in French through `res/values-fr/strings.xml`
(the device language decides).

## Backend (`:server`)

A Ktor service that issues the challenges and verifies the assertions. Run it with:

```bash
./gradlew :server:run          # listens on :8080, PORT overrides it
./gradlew :server:test
```

| Endpoint | Role |
|---|---|
| `POST /enroll` | Registers `{tagFingerprint, publicKeyPem}` produced by the on-device enrollment and returns a `deviceId` |
| `POST /challenge` | Issues a single-use challenge and returns `qrPayload`, the exact string to render as a QR code |
| `POST /verify` | Checks `{sessionId, payload, signatureBase64}` and answers `200 {granted:true}` or `401` |

`/verify` refuses unless **all** of the following hold: the session exists and has not been
consumed yet, the challenge has not expired, the signed payload is well formed and carries the
same `sid`/`nonce`/`origin` as the issued challenge, the device timestamp is within 120 s of the
server clock, the tag fingerprint belongs to an enrolled device, and the ECDSA signature checks
out **against the public key stored at enrollment** (a key sent in the request is never
trusted). The challenge is consumed on the first attempt, successful or not, so a nonce can
neither be replayed nor brute-forced.

State is in-memory (`Store`), which is the piece to swap for a database in a real deployment.

## Prototype limitations

- The Android app does not call the backend yet: it validates the loop locally and displays the
  assertion, which is what `POST /verify` expects as a body.
- Key attestation (`KeyGenParameterSpec.setAttestationChallenge`) is not used — it is what
  would prove to the server that the key really lives in a TEE/StrongBox.


---

### 📌 How to use this for GitHub

1. Create a new repository on GitHub.
2. Copy the content above into a file named `README.md` in the root of your project.
3. Add your actual screenshots inside a `screenshots/` folder to replace the placeholders.
4. Ensure the `LICENSE` file exists (if you choose MIT, update the badge accordingly).

Let me know if you need a separate `CHANGELOG.md` file or more details on any section!
