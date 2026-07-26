# TrustLink — prototype Android : QR + NFC + biométrie + analyse de risque Gemini

Prototype Kotlin / Jetpack Compose démontrant une authentification forte à trois facteurs,
avec un moteur anti-fraude Gemini dans la boucle.

## La boucle d'authentification

```
1. QR code   ──► challenge signé par le service : {v, sid, nonce, origin, exp}
2. NFC       ──► preuve de possession : l'UID du support est haché (SHA-256 salé)
                 et comparé à l'empreinte enrôlée. L'UID brut n'est ni stocké ni transmis.
3. Biométrie ──► BiometricPrompt + CryptoObject : débloque une clé EC P-256 du Keystore
                 matériel (StrongBox si dispo) qui signe
                 "trustlink/v1|sid|nonce|origin|tagFingerprint|ts".
4. Gemini    ──► score de risque 0-100 + verdict ALLOW / CHALLENGE / DENY à partir de
                 signaux contextuels uniquement (jamais de biométrie ni d'UID).
```

La signature reste la seule preuve cryptographique d'identité : Gemini est **consultatif**
et ne peut que durcir la décision (DENY bloque l'accès), jamais l'assouplir. En l'absence de
clé API, un moteur de règles local prend le relais avec les mêmes seuils.

## Modules

| Fichier | Rôle |
|---|---|
| `security/KeystoreManager.kt` | Clé EC P-256 non exportable, `setUserAuthenticationRequired(true)`, `AUTH_BIOMETRIC_STRONG`, invalidée si une nouvelle empreinte est enrôlée |
| `security/BiometricSigner.kt` | `BiometricPrompt` avec `CryptoObject(Signature)` — la signature est impossible sans validation biométrique |
| `nfc/NfcController.kt` | Foreground dispatch NFC, empreinte SHA-256 salée de l'UID |
| `qr/QrChallengeScanner.kt` | Scan via Google Code Scanner (aucune permission caméra), parsing et validation du challenge |
| `ai/GeminiRiskAnalyzer.kt` | Appel `generateContent` (`gemini-flash-lite-latest`, `responseMimeType: application/json`) + repli par règles |
| `data/EnrollmentStore.kt` | `EncryptedSharedPreferences` : empreinte du support, clé publique, historique |
| `AuthViewModel.kt` | Orchestration de la boucle et machine à états |

## Configuration

```properties
# local.properties
sdk.dir=/chemin/vers/Android/Sdk
GEMINI_API_KEY=votre_cle
```

La clé est injectée dans `BuildConfig.GEMINI_API_KEY`. Sans clé, l'app fonctionne en mode
règles locales.

> En production, l'appel Gemini doit être fait **côté serveur** : une clé API embarquée dans
> un APK est extractible. Ici elle est côté client pour garder le prototype autonome.

## Build

```bash
./gradlew :app:assembleDebug   # APK debug
./gradlew :app:testDebugUnitTest
```

Nécessite le SDK Android (platform 34, build-tools 34) et un JDK 17.

## Tester le flux

1. Installer l'APK sur un appareil physique **avec NFC et biométrie enrôlée** (l'émulateur
   n'a pas de NFC).
2. « Enrôler mon support NFC » puis approcher une carte/badge NFC.
3. Générer un QR code de test contenant, par ex. :
   ```json
   {"v":1,"sid":"s-1","nonce":"9f2c1b","origin":"https://demo.trustlink.fr","exp":4102444800}
   ```
4. « S'authentifier » → scanner le QR → approcher le même support → valider la biométrie.
5. L'écran affiche l'assertion signée et l'évaluation de risque.

Cas d'échec à essayer : approcher un **autre** support NFC (→ DENY), utiliser un QR avec
`exp` dans le passé (→ challenge expiré), annuler le prompt biométrique.

## Limites du prototype

- Pas de backend : le serveur qui émet le nonce et vérifie la signature ECDSA avec la clé
  publique enrôlée reste à écrire (`/challenge` + `/verify`).
- Le nonce n'est pas vérifié comme à usage unique côté client (c'est le rôle du serveur).
- L'attestation de clé (`KeyGenParameterSpec.setAttestationChallenge`) n'est pas exploitée :
  c'est elle qui prouverait au serveur que la clé vit bien dans un TEE/StrongBox.
