package com.trustlink.server

import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import kotlinx.serialization.json.Json

const val DEFAULT_ORIGIN = "https://demo.trustlink.fr"

fun main() {
    val port = System.getenv("PORT")?.toIntOrNull() ?: 8080
    embeddedServer(Netty, port = port) { trustLinkModule(Store()) }.start(wait = true)
}

fun Application.trustLinkModule(store: Store, origin: String = DEFAULT_ORIGIN) {
    install(ContentNegotiation) {
        json(Json { ignoreUnknownKeys = true })
    }
    install(StatusPages) {
        exception<Throwable> { call, cause ->
            call.respond(
                HttpStatusCode.BadRequest,
                ErrorResponse(cause.message ?: "invalid request"),
            )
        }
    }

    routing {
        get("/health") { call.respond(mapOf("status" to "ok")) }

        /** Registers the tag fingerprint and the public key produced during NFC enrollment. */
        post("/enroll") {
            val device = store.enroll(call.receive<EnrollRequest>())
            call.respond(EnrollResponse(device.deviceId, device.enrolledAtSeconds))
        }

        /** Issues a single-use challenge; `qrPayload` is what the service renders as a QR code. */
        post("/challenge") {
            val challenge = store.issueChallenge(origin)
            call.respond(
                ChallengeResponse(
                    qrPayload = challenge.toQrPayload(),
                    sessionId = challenge.sessionId,
                    expiresAtSeconds = challenge.expiresAtSeconds,
                )
            )
        }

        /** Verifies the biometric-gated ECDSA signature against the enrolled public key. */
        post("/verify") {
            val result = Verifier.verify(
                store = store,
                request = call.receive<VerifyRequest>(),
                nowSeconds = System.currentTimeMillis() / 1000,
            )
            val status = if (result.granted) HttpStatusCode.OK else HttpStatusCode.Unauthorized
            call.respond(status, result)
        }
    }
}
