package com.trustlink.server

import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RoutesTest {

    private val fingerprint = "c".repeat(64)
    private val keyPair = TestKeys.generate()

    @Test
    fun `enroll then challenge then verify grants access`() = testApplication {
        val store = Store()
        application { trustLinkModule(store) }
        val client = createClient { install(ContentNegotiation) { json() } }

        assertEquals(HttpStatusCode.OK, client.get("/health").status)

        val enroll: EnrollResponse = client.post("/enroll") {
            contentType(ContentType.Application.Json)
            setBody(EnrollRequest(fingerprint, TestKeys.pem(keyPair)))
        }.body()
        assertTrue(enroll.deviceId.isNotBlank())

        val challengeResponse: ChallengeResponse = client.post("/challenge").body()
        val challenge = Challenge(
            sessionId = challengeResponse.sessionId,
            nonce = challengeResponse.qrPayload.substringAfter("\"nonce\":\"").substringBefore('"'),
            origin = DEFAULT_ORIGIN,
            expiresAtSeconds = challengeResponse.expiresAtSeconds,
        )

        val payload = TestKeys.payload(challenge, fingerprint, System.currentTimeMillis() / 1000)
        val request = VerifyRequest(
            sessionId = challenge.sessionId,
            payload = payload,
            signatureBase64 = TestKeys.sign(keyPair, payload),
        )

        val granted: HttpResponse = client.post("/verify") {
            contentType(ContentType.Application.Json)
            setBody(request)
        }
        assertEquals(HttpStatusCode.OK, granted.status)
        assertTrue(granted.body<VerifyResponse>().granted)

        val replay: HttpResponse = client.post("/verify") {
            contentType(ContentType.Application.Json)
            setBody(request)
        }
        assertEquals(HttpStatusCode.Unauthorized, replay.status)
        assertFalse(replay.body<VerifyResponse>().granted)
    }

    @Test
    fun `enroll rejects an unparseable public key`() = testApplication {
        application { trustLinkModule(Store()) }
        val client = createClient { install(ContentNegotiation) { json() } }

        val response: HttpResponse = client.post("/enroll") {
            contentType(ContentType.Application.Json)
            setBody(EnrollRequest(fingerprint, "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----"))
        }
        assertEquals(HttpStatusCode.BadRequest, response.status)
    }
}
