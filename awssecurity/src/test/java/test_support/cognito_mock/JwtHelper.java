/*
 * Copyright 2021 Haulmont.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package test_support.cognito_mock;

import com.nimbusds.jose.*;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;


public final class JwtHelper {

    public static String token(String keyId, Map<String, Object> payloadBody) throws JOSEException {
        JWSObject jws = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyId).build(),
                new Payload(payloadBody)
        );
        return Rsa256Helper.sign(jws).serialize();
    }

    public static String accessToken(String keyId,
                                     String username,
                                     String[] userGroups,
                                     String[] scopes,
                                     String issuer,
                                     LocalDateTime issued,
                                     long expiresIn) throws JOSEException {
        long issuedAt = issued.atZone(ZoneId.systemDefault()).toEpochSecond();
        long expiresAt = issuedAt + expiresIn;
        Map<String, Object> payloadBody = new HashMap<>();
        payloadBody.put("sub", UUID.randomUUID().toString());
        payloadBody.put("cognito:groups", userGroups);
        payloadBody.put("event_id", UUID.randomUUID().toString());
        payloadBody.put("scope", String.join(" ", scopes));
        payloadBody.put("auth_time", issuedAt);
        payloadBody.put("iss", issuer);
        payloadBody.put("exp", expiresAt);
        payloadBody.put("iat", issuedAt);
        payloadBody.put("jti", UUID.randomUUID().toString());
        payloadBody.put("client_id", "test_client");
        payloadBody.put("username", username);
        return token(keyId, payloadBody);
    }

    public static String accessToken(String issuer, LocalDateTime issued) throws JOSEException {
        return accessToken(
                "test_key",
                "test_user",
                new String[]{"resource$test-role", "row_level$test-row-level"},
                new String[]{"openid"},
                issuer,
                issued,
                3600
        );
    }

    public static String accessToken(String issuer) throws JOSEException {
        return accessToken(issuer, LocalDateTime.now());
    }

    public static String idToken(String keyId,
                                 String username,
                                 String[] userGroups,
                                 String issuer,
                                 LocalDateTime issued,
                                 long expiresIn,
                                 String email,
                                 boolean verifiedEmail,
                                 String nonce) throws JOSEException {
        long issuedAt = issued.atZone(ZoneId.systemDefault()).toEpochSecond();
        long expiresAt = issuedAt + expiresIn;
        Map<String, Object> payloadBody = new HashMap<>();
        payloadBody.put("sub", UUID.randomUUID().toString());
        payloadBody.put("aud", "test_client");
        payloadBody.put("cognito:groups", userGroups);
        payloadBody.put("email_verified", verifiedEmail);
        payloadBody.put("event_id", UUID.randomUUID().toString());
        payloadBody.put("token_use", "id");
        payloadBody.put("auth_time", issuedAt);
        payloadBody.put("iss", issuer);
        payloadBody.put("cognito:username", username);
        payloadBody.put("exp", expiresAt);
        payloadBody.put("iat", issuedAt);
        payloadBody.put("jti", UUID.randomUUID().toString());
        payloadBody.put("email", email);
        payloadBody.put("nonce", nonce);
        return token(keyId, payloadBody);
    }

    public static String idToken(String issuer, LocalDateTime issued, String nonce) throws JOSEException {
        return idToken("test_key",
                "test_user",
                new String[]{"resource$test-role", "row_level$test-row-level"},
                issuer,
                issued,
                3600,
                "test@test.com",
                true,
                nonce);
    }

    private JwtHelper() {

    }
}
