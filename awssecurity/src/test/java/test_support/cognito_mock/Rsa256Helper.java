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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

public final class Rsa256Helper {

    private static final RSAKey JWK = generateKeys();
    private static final RSAKey PUBLIC = JWK.toPublicJWK();

    private static RSAKey generateKeys() {
        try {
            return new RSAKeyGenerator(2048)
                    .keyID("test_key")
                    .generate();
        } catch (JOSEException e) {
            throw new RuntimeException("Error generating RSA256 keys", e);
        }
    }

    public static JWSObject sign(JWSObject jws) throws JOSEException {
        JWSSigner signer = new RSASSASigner(JWK);
        jws.sign(signer);
        return jws;
    }

    public static String publicKeyModulus() {
        return PUBLIC.getModulus().toString();
    }

    public static String publicKeyExponent() {
        return PUBLIC.getPublicExponent().toString();
    }

    private Rsa256Helper() {}
}
