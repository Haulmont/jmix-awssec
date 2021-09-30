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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import org.apache.commons.io.FileUtils;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.Parameter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

@Configuration
public class MockServerConfiguration {

    @Value("${jmix.awssecurity.test.mock-server-port}")
    private int port;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private final Map<String, String> nonces = new HashMap<>();

    @Bean
    public ClientAndServer mockServer() throws Exception {
        ClientAndServer mockServer = ClientAndServer.startClientAndServer(port);
        mockServer.when(request()
                .withMethod("GET")
                .withPath("/test_user_pool/.well-known/openid-configuration")
        ).respond(response(openidConfigurationBody())
                .withHeader("Content-Type", "application/json")
        );
        mockServer.when(request()
                .withMethod("GET")
                .withPath("/test_user_pool/.well-known/jwks.json")
        ).respond(response(jwksBody())
                .withHeader("Content-Type", "application/json")
        );
        mockServer.when(request()
                .withMethod("GET")
                .withPath("/hosted_ui/oauth2/authorize")
                .withQueryStringParameter("response_type", "code")
        ).callback(httpRequest -> {
            List<Parameter> parameters = httpRequest.getQueryStringParameters();
            String state = "", nonce = "", redirectUri = "";
            for (Parameter param : parameters) {
                if (param.getName().getValue().equals("state")) {
                    state = param.getValues().get(0).getValue();
                    try {
                        state = URLDecoder.decode(state, "utf-8");
                    } catch (UnsupportedEncodingException e) {
                        return response().withStatusCode(500);
                    }
                }
                if (param.getName().getValue().equals("nonce")) {
                    nonce = param.getValues().get(0).getValue();
                }
                if (param.getName().getValue().equals("redirect_uri")) {
                    redirectUri = param.getValues().get(0).getValue();
                }
            }
            String code = UUID.randomUUID().toString();
            nonces.put(code, nonce);
            return response().withStatusCode(302)
                    .withHeader("Location", redirectUri +
                            "?code=" + code +
                            "&state=" + state);
        });
        mockServer.when(request()
                .withMethod("POST")
                .withPath("/hosted_ui/oauth2/token")
                .withHeader("Authorization", "Basic dGVzdF9jbGllbnQ6")
        ).callback(httpRequest -> {
            try {
                Map<String, String> bodyParams = Arrays.stream(httpRequest.getBodyAsString().split("&"))
                        .map(entry -> entry.split("="))
                        .collect(Collectors.toMap(
                                val -> val[0],
                                val -> val[1]
                        ));
                String code = bodyParams.get("code");
                if (code == null) {
                    return response().withStatusCode(400);
                }
                String nonce = nonces.remove(code);
                if (nonce == null) {
                    return response().withStatusCode(500);
                }
                LocalDateTime now = LocalDateTime.now();
                String issuer = "http://localhost:" + port + "/test_user_pool";
                String body = objectMapper.writeValueAsString(ImmutableMap.of(
                        "access_token", JwtHelper.accessToken(issuer, now),
                        "id_token", JwtHelper.idToken(issuer, now, nonce),
                        "expires_in", 3600,
                        "token_type", "Bearer"
                ));
                return response(body).withHeader("Content-Type", "application/json");
            } catch (Exception e) {
                return response().withStatusCode(500);
            }
        });
        return mockServer;
    }

    private String readResource(String path, Map<String, Object> replacements) throws Exception {
        Resource templateResource = new ClassPathResource(path);
        File templateFile = templateResource.getFile();
        String text = FileUtils.readFileToString(templateFile, StandardCharsets.UTF_8);
        for (Map.Entry<String, Object> replacement : replacements.entrySet()) {
            String regex = Pattern.quote(replacement.getKey());
            text = text.replaceAll(regex, String.valueOf(replacement.getValue()));
        }
        return text;
    }

    private String openidConfigurationBody() throws Exception {
        return readResource("mock_server/openid-configuration.json",
                ImmutableMap.of("{port}", this.port));
    }

    private String jwksBody() throws Exception {
        return readResource("mock_server/jwks.json", ImmutableMap.of(
                "{exponent}", Rsa256Helper.publicKeyExponent(),
                "{modulus}", Rsa256Helper.publicKeyModulus()
        ));
    }
}
