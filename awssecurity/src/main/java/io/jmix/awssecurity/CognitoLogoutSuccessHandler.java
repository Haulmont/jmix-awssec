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

package io.jmix.awssecurity;

import io.jmix.core.annotation.Internal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.nio.charset.StandardCharsets;

/**
 * Support for Cognito LOGOUT Endpoint for Backoffice UI
 * @see <a href="https://docs.aws.amazon.com/cognito/latest/developerguide/logout-endpoint.html">LOGOUT Endpoint</a>
 */
@Internal
@Component("awssec_CognitoLogoutSuccessHandler")
public class CognitoLogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {

    private static final String LOGOUT_ENDPOINT = "/logout";

    private final CognitoProperties cognitoProperties;

    @Autowired
    public CognitoLogoutSuccessHandler(CognitoProperties cognitoProperties) {
        this.cognitoProperties = cognitoProperties;
    }

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) {
        UriComponents baseUrl = UriComponentsBuilder
                .fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
                .replacePath(request.getContextPath())
                .replaceQuery(null)
                .fragment(null)
                .build();

        return UriComponentsBuilder
                .fromUri(URI.create(cognitoProperties.getDomain() + LOGOUT_ENDPOINT))
                .queryParam("client_id", cognitoProperties.getClientId())
                .queryParam("logout_uri", baseUrl)
                .encode(StandardCharsets.UTF_8)
                .build()
                .toUriString();
    }
}
