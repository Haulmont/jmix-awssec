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

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.HashMap;
import java.util.Map;

@ConfigurationProperties("jmix.awssec")
@ConstructorBinding
public class CognitoProperties {

    private final String region;
    private final String userPoolId;
    private final String issuerUri;
    private final String clientId;
    private final String clientSecret;
    private final String domain;

    public CognitoProperties(
            String region,
            String userPoolId,
            @DefaultValue("https://cognito-idp.{region}.amazonaws.com/{userPoolId}") String issuer,
            String clientId,
            @DefaultValue("") String clientSecret,
            String domain) {
        this.region = region;
        this.userPoolId = userPoolId;
        UriComponents uriComponents = UriComponentsBuilder.fromUriString(issuer).build();
        Map<String, String> issuerPathReplacements = new HashMap<>();
        issuerPathReplacements.put("region", region);
        issuerPathReplacements.put("userPoolId", userPoolId);
        uriComponents = uriComponents.expand(issuerPathReplacements);
        this.issuerUri = uriComponents.toUriString();
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.domain = domain;
    }

    /**
     * AWS Region.
     */
    public String getRegion() {
        return region;
    }

    /**
     * Identifier of Amazon Cognito User Pool.
     */
    public String getUserPoolId() {
        return userPoolId;
    }

    /**
     * Cognito authorization server issuer URI
     */
    public String getIssuerUri() {
        return issuerUri;
    }

    /**
     * Unique ID of app client registered in Cognito.
     */
    public String getClientId() {
        return clientId;
    }

    /**
     * Secret of app client registered in Cognito.
     */
    public String getClientSecret() {
        return clientSecret;
    }

    /**
     * Domain name used for the sign-up and sign-in pages that are hosted by Cognito.
     */
    public String getDomain() {
        return domain;
    }
}
