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

import io.jmix.core.JmixOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import java.util.Collections;
import java.util.Optional;

import static io.jmix.security.SecurityConfigurers.apiSecurity;

/**
 * Security configuration for provided API endpoints.
 * Requests to the authenticated URIs should have `Authorization` header containing JWT token issued by Cognito.
 */
@Order(JmixOrder.HIGHEST_PRECEDENCE + 100)
public abstract class CognitoResourceServerConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private CognitoGroupsMapper cognitoGroupsMapper;

    @Autowired
    private CognitoProperties cognitoProperties;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.apply(apiSecurity()).and()
                .oauth2ResourceServer()
                .jwt()
                .decoder(cognitoJwtDecoder())
                .jwtAuthenticationConverter(cognitoJwtAuthenticationConverter());
    }

    @Bean("awssec_JwtDecoder")
    public JwtDecoder cognitoJwtDecoder() {
        String issuerUri = cognitoProperties.getIssuerUri();
        return JwtDecoders.fromIssuerLocation(issuerUri);
    }

    @Bean("awssec_JwtAuthenticationConverter")
    public JwtAuthenticationConverter cognitoJwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt ->
                Optional.ofNullable(jwt.getClaimAsStringList("cognito:groups"))
                        .map(cognitoGroupsMapper::createAuthorities)
                        .orElse(Collections.emptyList())
        );
        return converter;
    }
}
