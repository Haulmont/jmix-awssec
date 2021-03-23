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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;

@Configuration
public class CognitoClientRegistrationConfiguration {

    @Autowired
    private CognitoProperties properties;

    @Bean("awssec_ClientRegistrationRepository")
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(cognitoClientRegistration());
    }

    public ClientRegistration cognitoClientRegistration() {
        return ClientRegistrations.fromIssuerLocation(properties.getIssuerUri())
                .registrationId("cognito")
                .clientId(properties.getClientId())
                .clientSecret(properties.getClientSecret())
                .scope("openid")
                .userNameAttributeName("cognito:username")
                .build();
    }
}
