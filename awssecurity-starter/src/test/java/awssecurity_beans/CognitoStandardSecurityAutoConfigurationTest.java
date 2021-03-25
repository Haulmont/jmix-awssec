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

package awssecurity_beans;

import io.jmix.autoconfigure.awssecurity.CognitoSecurityAutoConfiguration;
import io.jmix.awssecurity.CognitoStandardSecurityConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.test.context.support.TestPropertySourceUtils;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class CognitoStandardSecurityAutoConfigurationTest extends CognitoSecurityAutoConfigurationTestBase {

    @Test
    public void testStandardSecurityDisabledWithoutProperty() {
        ApplicationContextRunner contextRunner = baseContextRunner
                .withInitializer(ctx -> TestPropertySourceUtils.addInlinedPropertiesToEnvironment(ctx,
                        "jmix.awssecurity.apiSecurity.enabled=false"
                ));

        contextRunner.run(ctx -> {
            Map<String, WebSecurityConfigurerAdapter> beans = ctx.getBeansOfType(WebSecurityConfigurerAdapter.class);
            assertThat(beans).hasSize(0);
        });
    }

    @Test
    public void testStandardSecurityDisabledWithoutClientIdAndDomain() {
        ApplicationContextRunner contextRunner = baseContextRunner
                .withInitializer(ctx -> TestPropertySourceUtils.addInlinedPropertiesToEnvironment(ctx,
                        "jmix.awssecurity.apiSecurity.enabled=false",
                        "jmix.awssecurity.uiSecurity.enabled=true"
                ));

        contextRunner.run(ctx -> {
            Map<String, WebSecurityConfigurerAdapter> beans = ctx.getBeansOfType(WebSecurityConfigurerAdapter.class);
            assertThat(beans).hasSize(0);
        });
    }

    @Test
    public void testStandardSecurityDisabledWithoutDomain() {
        ApplicationContextRunner contextRunner = baseContextRunner
                .withInitializer(ctx -> TestPropertySourceUtils.addInlinedPropertiesToEnvironment(ctx,
                        "jmix.awssecurity.apiSecurity.enabled=false",
                        "jmix.awssecurity.uiSecurity.enabled=true",
                        "jmix.awssecurity.clientId=test_client"
                ));

        contextRunner.run(ctx -> {
            Map<String, WebSecurityConfigurerAdapter> beans = ctx.getBeansOfType(WebSecurityConfigurerAdapter.class);
            assertThat(beans).hasSize(0);
        });
    }

    @Test
    public void testStandardSecurityDisabledWithoutClientId() {
        ApplicationContextRunner contextRunner = baseContextRunner
                .withInitializer(ctx -> TestPropertySourceUtils.addInlinedPropertiesToEnvironment(ctx,
                        "jmix.awssecurity.apiSecurity.enabled=false",
                        "jmix.awssecurity.uiSecurity.enabled=true",
                        "jmix.awssecurity.domain=https://domain.test.com"
                ));

        contextRunner.run(ctx -> {
            Map<String, WebSecurityConfigurerAdapter> beans = ctx.getBeansOfType(WebSecurityConfigurerAdapter.class);
            assertThat(beans).hasSize(0);
        });
    }

    @Test
    public void testStandardSecurityEnabledWithClientIdAndDomain() {
        ApplicationContextRunner contextRunner = baseContextRunner
                .withInitializer(ctx -> TestPropertySourceUtils.addInlinedPropertiesToEnvironment(ctx,
                        "jmix.awssecurity.apiSecurity.enabled=false",
                        "jmix.awssecurity.uiSecurity.enabled=true",
                        "jmix.awssecurity.clientId=test_client",
                        "jmix.awssecurity.domain=https://domain.test.com"
                ))
                .withBean("awssec_ClientRegistrationRepository", ClientRegistrationRepository.class,
                        this::testClientRegistrationRepository);

        contextRunner.run(ctx -> {
            Map<String, WebSecurityConfigurerAdapter> beans = ctx.getBeansOfType(WebSecurityConfigurerAdapter.class);
            assertThat(beans).hasSize(1);
            assertThat(beans.values().iterator().next())
                    .isInstanceOf(CognitoStandardSecurityConfiguration.class)
                    .isInstanceOf(CognitoSecurityAutoConfiguration.DefaultCognitoStandardSecurityConfiguration.class);
        });
    }

    @Test
    public void testStandardSecurityNotApplied() {
        ApplicationContextRunner contextRunner = baseContextRunner
                .withInitializer(ctx -> TestPropertySourceUtils.addInlinedPropertiesToEnvironment(ctx,
                        "jmix.awssecurity.apiSecurity.enabled=false",
                        "jmix.awssecurity.uiSecurity.enabled=true",
                        "jmix.awssecurity.clientId=test_client",
                        "jmix.awssecurity.domain=https://domain.test.com"
                ))
                .withBean("awssec_ClientRegistrationRepository", ClientRegistrationRepository.class,
                        this::testClientRegistrationRepository)
                .withUserConfiguration(CustomTestStandardSecurityConfiguration.class);

        contextRunner.run(ctx -> {
            Map<String, WebSecurityConfigurerAdapter> beans = ctx.getBeansOfType(WebSecurityConfigurerAdapter.class);
            assertThat(beans).hasSize(1);
            assertThat(beans.values().iterator().next())
                    .isInstanceOf(CognitoStandardSecurityConfiguration.class)
                    .isInstanceOf(CustomTestStandardSecurityConfiguration.class)
                    .isNotInstanceOf(CognitoSecurityAutoConfiguration.DefaultCognitoStandardSecurityConfiguration.class);
        });
    }

    private ClientRegistrationRepository testClientRegistrationRepository() {
        ClientRegistration clientRegistration = ClientRegistration
                .withRegistrationId("cognito")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .clientId("test_client")
                .redirectUri("{baseUrl}/redirect")
                .authorizationUri("https://domain.test.com/login/oauth/authorize")
                .tokenUri("https://domain.test.com/login/oauth/token")
                .build();
        return new InMemoryClientRegistrationRepository(clientRegistration);
    }
}
