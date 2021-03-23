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

package awssec_beans;

import io.jmix.autoconfigure.awssecurity.CognitoSecurityAutoConfiguration;
import io.jmix.awssecurity.CognitoResourceServerConfiguration;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.support.TestPropertySourceUtils;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class CognitoResourceServerAutoConfigurationTest extends CognitoSecurityAutoConfigurationTestBase {

    @Test
    public void testCognitoDisabled() {
        ApplicationContextRunner contextRunner = baseContextRunner
                .withInitializer(ctx -> TestPropertySourceUtils.addInlinedPropertiesToEnvironment(ctx,
                        "jmix.awssec.apiSecurity.enabled=false",
                        "jmix.awssec.uiSecurity.enabled=false"
                ));

        contextRunner.run(ctx -> {
            Map<String, WebSecurityConfigurerAdapter> beans = ctx.getBeansOfType(WebSecurityConfigurerAdapter.class);
            assertThat(beans).hasSize(0);
        });
    }

    @Test
    public void testResourceServerDisabledWithoutAuthorizedUrls() {
        ApplicationContextRunner contextRunner = baseContextRunner
                .withInitializer(ctx -> TestPropertySourceUtils.addInlinedPropertiesToEnvironment(ctx,
                        "jmix.awssec.apiSecurity.enabled=true",
                        "jmix.awssec.uiSecurity.enabled=false"
                ));

        contextRunner.run(ctx -> {
            Map<String, WebSecurityConfigurerAdapter> beans = ctx.getBeansOfType(WebSecurityConfigurerAdapter.class);
            assertThat(beans).hasSize(0);
        });
    }

    @Test
    public void testResourceServerEnabledWithAuthorizedUrls() {
        ApplicationContextRunner contextRunner = baseContextRunner
                .withInitializer(ctx -> TestPropertySourceUtils.addInlinedPropertiesToEnvironment(ctx,
                        "jmix.awssec.apiSecurity.enabled=true",
                        "jmix.awssec.uiSecurity.enabled=false")
                )
                .withBean(TestAuthorizedUrlsProvider.class)
                .withBean("awssec_JwtDecoder", JwtDecoder.class, () -> Mockito.mock(JwtDecoder.class));

        contextRunner.run(ctx -> {
            Map<String, WebSecurityConfigurerAdapter> beans = ctx.getBeansOfType(WebSecurityConfigurerAdapter.class);
            assertThat(beans).hasSize(1);
            assertThat(beans.values().iterator().next())
                    .isInstanceOf(CognitoResourceServerConfiguration.class)
                    .isInstanceOf(CognitoSecurityAutoConfiguration.DefaultCognitoResourceServerConfiguration.class);
        });
    }

    @Test
    public void testResourceServerEnabledWithoutProperty() {
        ApplicationContextRunner contextRunner = baseContextRunner
                .withInitializer(ctx -> TestPropertySourceUtils.addInlinedPropertiesToEnvironment(ctx,
                        "jmix.awssec.uiSecurity.enabled=false")
                )
                .withBean(TestAuthorizedUrlsProvider.class)
                .withBean("awssec_JwtDecoder", JwtDecoder.class, () -> Mockito.mock(JwtDecoder.class));

        contextRunner.run(ctx -> {
            Map<String, WebSecurityConfigurerAdapter> beans = ctx.getBeansOfType(WebSecurityConfigurerAdapter.class);
            assertThat(beans).hasSize(1);
            assertThat(beans.values().iterator().next())
                    .isInstanceOf(CognitoResourceServerConfiguration.class)
                    .isInstanceOf(CognitoSecurityAutoConfiguration.DefaultCognitoResourceServerConfiguration.class);
        });
    }

    @Test
    public void testDefaultResourceServerConfigurationNotApplied() {
        ApplicationContextRunner contextRunner = baseContextRunner
                .withInitializer(ctx -> TestPropertySourceUtils.addInlinedPropertiesToEnvironment(ctx,
                        "jmix.awssec.apiSecurity.enabled=true",
                        "jmix.awssec.uiSecurity=false")
                )
                .withBean(TestAuthorizedUrlsProvider.class)
                .withBean("awssec_JwtDecoder", JwtDecoder.class, () -> Mockito.mock(JwtDecoder.class))
                .withUserConfiguration(CustomTestResourceServerConfiguration.class);

        contextRunner.run(ctx -> {
            Map<String, WebSecurityConfigurerAdapter> beans = ctx.getBeansOfType(WebSecurityConfigurerAdapter.class);
            assertThat(beans).hasSize(1);
            assertThat(beans.values().iterator().next())
                    .isInstanceOf(CognitoResourceServerConfiguration.class)
                    .isInstanceOf(CustomTestResourceServerConfiguration.class)
                    .isNotInstanceOf(CognitoSecurityAutoConfiguration.DefaultCognitoResourceServerConfiguration.class);
        });
    }
}
