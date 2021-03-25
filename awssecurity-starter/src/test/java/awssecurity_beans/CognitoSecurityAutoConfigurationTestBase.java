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
import io.jmix.autoconfigure.core.CoreAutoConfiguration;
import io.jmix.awssecurity.CognitoResourceServerConfiguration;
import io.jmix.awssecurity.CognitoStandardSecurityConfiguration;
import io.jmix.core.security.AuthorizedUrlsProvider;
import io.jmix.core.security.InMemoryUserRepository;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.cache.CacheAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.lang.NonNull;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import java.util.Collection;
import java.util.Collections;

public abstract class CognitoSecurityAutoConfigurationTestBase {

    protected final ApplicationContextRunner baseContextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(CacheAutoConfiguration.class,
                    CoreAutoConfiguration.class,
                    SecurityAutoConfiguration.class,
                    CognitoSecurityAutoConfiguration.class))
            .withBean(InMemoryUserRepository.class)
            .withAllowBeanDefinitionOverriding(true);

    public static class TestAuthorizedUrlsProvider implements AuthorizedUrlsProvider {

        @Override
        @NonNull
        public Collection<String> getAuthenticatedUrlPatterns() {
            return Collections.singletonList("/rest/**");
        }

        @Override
        @NonNull
        public Collection<String> getAnonymousUrlPatterns() {
            return Collections.emptyList();
        }
    }

    @EnableWebSecurity
    public static class CustomTestResourceServerConfiguration extends CognitoResourceServerConfiguration {

    }

    @EnableWebSecurity
    public static class CustomTestStandardSecurityConfiguration extends CognitoStandardSecurityConfiguration {

    }
}
