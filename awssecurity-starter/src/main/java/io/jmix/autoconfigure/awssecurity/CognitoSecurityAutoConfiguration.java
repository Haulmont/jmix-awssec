/*
 * Copyright 2020 Haulmont.
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

package io.jmix.autoconfigure.awssecurity;

import io.jmix.awssecurity.CognitoConfiguration;
import io.jmix.awssecurity.CognitoResourceServerConfiguration;
import io.jmix.awssecurity.CognitoStandardSecurityConfiguration;
import io.jmix.core.security.AuthorizedUrlsProvider;
import io.jmix.security.SecurityConfiguration;
import io.jmix.security.StandardSecurityConfiguration;
import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@Configuration
@Import({SecurityConfiguration.class, CognitoConfiguration.class})
public class CognitoSecurityAutoConfiguration {

    @EnableWebSecurity
    @Conditional(OnUiSecurityPropertiesCondition.class)
    @ConditionalOnMissingBean({StandardSecurityConfiguration.class, CognitoStandardSecurityConfiguration.class})
    public static class DefaultCognitoStandardSecurityConfiguration extends CognitoStandardSecurityConfiguration {

    }

    @EnableWebSecurity
    @ConditionalOnProperty(prefix = "jmix.awssecurity.apiSecurity", name = "enabled", havingValue = "true",
            matchIfMissing = true)
    @ConditionalOnBean(AuthorizedUrlsProvider.class)
    @ConditionalOnMissingBean({CognitoResourceServerConfiguration.class})
    public static class DefaultCognitoResourceServerConfiguration extends CognitoResourceServerConfiguration {

    }

    private static class OnUiSecurityPropertiesCondition extends AllNestedConditions {

        OnUiSecurityPropertiesCondition() {
            super(ConfigurationPhase.PARSE_CONFIGURATION);
        }

        @ConditionalOnProperty(prefix = "jmix.awssecurity.uiSecurity", name = "enabled", havingValue = "true")
        static class UiSecurityEnabledProperty {
        }

        @ConditionalOnProperty(prefix = "jmix.awssecurity", name = "clientId")
        static class HasClientIdProperty {
        }

        @ConditionalOnProperty(prefix = "jmix.awssecurity", name = "domain")
        static class HasDomainProperty {
        }

    }
}
