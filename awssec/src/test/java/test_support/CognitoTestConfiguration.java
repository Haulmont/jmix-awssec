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

package test_support;

import io.jmix.awssecurity.CognitoConfiguration;
import io.jmix.core.annotation.JmixModule;
import io.jmix.core.security.AuthorizedUrlsProvider;
import io.jmix.core.security.InMemoryUserRepository;
import io.jmix.core.security.UserRepository;
import org.springframework.cache.CacheManager;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.*;

@Configuration
@JmixModule(dependsOn = {CognitoConfiguration.class})
@PropertySource("classpath:/application.properties")
public class CognitoTestConfiguration {

    @Bean
    public AuthorizedUrlsProvider testAuthorizedUrlsProvider() {
        return new TestAuthorizedUrlsProvider();
    }

    @Bean
    public UserRepository userRepository() {
        return new InMemoryUserRepository();
    }

    @Bean
    public CacheManager cacheManager() {
        return new ConcurrentMapCacheManager();
    }
}
