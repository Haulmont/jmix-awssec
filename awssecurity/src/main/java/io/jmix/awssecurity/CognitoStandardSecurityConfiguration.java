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

import io.jmix.awssecurity.user.OAuth2UserDetails;
import io.jmix.awssecurity.user.OidcUserDetails;
import io.jmix.security.StandardSecurityConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Security configuration for Backoffice UI. Setups OAuth2 login configuration with Cognito as authorization server.
 * Exposes endpoint <pre>/oauth2/authorization/cognito</pre> that can be used to access Cognito hosted sign-up and sign-in pages.
 */
@Import(CognitoClientRegistrationConfiguration.class)
public abstract class CognitoStandardSecurityConfiguration extends StandardSecurityConfiguration {

    @Autowired
    private CognitoGroupsMapper cognitoGroupsMapper;

    @Autowired
    private CognitoLogoutSuccessHandler cognitoLogoutSuccessHandler;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        super.configure(http);
        http.oauth2Login()
                .userInfoEndpoint()
                .userService(oauth2UserService())
                .oidcUserService(oidcUserService())
                .and()
                .and()
                .logout()
                .logoutSuccessHandler(cognitoLogoutSuccessHandler);
    }

    private OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
        DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
        return userRequest -> {
            OAuth2User user = delegate.loadUser(userRequest);
            return new OAuth2UserDetails<>(user, getUserAuthorities(user));
        };
    }

    private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        OidcUserService delegate = new OidcUserService();
        return userRequest -> {
            OidcUser user = delegate.loadUser(userRequest);
            return new OidcUserDetails(user, getUserAuthorities(user));
        };
    }

    private Collection<? extends GrantedAuthority> getUserAuthorities(OAuth2User user) throws OAuth2AuthenticationException {
        List<String> groups = user.getAttribute("cognito:groups");
        if (groups != null && !groups.isEmpty()) {
            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.addAll(user.getAuthorities());
            authorities.addAll(cognitoGroupsMapper.createAuthorities(groups));
            return authorities;
        } else {
            return user.getAuthorities();
        }
    }
}
