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

package cognito_oauth_login

import org.apache.http.HttpResponse
import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.BasicCookieStore
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.impl.client.HttpClients
import org.apache.http.util.EntityUtils
import org.springframework.test.context.ContextConfiguration
import org.springframework.web.util.UriComponents
import org.springframework.web.util.UriComponentsBuilder
import test_support.CognitoWebSpecification
import test_support.TestCognitoStandardSecurityConfiguration

@ContextConfiguration(
        classes = [TestCognitoStandardSecurityConfiguration]
)
class CognitoOAuthLoginTest extends CognitoWebSpecification {

    def "test oauth2 login"() {
        given: "authorization request endpoint"
        CloseableHttpClient httpClient = HttpClients.custom()
                .disableRedirectHandling()
                .setDefaultCookieStore(new BasicCookieStore())
                .build()
        HttpGet loginRequest = new HttpGet("http://localhost:${port}/oauth2/authorization/cognito")

        when: "execute authorization request"
        def loginResponse = httpClient.execute(loginRequest)

        then: "redirected to Cognito hosted sign-in endpoint"
        loginResponse.statusLine.statusCode == 302
        loginResponse.containsHeader("Location")
        def locationUri = getLocationUri(loginResponse)
        locationUri.path == "/hosted_ui/oauth2/authorize"
        locationUri.queryParams["response_type"] == ["code"]
        locationUri.queryParams["client_id"] == ["test_client"]
        locationUri.queryParams["scope"] == ["openid"]
        locationUri.queryParams["state"] != null
        locationUri.queryParams["redirect_uri"] == ["http://localhost:${port}/login/oauth2/code/cognito".toString()]

        when: "follow redirect to Cognito hosted sign-in endpoint"
        HttpGet httpGet = new HttpGet(locationUri.toUri())
        def response = httpClient.execute(httpGet)

        then: "redirected to OAuth2 login endpoint by Cognito"
        response.statusLine.statusCode == 302
        getLocationUri(response).path == "/login/oauth2/code/cognito"

        when: "follow redirect to OAuth2 login endpoint"
        httpGet = new HttpGet(getLocationUri(response).toUri())
        response = httpClient.execute(httpGet)

        then: "login is a success and redirected to root page"
        response.statusLine.statusCode == 302
        getLocationUri(response).path == "/"

        when: "execute request to test username endpoint"
        httpGet = new HttpGet("http://localhost:${port}/test/username")
        response = httpClient.execute(httpGet)

        then: "receive user name in body"
        response.statusLine.statusCode == 200
        EntityUtils.toString(response.entity) == 'test_user'
    }

    static UriComponents getLocationUri(HttpResponse response) {
        def locationHeader = response.getFirstHeader("Location").getValue()
        return UriComponentsBuilder.fromUriString(locationHeader).build()
    }
}
