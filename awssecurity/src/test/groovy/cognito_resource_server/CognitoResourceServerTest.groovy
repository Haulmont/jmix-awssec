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

package cognito_resource_server


import org.apache.http.client.methods.CloseableHttpResponse
import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.impl.client.HttpClients
import org.apache.http.util.EntityUtils
import org.springframework.test.context.ContextConfiguration
import test_support.CognitoWebSpecification
import test_support.TestCognitoResourceServerConfiguration
import test_support.cognito_mock.JwtHelper

import java.time.LocalDateTime

@ContextConfiguration(
        classes = [TestCognitoResourceServerConfiguration]
)
class CognitoResourceServerTest extends CognitoWebSpecification {

    def "test authorized endpoint without token"() {
        given: "authorized endpoint"
        CloseableHttpClient httpClient = HttpClients.createDefault()
        HttpGet httpGet = new HttpGet("http://localhost:${port}/authorized/test")

        when: "execute HTTP request"
        CloseableHttpResponse response = httpClient.execute(httpGet)

        then: "receive 401 response"
        response.statusLine.statusCode == 401
        response.containsHeader("WWW-Authenticate")
    }

    def "test authorized endpoint with invalid token"() {
        given: "authorized endpoint"
        CloseableHttpClient httpClient = HttpClients.createDefault()
        HttpGet httpGet = new HttpGet("http://localhost:${port}/authorized/test")

        and: "invalid jwt token"
        httpGet.addHeader("Authorization", "Bearer invalid")

        when: "execute HTTP request"
        CloseableHttpResponse response = httpClient.execute(httpGet)

        then: "receive 401 response"
        response.statusLine.statusCode == 401
        response.containsHeader("WWW-Authenticate")
    }

    def "test authorized endpoint with valid token"() {
        given: "authorized endpoint"
        CloseableHttpClient httpClient = HttpClients.createDefault()
        HttpGet httpGet = new HttpGet("http://localhost:${port}/authorized/test")

        and: "valid jwt token"
        String token = JwtHelper.accessToken("http://localhost:${mockServer.port}/test_user_pool")
        httpGet.addHeader("Authorization", "Bearer $token")

        when: "execute HTTP request"
        CloseableHttpResponse response = httpClient.execute(httpGet)

        then: "receive 200 response"
        response.statusLine.statusCode == 200
        !response.containsHeader("WWW-Authenticate")
        EntityUtils.toString(response.entity) == "authorized"
    }

    def "test authorized endpoint with expired token"() {
        given: "authorized endpoint"
        CloseableHttpClient httpClient = HttpClients.createDefault()
        HttpGet httpGet = new HttpGet("http://localhost:${port}/authorized/test")

        and: "expired jwt token"
        LocalDateTime issued = LocalDateTime.now().minusHours(2)
        String token = JwtHelper.accessToken("http://localhost:${mockServer.port}/test_user_pool", issued)
        httpGet.addHeader("Authorization", "Bearer $token")

        when: "execute HTTP request"
        CloseableHttpResponse response = httpClient.execute(httpGet)

        then: "receive 401 response"
        response.statusLine.statusCode == 401
        response.containsHeader("WWW-Authenticate")
    }

    def "test authorized endpoint with token having wrong issuer"() {
        given: "authorized endpoint"
        CloseableHttpClient httpClient = HttpClients.createDefault()
        HttpGet httpGet = new HttpGet("http://localhost:${port}/authorized/test")

        and: "jwt token with wrong issuer"
        String token = JwtHelper.accessToken("http://wrong-issuer:${mockServer.port}/test_user_pool")
        httpGet.addHeader("Authorization", "Bearer $token")

        when: "execute HTTP request"
        CloseableHttpResponse response = httpClient.execute(httpGet)

        then: "receive 401 response"
        response.statusLine.statusCode == 401
        response.containsHeader("WWW-Authenticate")
    }

    def "test anonymous endpoint without token"() {
        given: "anonymous endpoint"
        CloseableHttpClient httpClient = HttpClients.createDefault()
        HttpGet httpGet = new HttpGet("http://localhost:${port}/anonymous/test")

        when: "execute HTTP request"
        CloseableHttpResponse response = httpClient.execute(httpGet)

        then: "receive 200 response"
        response.statusLine.statusCode == 200
        !response.containsHeader("WWW-Authenticate")
        EntityUtils.toString(response.entity) == "anonymous"
    }

    def "test anonymous endpoint with invalid token"() {
        given: "anonymous endpoint"
        CloseableHttpClient httpClient = HttpClients.createDefault()
        HttpGet httpGet = new HttpGet("http://localhost:${port}/anonymous/test")

        and: "invalid jwt token"
        httpGet.addHeader("Authorization", "Bearer invalid")

        when: "execute HTTP request"
        CloseableHttpResponse response = httpClient.execute(httpGet)

        then: "receive 401 response"
        response.statusLine.statusCode == 401
        response.containsHeader("WWW-Authenticate")
    }

    def "test anonymous endpoint with valid token"() {
        given: "anonymous endpoint"
        CloseableHttpClient httpClient = HttpClients.createDefault()
        HttpGet httpGet = new HttpGet("http://localhost:${port}/anonymous/test")

        and: "valid jwt token"
        String token = JwtHelper.accessToken("http://localhost:${mockServer.port}/test_user_pool")
        httpGet.addHeader("Authorization", "Bearer $token")

        when: "execute HTTP request"
        CloseableHttpResponse response = httpClient.execute(httpGet)

        then: "receive 200 response"
        response.statusLine.statusCode == 200
        !response.containsHeader("WWW-Authenticate")
        EntityUtils.toString(response.entity) == "anonymous"
    }
}
