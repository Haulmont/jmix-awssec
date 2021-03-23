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

package cognito_groups_mapper

import io.jmix.awssecurity.CognitoGroupsMapper
import io.jmix.security.authentication.RoleGrantedAuthority
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.GrantedAuthority
import test_support.CognitoSpecification

class CognitoGroupsMapperTest extends CognitoSpecification {

    @Autowired
    CognitoGroupsMapper mapper

    def "resource role mapping"() {
        when:
        GrantedAuthority authority = mapper.createAuthority("resource\$test-role")

        then:
        authority instanceof RoleGrantedAuthority
        authority.authority == "test-role"
    }

    def "row level role mapping"() {
        when:
        GrantedAuthority authority = mapper.createAuthority("row_level\$test-row-level")

        then:
        authority instanceof RoleGrantedAuthority
    }
}
