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

import io.jmix.core.annotation.Internal;
import io.jmix.security.authentication.RoleGrantedAuthority;
import io.jmix.security.model.ResourceRole;
import io.jmix.security.model.RowLevelRole;
import io.jmix.security.role.ResourceRoleRepository;
import io.jmix.security.role.RowLevelRoleRepository;
import io.jmix.security.role.assignment.RoleAssignmentRoleType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.annotation.Nullable;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Maps list of Cognito user groups names to {@link GrantedAuthority} objects.
 * Group is treated as resource or row-level role based on prefix:
 * <ul>
 *     <li><i>resource$</i> for resource roles;</li>
 *     <li><i>row_level$</i> for row-level roles.</li>
 * </ul>
 */
@Internal
@Component("awssec_CognitoGroupsMapper")
public class CognitoGroupsMapper {

    @Autowired
    private ResourceRoleRepository resourceRoleRepository;

    @Autowired
    private RowLevelRoleRepository rowLevelRoleRepository;

    @Nullable
    public GrantedAuthority createAuthority(String group) {
        int separator = group.indexOf('$');
        if (separator >= 0) {
            String roleType = group.substring(0, separator);
            String roleCode = group.substring(separator + 1);
            if (RoleAssignmentRoleType.RESOURCE.equals(roleType)) {
                ResourceRole role = resourceRoleRepository.findRoleByCode(roleCode);
                if (role != null) {
                    return RoleGrantedAuthority.ofResourceRole(role);
                }
            } else if (RoleAssignmentRoleType.ROW_LEVEL.equals(roleType)) {
                RowLevelRole role = rowLevelRoleRepository.findRoleByCode(roleCode);
                if (role != null) {
                    return RoleGrantedAuthority.ofRowLevelRole(role);
                }
            }
        }
        return null;
    }

    public List<GrantedAuthority> createAuthorities(Collection<String> groups) {
        return groups.stream()
                .map(this::createAuthority)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }
}
