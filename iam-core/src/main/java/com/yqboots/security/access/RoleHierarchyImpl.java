/*
 *
 *  * Copyright 2015-2016 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */
package com.yqboots.security.access;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * The simple implementation of {@link RoleHierarchy}.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public class RoleHierarchyImpl implements RoleHierarchy {
    /**
     * {@inheritDoc}
     */
    @Override
    public Collection<? extends GrantedAuthority> getReachableGrantedAuthorities(
            Collection<? extends GrantedAuthority> authorities) {
        Assert.notEmpty(authorities);

        final Set<GrantedAuthority> results = new HashSet<>();
        for (final GrantedAuthority role : authorities) {
            results.addAll(retrieveHierarchyRoles(role));
        }

        return results;
    }

    /**
     * Retrieves the hierarchy roles.
     *
     * @param role the granted authority
     * @return the roles from hierarchy
     */
    protected Collection<? extends GrantedAuthority> retrieveHierarchyRoles(GrantedAuthority role) {
        final Set<GrantedAuthority> results = new HashSet<>();
        // /R001/R002/R003 ...
        String roleStr = role.getAuthority();

        if (StringUtils.startsWith(roleStr, "ROLE_") && StringUtils.contains(roleStr, "/")) {
            roleStr = StringUtils.substringAfter(roleStr, "ROLE_");
        }

        while (StringUtils.isNotBlank(roleStr)) {
            results.add(new SimpleGrantedAuthority(roleStr));
            if (!StringUtils.contains(roleStr, "/")) {
                break;
            }

            roleStr = StringUtils.substringBeforeLast(roleStr, "/");
        }

        return results;
    }
}
