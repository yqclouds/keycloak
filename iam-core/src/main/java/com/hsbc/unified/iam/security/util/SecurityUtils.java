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
package com.hsbc.unified.iam.security.util;

import com.hsbc.unified.iam.security.core.Role;
import com.hsbc.unified.iam.security.core.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Utility methods for security.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public final class SecurityUtils {
    /**
     * Gets current signed in user.
     *
     * @return the user who had bean signed in, null if not found
     */
    public static Optional<User> getCurrentUser() {
        User result = null;

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            if (authentication.getPrincipal() instanceof org.springframework.security.core.userdetails.User) {
                org.springframework.security.core.userdetails.User _user = (org.springframework.security.core.userdetails.User) authentication.getPrincipal();
                Set<Role> roles = _user.getAuthorities().stream().map(auth -> new Role(auth.getAuthority())).collect(Collectors.toSet());
                result = new User(_user.getUsername(), _user.getPassword(), roles);
            } else {
                result = (User) authentication.getPrincipal();
            }
        }

        assert result != null;
        return Optional.of(result);
    }

    /**
     * Constructs the SecurityUtils.
     */
    private SecurityUtils() {
    }
}
