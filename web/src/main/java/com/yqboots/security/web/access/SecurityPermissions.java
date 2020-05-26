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
package com.yqboots.security.web.access;

/**
 * Permission constants for {@link com.yqboots.security.core.User}, {@link com.yqboots.security.core.Group},
 * {@link com.yqboots.security.core.Role}.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public abstract class SecurityPermissions {
    /**
     * READ permission expression for {@link com.yqboots.security.core.User}.
     */
    public static final String USER_READ = "hasPermission('/security/user', 'com.yqboots.menu.core.MenuItem', 'READ')";

    /**
     * WRITE permission expression for {@link com.yqboots.security.core.User}.
     */
    public static final String USER_WRITE = "hasPermission('/security/user', 'com.yqboots.menu.core.MenuItem', 'WRITE')";

    /**
     * CREATE permission expression for {@link com.yqboots.security.core.User}.
     */
    public static final String USER_CREATE = "hasPermission('/security/user', 'com.yqboots.menu.core.MenuItem', 'CREATE')";

    /**
     * DELETE permission expression for {@link com.yqboots.security.core.User}.
     */
    public static final String USER_DELETE = "hasPermission('/security/user', 'com.yqboots.menu.core.MenuItem', 'DELETE')";

    /**
     * ADMINISTRATION permission expression for {@link com.yqboots.security.core.User}.
     */
    public static final String USER_ADMINISTRATION = "hasPermission('/security/user', 'com.yqboots.menu.core.MenuItem', 'ADMINISTRATION')";

    /**
     * READ permission expression for {@link com.yqboots.security.core.Group}.
     */
    public static final String GROUP_READ = "hasPermission('/security/group', 'com.yqboots.menu.core.MenuItem', 'READ')";

    /**
     * WRITE permission expression for {@link com.yqboots.security.core.Group}.
     */
    public static final String GROUP_WRITE = "hasPermission('/security/group', 'com.yqboots.menu.core.MenuItem', 'WRITE')";

    /**
     * CREATE permission expression for {@link com.yqboots.security.core.Group}.
     */
    public static final String GROUP_CREATE = "hasPermission('/security/group', 'com.yqboots.menu.core.MenuItem', 'CREATE')";

    /**
     * DELETE permission expression for {@link com.yqboots.security.core.Group}.
     */
    public static final String GROUP_DELETE = "hasPermission('/security/group', 'com.yqboots.menu.core.MenuItem', 'DELETE')";

    /**
     * ADMINISTRATION permission expression for {@link com.yqboots.security.core.Group}.
     */
    public static final String GROUP_ADMINISTRATION = "hasPermission('/security/group', 'com.yqboots.menu.core.MenuItem', 'ADMINISTRATION')";

    /**
     * READ permission expression for {@link com.yqboots.security.core.Role}.
     */
    public static final String ROLE_READ = "hasPermission('/security/role', 'com.yqboots.menu.core.MenuItem', 'READ')";

    /**
     * WRITE permission expression for {@link com.yqboots.security.core.Role}.
     */
    public static final String ROLE_WRITE = "hasPermission('/security/role', 'com.yqboots.menu.core.MenuItem', 'WRITE')";

    /**
     * CREATE permission expression for {@link com.yqboots.security.core.Role}.
     */
    public static final String ROLE_CREATE = "hasPermission('/security/role', 'com.yqboots.menu.core.MenuItem', 'CREATE')";

    /**
     * DELETE permission expression for {@link com.yqboots.security.core.Role}.
     */
    public static final String ROLE_DELETE = "hasPermission('/security/role', 'com.yqboots.menu.core.MenuItem', 'DELETE')";

    /**
     * ADMINISTRATION permission expression for {@link com.yqboots.security.core.Role}.
     */
    public static final String ROLE_ADMINISTRATION = "hasPermission('/security/role', 'com.yqboots.menu.core.MenuItem', 'ADMINISTRATION')";

    /**
     * READ permission expression for {@link com.yqboots.security.core.Permission}.
     */
    public static final String PERMISSION_READ = "hasPermission('/security/permission', 'com.yqboots.menu.core.MenuItem', 'READ')";

    /**
     * READ permission expression for {@link com.yqboots.security.core.audit.SecurityAudit}.
     */
    public static final String AUDIT_READ = "hasPermission('/security/audit', 'com.yqboots.menu.core.MenuItem', 'READ')";

    /**
     * READ permission expression for {@link com.yqboots.security.core.audit.SecurityAudit}.
     */
    public static final String LOGIN_HISTORY_READ = "hasPermission('/security/history', 'com.yqboots.menu.core.MenuItem', 'READ')";

    /**
     * READ permission expression for {@link org.springframework.security.core.session.SessionInformation}.
     */
    public static final String SESSION_READ = "hasPermission('/security/session', 'com.yqboots.menu.core.MenuItem', 'READ')";

    /**
     * DELETE permission expression for {@link org.springframework.security.core.session.SessionInformation}.
     */
    public static final String SESSION_DELETE = "hasPermission('/security/session', 'com.yqboots.menu.core.MenuItem', 'DELETE')";
}
