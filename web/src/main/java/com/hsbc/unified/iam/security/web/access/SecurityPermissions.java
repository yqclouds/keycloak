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
package com.hsbc.unified.iam.security.web.access;

import com.hsbc.unified.iam.security.core.Group;
import com.hsbc.unified.iam.security.core.Permission;
import com.hsbc.unified.iam.security.core.Role;
import com.hsbc.unified.iam.security.core.User;
import com.hsbc.unified.iam.security.core.audit.SecurityAudit;

/**
 * Permission constants for {@link User}, {@link Group},
 * {@link Role}.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public abstract class SecurityPermissions {
    /**
     * READ permission expression for {@link User}.
     */
    public static final String USER_READ = "hasPermission('/security/user', 'MenuItem', 'READ')";

    /**
     * WRITE permission expression for {@link User}.
     */
    public static final String USER_WRITE = "hasPermission('/security/user', 'MenuItem', 'WRITE')";

    /**
     * CREATE permission expression for {@link User}.
     */
    public static final String USER_CREATE = "hasPermission('/security/user', 'MenuItem', 'CREATE')";

    /**
     * DELETE permission expression for {@link User}.
     */
    public static final String USER_DELETE = "hasPermission('/security/user', 'MenuItem', 'DELETE')";

    /**
     * ADMINISTRATION permission expression for {@link User}.
     */
    public static final String USER_ADMINISTRATION = "hasPermission('/security/user', 'MenuItem', 'ADMINISTRATION')";

    /**
     * READ permission expression for {@link Group}.
     */
    public static final String GROUP_READ = "hasPermission('/security/group', 'MenuItem', 'READ')";

    /**
     * WRITE permission expression for {@link Group}.
     */
    public static final String GROUP_WRITE = "hasPermission('/security/group', 'MenuItem', 'WRITE')";

    /**
     * CREATE permission expression for {@link Group}.
     */
    public static final String GROUP_CREATE = "hasPermission('/security/group', 'MenuItem', 'CREATE')";

    /**
     * DELETE permission expression for {@link Group}.
     */
    public static final String GROUP_DELETE = "hasPermission('/security/group', 'MenuItem', 'DELETE')";

    /**
     * ADMINISTRATION permission expression for {@link Group}.
     */
    public static final String GROUP_ADMINISTRATION = "hasPermission('/security/group', 'MenuItem', 'ADMINISTRATION')";

    /**
     * READ permission expression for {@link Role}.
     */
    public static final String ROLE_READ = "hasPermission('/security/role', 'MenuItem', 'READ')";

    /**
     * WRITE permission expression for {@link Role}.
     */
    public static final String ROLE_WRITE = "hasPermission('/security/role', 'MenuItem', 'WRITE')";

    /**
     * CREATE permission expression for {@link Role}.
     */
    public static final String ROLE_CREATE = "hasPermission('/security/role', 'MenuItem', 'CREATE')";

    /**
     * DELETE permission expression for {@link Role}.
     */
    public static final String ROLE_DELETE = "hasPermission('/security/role', 'MenuItem', 'DELETE')";

    /**
     * ADMINISTRATION permission expression for {@link Role}.
     */
    public static final String ROLE_ADMINISTRATION = "hasPermission('/security/role', 'MenuItem', 'ADMINISTRATION')";

    /**
     * READ permission expression for {@link Permission}.
     */
    public static final String PERMISSION_READ = "hasPermission('/security/permission', 'MenuItem', 'READ')";

    /**
     * READ permission expression for {@link SecurityAudit}.
     */
    public static final String AUDIT_READ = "hasPermission('/security/audit', 'MenuItem', 'READ')";

    /**
     * READ permission expression for {@link SecurityAudit}.
     */
    public static final String LOGIN_HISTORY_READ = "hasPermission('/security/history', 'MenuItem', 'READ')";

    /**
     * READ permission expression for {@link org.springframework.security.core.session.SessionInformation}.
     */
    public static final String SESSION_READ = "hasPermission('/security/session', 'MenuItem', 'READ')";

    /**
     * DELETE permission expression for {@link org.springframework.security.core.session.SessionInformation}.
     */
    public static final String SESSION_DELETE = "hasPermission('/security/session', 'MenuItem', 'DELETE')";
}
