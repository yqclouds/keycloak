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
package com.hsbc.unified.iam.security.core.audit;

import com.hsbc.unified.iam.security.core.*;
import com.hsbc.unified.iam.security.core.audit.interceptor.AuditAttribute;
import com.hsbc.unified.iam.security.core.audit.interceptor.AuditAttributeSource;
import com.hsbc.unified.iam.security.core.audit.repository.SecurityAuditRepository;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.lang.reflect.Method;

/**
 * {@link AuditProvider} implementation for security entities.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
@Service
public class SecurityAuditProvider extends AuditProviderSupport {
    /**
     * The LOGGER.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityAuditProvider.class);

    /**
     * The audit provider delegates the execution to a list of AuditProvider.
     */
    private final AuditProvider[] delegates = new AuditProvider[]{new UserAuditProvider(), new GroupAuditProvider(), new RoleAuditProvider()};

    /**
     * auditAttributeSource
     */
    @Autowired
    private AuditAttributeSource auditAttributeSource;

    /**
     * securityAuditRepository
     */
    @Autowired
    private SecurityAuditRepository securityAuditRepository;

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean supports(Class<?> clazz) {
        for (AuditProvider delegate : delegates) {
            if (delegate.supports(clazz)) {
                return true;
            }
        }

        return false;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void afterInvocation(Method method, Object[] arguments, Object returnObj) {
        for (AuditProvider delegate : delegates) {
            if (delegate.supports(method.getDeclaringClass())) {
                delegate.afterInvocation(method, arguments, returnObj);
            }
        }
    }

    /**
     * Sets the {@link AuditAttributeSource}.
     *
     * @param auditAttributeSource auditAttributeSource
     */
    public void setAuditAttributeSource(AuditAttributeSource auditAttributeSource) {
        this.auditAttributeSource = auditAttributeSource;
    }

    /**
     * Sets the {@link SecurityAuditRepository}.
     *
     * @param securityAuditRepository securityAuditRepository
     */
    public void setSecurityAuditRepository(SecurityAuditRepository securityAuditRepository) {
        this.securityAuditRepository = securityAuditRepository;
    }

    private class UserAuditProvider extends AuditProviderSupport {
        /**
         * {@inheritDoc}
         */
        @Override
        public boolean supports(Class<?> clazz) {
            return UserManager.class.isAssignableFrom(clazz);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void afterInvocation(Method method, Object[] arguments, Object returnObj) {
            final AuditAttribute attr = auditAttributeSource.getAuditAttribute(method);

            SecurityAudit audit = new SecurityAudit(attr.getCode());

            ToStringBuilder sb = new ToStringBuilder(null, ToStringStyle.MULTI_LINE_STYLE);
            User user;
            switch (attr.getCode()) {
                case SecurityAudit.CODE_ADD_USER:
                case SecurityAudit.CODE_UPDATE_USER:
                    user = (User) arguments[0];
                    audit.setTarget(user.getUsername());
                    sb.append("enabled", user.isEnabled());
                    break;
                case SecurityAudit.CODE_UPDATE_GROUPS_OF_USER:
                case SecurityAudit.CODE_REMOVE_GROUPS_FROM_USER:
                    audit.setTarget(arguments[0].toString());
                    sb.append("groups", arguments[1]);
                    break;
                case SecurityAudit.CODE_UPDATE_ROLES_OF_USER:
                case SecurityAudit.CODE_REMOVE_ROLES_FROM_USER:
                    audit.setTarget(arguments[0].toString());
                    sb.append("roles", arguments[1]);
                    break;
                case SecurityAudit.CODE_REMOVE_USER:
                    audit.setTarget(arguments[0].toString());
                    break;
                default:
                    LOGGER.error("Invalid code for UserManager operations: " + attr.getCode());
                    break;
            }
            audit.setDescription(StringUtils.remove(sb.toString(), "<null>"));

            securityAuditRepository.save(audit);
        }
    }

    private class GroupAuditProvider extends AuditProviderSupport {
        /**
         * {@inheritDoc}
         */
        @Override
        public boolean supports(Class<?> clazz) {
            return GroupManager.class.isAssignableFrom(clazz);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void afterInvocation(Method method, Object[] arguments, Object returnObj) {
            final AuditAttribute attr = auditAttributeSource.getAuditAttribute(method);

            SecurityAudit audit = new SecurityAudit(attr.getCode());

            ToStringBuilder sb = new ToStringBuilder(null, ToStringStyle.MULTI_LINE_STYLE);
            Group group;
            switch (attr.getCode()) {
                case SecurityAudit.CODE_ADD_GROUP:
                case SecurityAudit.CODE_UPDATE_GROUP:
                    group = (Group) arguments[0];
                    audit.setTarget(group.getPath());
                    sb.append("alias", group.getAlias()).append("description", group.getDescription());
                    break;
                case SecurityAudit.CODE_UPDATE_USERS_OF_GROUP:
                case SecurityAudit.CODE_REMOVE_USERS_FROM_GROUP:
                    audit.setTarget(arguments[0].toString());
                    sb.append("users", arguments[1]);
                    break;
                case SecurityAudit.CODE_UPDATE_ROLES_OF_GROUP:
                case SecurityAudit.CODE_REMOVE_ROLES_FROM_GROUP:
                    audit.setTarget(arguments[0].toString());
                    sb.append("roles", arguments[1]);
                    break;
                case SecurityAudit.CODE_REMOVE_GROUP:
                    audit.setTarget(arguments[0].toString());
                    break;
                default:
                    LOGGER.error("Invalid code for GroupManager operations: " + attr.getCode());
                    break;
            }
            audit.setDescription(StringUtils.remove(sb.toString(), "<null>"));

            securityAuditRepository.save(audit);
        }
    }

    private class RoleAuditProvider extends AuditProviderSupport {
        /**
         * {@inheritDoc}
         */
        @Override
        public boolean supports(Class<?> clazz) {
            return RoleManager.class.isAssignableFrom(clazz);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void afterInvocation(Method method, Object[] arguments, Object returnObj) {
            final AuditAttribute attr = auditAttributeSource.getAuditAttribute(method);

            SecurityAudit audit = new SecurityAudit(attr.getCode());

            ToStringBuilder sb = new ToStringBuilder(null, ToStringStyle.MULTI_LINE_STYLE);
            Role role;
            switch (attr.getCode()) {
                case SecurityAudit.CODE_ADD_ROLE:
                case SecurityAudit.CODE_UPDATE_ROLE:
                    role = (Role) arguments[0];
                    audit.setTarget(role.getPath());
                    sb.append("alias", role.getAlias()).append("description", role.getDescription());
                    break;
                case SecurityAudit.CODE_UPDATE_USERS_OF_ROLE:
                case SecurityAudit.CODE_REMOVE_USERS_FROM_ROLE:
                    audit.setTarget(arguments[0].toString());
                    sb.append("users", arguments[1]);
                    break;
                case SecurityAudit.CODE_UPDATE_GROUPS_OF_ROLE:
                case SecurityAudit.CODE_REMOVE_GROUPS_FROM_ROLE:
                    audit.setTarget(arguments[0].toString());
                    sb.append("groups", arguments[1]);
                    break;
                case SecurityAudit.CODE_REMOVE_ROLE:
                    audit.setTarget(arguments[0].toString());
                    break;
                default:
                    LOGGER.error("Invalid code for RoleManager operations: " + attr.getCode());
                    break;
            }
            audit.setDescription(StringUtils.remove(sb.toString(), "<null>"));

            securityAuditRepository.save(audit);
        }
    }
}
