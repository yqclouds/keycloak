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
package com.yqboots.security.autoconfigure;

import com.yqboots.security.access.RoleHierarchyImpl;
import com.yqboots.security.access.support.DelegatingObjectIdentityRetrievalStrategy;
import com.yqboots.security.access.support.ObjectIdentityRetrieval;
import com.yqboots.security.authentication.UserDetailsServiceImpl;
import com.yqboots.security.core.repository.GroupRepository;
import com.yqboots.security.core.repository.RoleRepository;
import com.yqboots.security.core.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyAuthoritiesMapper;
import org.springframework.security.acls.AclPermissionEvaluator;
import org.springframework.security.acls.domain.*;
import org.springframework.security.acls.jdbc.BasicLookupStrategy;
import org.springframework.security.acls.jdbc.JdbcAclService;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.*;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetailsService;

import javax.sql.DataSource;
import java.util.List;

/**
 * The Auto Configuration class for Security related beans.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
@Configuration
@EnableConfigurationProperties({SecurityProperties.class})
public class SecurityAutoConfiguration {
    @Autowired
    private SecurityProperties properties;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private GroupRepository groupRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Bean
    public RoleHierarchy roleHierarchy() {
        return new RoleHierarchyImpl();
    }

    @Bean
    public GrantedAuthoritiesMapper grantedAuthoritiesMapper() {
        return new RoleHierarchyAuthoritiesMapper(roleHierarchy());
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetailsServiceImpl bean = new UserDetailsServiceImpl();
        bean.setUserRepository(userRepository);
        bean.setGroupRepository(groupRepository);
        bean.setRoleRepository(roleRepository);
        bean.setEnableAuthorities(properties.getUser().isEnableAuthorities());
        bean.setEnableGroups(properties.getUser().isEnableGroups());

        return bean;
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider bean = new DaoAuthenticationProvider();
        bean.setUserDetailsService(userDetailsService());
        bean.setAuthoritiesMapper(grantedAuthoritiesMapper());
        // TODO: set SaltSource and PasswordEncoder
        // bean.setSaltSource();
        // bean.setPasswordEncoder(new PlaintextPasswordEncoder());

        return bean;
    }

    @Configuration
    protected static class AclSecurityConfiguration {
        public static final String ACL_CACHE_NAME = "acls";

        @Autowired
        private DataSource dataSource;

        @Autowired
        private RoleHierarchy roleHierarchy;

        @Autowired(required = false)
        private List<ObjectIdentityRetrieval> objectIdentityRetrievals;

        @Bean
        public PermissionEvaluator permissionEvaluator() {
            AclPermissionEvaluator bean = new AclPermissionEvaluator(aclService());
            bean.setObjectIdentityRetrievalStrategy(aclObjectIdentityRetrievalStrategy());
            bean.setObjectIdentityGenerator(aclObjectIdentityGenerator());
            bean.setSidRetrievalStrategy(aclSidRetrievalStrategy());
            return bean;
        }

        @Bean
        public AclService aclService() {
            return new JdbcAclService(dataSource, aclLookupStrategy());
        }

        @Bean
        public LookupStrategy aclLookupStrategy() {
            return new BasicLookupStrategy(dataSource, aclCache(), aclAuthorizationStrategy(),
                    aclPermissionGrantingStrategy());
        }

        @Bean
        public AclCache aclCache() {
            return new SpringCacheBasedAclCache(new ConcurrentMapCache(ACL_CACHE_NAME), aclPermissionGrantingStrategy(),
                    aclAuthorizationStrategy());
        }

        @Bean
        public PermissionGrantingStrategy aclPermissionGrantingStrategy() {
            return new DefaultPermissionGrantingStrategy(new ConsoleAuditLogger());
        }

        @Bean
        public AclAuthorizationStrategy aclAuthorizationStrategy() {
            return new AclAuthorizationStrategyImpl(new SimpleGrantedAuthority("SUPERVISOR"));
        }

        @Bean
        public ObjectIdentityRetrievalStrategy aclObjectIdentityRetrievalStrategy() {
            return new DelegatingObjectIdentityRetrievalStrategy(objectIdentityRetrievals);
        }

        @Bean
        public ObjectIdentityGenerator aclObjectIdentityGenerator() {
            return new DelegatingObjectIdentityRetrievalStrategy(objectIdentityRetrievals);
        }

        @Bean
        public SidRetrievalStrategy aclSidRetrievalStrategy() {
            return new SidRetrievalStrategyImpl(roleHierarchy);
        }
    }
}
