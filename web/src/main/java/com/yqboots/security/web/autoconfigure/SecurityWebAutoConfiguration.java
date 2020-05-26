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
package com.yqboots.security.web.autoconfigure;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import javax.servlet.http.HttpSessionListener;

/**
 * The web security configuration.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
@Configuration
// @Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
public class SecurityWebAutoConfiguration extends WebSecurityConfigurerAdapter {
    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private AuthenticationProvider authenticationProvider;

    /**
     * {@inheritDoc}
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/", "/security/login", "/projects/**", "/showcase/**").permitAll()
                .and().authorizeRequests().anyRequest().authenticated()
                .and().anonymous().authorities("/USER")
                .and().csrf().disable().formLogin().loginPage("/security/login").loginProcessingUrl("/login")
                .and().httpBasic().realmName("YQBoots")
                .and().rememberMe().userDetailsService(userDetailsService)
                .and().sessionManagement().maximumSessions(3).expiredUrl("/security/login").sessionRegistry(sessionRegistry())
                .and().sessionFixation().migrateSession().sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                .and().exceptionHandling().accessDeniedPage("/security/403");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
        auth.eraseCredentials(true).authenticationProvider(authenticationProvider);
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public ServletListenerRegistrationBean<HttpSessionListener> httpSessionEventPublisher() {
        return new ServletListenerRegistrationBean<>(new HttpSessionEventPublisher());
    }
}
