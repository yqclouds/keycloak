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
package com.yqboots.security.web.authentication.event;

import com.yqboots.security.core.audit.LoginHistory;
import com.yqboots.security.core.audit.repository.LoginHistoryRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

import java.sql.Timestamp;

/**
 * Listens to the {@link InteractiveAuthenticationSuccessEvent}, logs the login history.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
@Component
public class LoginHistoryOnAuthenticationSuccessListener implements ApplicationListener<InteractiveAuthenticationSuccessEvent> {
    private static final Logger LOG = LoggerFactory.getLogger(LoginHistoryOnAuthenticationSuccessListener.class);

    @Autowired
    private LoginHistoryRepository loginHistoryRepository;

    /**
     * {@inheritDoc}
     */
    @Override
    public void onApplicationEvent(final InteractiveAuthenticationSuccessEvent event) {
        Authentication auth = event.getAuthentication();
        if (auth instanceof UsernamePasswordAuthenticationToken) {
            UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) auth;
            if (token.getDetails() instanceof WebAuthenticationDetails) {
                WebAuthenticationDetails details = (WebAuthenticationDetails) token.getDetails();

                LOG.debug(token.toString());

                LoginHistory history = new LoginHistory();
                history.setUsername(token.getName());
                history.setSessionId(details.getSessionId());
                history.setIpAddress(details.getRemoteAddress());
                history.setLoginTime(new Timestamp(event.getTimestamp()));

                loginHistoryRepository.save(history);
            }
        }
    }
}
