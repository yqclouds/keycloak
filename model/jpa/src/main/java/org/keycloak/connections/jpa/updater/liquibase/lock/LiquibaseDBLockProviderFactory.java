/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.connections.jpa.updater.liquibase.lock;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.dblock.DBLockProvider;
import org.keycloak.models.dblock.DBLockProviderFactory;
import org.keycloak.stereotype.ProviderFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@Component("LiquibaseDBLockProviderFactory")
@ProviderFactory(id = "jpa", providerClasses = DBLockProvider.class)
public class LiquibaseDBLockProviderFactory implements DBLockProviderFactory {

    private static final Logger logger = Logger.getLogger(LiquibaseDBLockProviderFactory.class);

    @Value("${lockWaitTimeout}")
    private int lockWaitTimeout;
    private long lockWaitTimeoutMillis;

    protected long getLockWaitTimeoutMillis() {
        return lockWaitTimeoutMillis;
    }

    @PostConstruct
    public void afterPropertiesSet() {
        this.lockWaitTimeoutMillis = Time.toMillis(lockWaitTimeout);
        logger.debugf("Liquibase lock provider configured with lockWaitTime: %d seconds", lockWaitTimeout);
    }

    @Override
    public LiquibaseDBLockProvider create(KeycloakSession session) {
        return new LiquibaseDBLockProvider(this, session);
    }

    @Override
    public void setTimeouts(long lockRecheckTimeMillis, long lockWaitTimeoutMillis) {
        this.lockWaitTimeoutMillis = lockWaitTimeoutMillis;
    }

    @Override
    public String getId() {
        return "jpa";
    }
}
