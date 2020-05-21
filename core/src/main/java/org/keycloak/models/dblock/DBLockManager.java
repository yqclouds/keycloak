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

package org.keycloak.models.dblock;

import org.keycloak.models.KeycloakSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class DBLockManager {
    private static final Logger LOG = LoggerFactory.getLogger(DBLockManager.class);

    private final KeycloakSession session;

    private boolean forceUnlock;
    private DBLockProviderFactory dbLockProviderFactory;

    public DBLockManager(KeycloakSession session) {
        this.session = session;
    }

    public void checkForcedUnlock() {
        if (forceUnlock) {
            DBLockProvider lock = getDBLock();
            if (lock.supportsForcedUnlock()) {
                LOG.warn("Forced release of DB lock at startup requested by System property. Make sure to not use this in production environment! And especially when more cluster nodes are started concurrently.");
                lock.releaseLock();
            } else {
                throw new IllegalStateException("Forced unlock requested, but provider " + lock + " doesn't support it");
            }
        }
    }

    public DBLockProvider getDBLock() {
        return dbLockProviderFactory.create();
    }

    public void setForceUnlock(boolean forceUnlock) {
        this.forceUnlock = forceUnlock;
    }

    public void setDbLockProviderFactory(DBLockProviderFactory dbLockProviderFactory) {
        this.dbLockProviderFactory = dbLockProviderFactory;
    }
}
