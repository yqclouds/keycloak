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

import liquibase.Liquibase;
import liquibase.exception.DatabaseException;
import liquibase.exception.LiquibaseException;
import org.keycloak.common.util.Retry;
import org.keycloak.connections.jpa.JpaConnectionProviderFactory;
import org.keycloak.connections.jpa.updater.liquibase.conn.LiquibaseConnectionProvider;
import org.keycloak.connections.jpa.updater.liquibase.conn.LiquibaseConnectionProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.dblock.DBLockProvider;
import org.keycloak.models.dblock.DBLockProviderFactory;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class LiquibaseDBLockProvider implements DBLockProvider {
    private static final Logger LOG = LoggerFactory.getLogger(LiquibaseDBLockProvider.class);

    private final KeycloakSession session;
    // 10 should be sufficient
    private int DEFAULT_MAX_ATTEMPTS = 10;
    private CustomLockService lockService;
    private Connection dbConnection;
    private boolean initialized = false;
    private Namespace namespaceLocked = null;

    @Autowired
    private JpaConnectionProviderFactory jpaConnectionProviderFactory;
    @Autowired
    private LiquibaseConnectionProviderFactory liquibaseConnectionProviderFactory;
    @Autowired
    private DBLockProviderFactory dbLockProviderFactory;

    public LiquibaseDBLockProvider(KeycloakSession session) {
        this.session = session;
    }

    private void lazyInit() {
        if (!initialized) {
            this.dbConnection = jpaConnectionProviderFactory.getConnection();
            String defaultSchema = jpaConnectionProviderFactory.getSchema();

            try {
                LiquibaseConnectionProvider liquibaseProvider = liquibaseConnectionProviderFactory.create(session);
                Liquibase liquibase = liquibaseProvider.getLiquibase(dbConnection, defaultSchema);

                this.lockService = new CustomLockService();
                lockService.setChangeLogLockWaitTime(dbLockProviderFactory.getLockWaitTimeoutMillis());
                lockService.setDatabase(liquibase.getDatabase());
                initialized = true;
            } catch (LiquibaseException exception) {
                safeRollbackConnection();
                safeCloseConnection();
                throw new IllegalStateException(exception);
            }
        }
    }

    // Assumed transaction was rolled-back and we want to start with new DB connection
    private void restart() {
        safeCloseConnection();
        this.dbConnection = null;
        this.lockService = null;
        initialized = false;
        lazyInit();
    }

    @Override
    public void waitForLock(Namespace lock) {
        KeycloakModelUtils.suspendJtaTransaction(session.getKeycloakSessionFactory(), () -> {

            lazyInit();

            if (this.lockService.hasChangeLogLock()) {
                if (lock.equals(this.namespaceLocked)) {
                    LOG.warn("Locking namespace {} which was already locked in this provider", lock);
                    return;
                } else {
                    throw new RuntimeException(String.format("Trying to get a lock when one was already taken by the provider"));
                }
            }

            LOG.debug("Going to lock namespace={}", lock);
            Retry.executeWithBackoff((int iteration) -> {

                lockService.waitForLock(lock);
                namespaceLocked = lock;

            }, (int iteration, Throwable e) -> {

                if (e instanceof LockRetryException && iteration < (DEFAULT_MAX_ATTEMPTS - 1)) {
                    // Indicates we should try to acquire lock again in different transaction
                    safeRollbackConnection();
                    restart();
                } else {
                    safeRollbackConnection();
                    safeCloseConnection();
                }

            }, DEFAULT_MAX_ATTEMPTS, 10);
        });

    }

    @Override
    public void releaseLock() {
        KeycloakModelUtils.suspendJtaTransaction(session.getKeycloakSessionFactory(), () -> {
            lazyInit();

            LOG.debug("Going to release database lock namespace={}", namespaceLocked);
            namespaceLocked = null;
            lockService.releaseLock();
            lockService.reset();
        });
    }

    @Override
    public Namespace getCurrentLock() {
        return this.namespaceLocked;
    }

    @Override
    public boolean supportsForcedUnlock() {
        // Implementation based on "SELECT FOR UPDATE" can't force unlock as it's locked by other transaction
        return false;
    }

    @Override
    public void destroyLockInfo() {
        KeycloakModelUtils.suspendJtaTransaction(session.getKeycloakSessionFactory(), () -> {
            lazyInit();

            try {
                this.lockService.destroy();
                dbConnection.commit();
                LOG.debug("Destroyed lock table");
            } catch (DatabaseException | SQLException de) {
                LOG.error("Failed to destroy lock table");
                safeRollbackConnection();
            }
        });
    }

    @Override
    public void close() {
        KeycloakModelUtils.suspendJtaTransaction(session.getKeycloakSessionFactory(), this::safeCloseConnection);
    }

    private void safeRollbackConnection() {
        if (dbConnection != null) {
            try {
                this.dbConnection.rollback();
            } catch (SQLException se) {
                LOG.warn("Failed to rollback connection after error", se);
            }
        }
    }

    private void safeCloseConnection() {
        // Close to prevent in-mem databases from closing
        if (dbConnection != null) {
            try {
                dbConnection.close();
            } catch (SQLException e) {
                LOG.warn("Failed to close connection", e);
            }
        }
    }

    public void setJpaConnectionProviderFactory(JpaConnectionProviderFactory jpaConnectionProviderFactory) {
        this.jpaConnectionProviderFactory = jpaConnectionProviderFactory;
    }

    public void setLiquibaseConnectionProviderFactory(LiquibaseConnectionProviderFactory liquibaseConnectionProviderFactory) {
        this.liquibaseConnectionProviderFactory = liquibaseConnectionProviderFactory;
    }

    public void setDbLockProviderFactory(DBLockProviderFactory dbLockProviderFactory) {
        this.dbLockProviderFactory = dbLockProviderFactory;
    }
}
