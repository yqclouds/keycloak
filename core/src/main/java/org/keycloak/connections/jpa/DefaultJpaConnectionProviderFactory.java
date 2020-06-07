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

package org.keycloak.connections.jpa;

import org.keycloak.connections.jpa.updater.JpaUpdaterProvider;
import org.keycloak.models.dblock.DBLockManager;
import org.keycloak.models.dblock.DBLockProvider;
import org.keycloak.provider.ServerInfoAwareProviderFactory;
import org.keycloak.stereotype.ProviderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PreDestroy;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.sql.DataSource;
import java.io.File;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
@Component("DefaultJpaConnectionProviderFactory")
@ProviderFactory(id = "default", providerClasses = JpaConnectionProvider.class)
public class DefaultJpaConnectionProviderFactory implements JpaConnectionProviderFactory, ServerInfoAwareProviderFactory {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultJpaConnectionProviderFactory.class);

    private Map<String, String> operationalInfo;
    private boolean jtaEnabled;

    private int globalStatsInterval = -1;
    private String migrationExport = "keycloak-database-update.sql";
    private String migrationStrategy = "UPDATE";

    @Autowired
    private DataSource dataSource;
    @Autowired
    private EntityManagerFactory entityManagerFactory;
    @Autowired
    private JpaUpdaterProvider jpaUpdaterProvider;

    @Override
    public JpaConnectionProvider create() {
        LOG.trace("Create JpaConnectionProvider");
        EntityManager em = PersistenceExceptionConverter.create(entityManagerFactory.createEntityManager());
        return new DefaultJpaConnectionProvider(em);
    }

    @PreDestroy
    public void destroy() throws Exception {
        if (entityManagerFactory != null) {
            entityManagerFactory.close();
        }
    }

    protected void update(Connection connection, String schema, JpaUpdaterProvider updater) {
        DBLockManager dbLockManager = new DBLockManager();
        DBLockProvider dbLock2 = dbLockManager.getDBLock();
        dbLock2.waitForLock(DBLockProvider.Namespace.DATABASE);
        try {
            updater.update(connection, schema);
        } finally {
            dbLock2.releaseLock();
        }
    }

    protected void export(Connection connection, String schema, File databaseUpdateFile, JpaUpdaterProvider updater) {
        DBLockManager dbLockManager = new DBLockManager();
        DBLockProvider dbLock2 = dbLockManager.getDBLock();
        dbLock2.waitForLock(DBLockProvider.Namespace.DATABASE);
        try {
            updater.export(connection, schema, databaseUpdateFile);
        } finally {
            dbLock2.releaseLock();
        }
    }

    @Override
    public Connection getConnection() {
        try {
            return dataSource.getConnection();
        } catch (Exception e) {
            throw new RuntimeException("Failed to connect to database", e);
        }
    }

    @Override
    public String getSchema() {
        return "";
    }

    @Override
    public Map<String, String> getOperationalInfo() {
        return operationalInfo;
    }

    private MigrationStrategy getMigrationStrategy() {
        String migrationStrategy = this.migrationStrategy;
        if (migrationStrategy != null) {
            return MigrationStrategy.valueOf(migrationStrategy.toUpperCase());
        } else {
            return MigrationStrategy.UPDATE;
        }
    }

    enum MigrationStrategy {
        UPDATE, VALIDATE, MANUAL
    }

}
