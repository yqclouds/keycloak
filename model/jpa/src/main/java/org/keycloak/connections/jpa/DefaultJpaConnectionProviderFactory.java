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

import org.hibernate.cfg.AvailableSettings;
import org.keycloak.ServerStartupError;
import org.keycloak.connections.jpa.updater.JpaUpdaterProvider;
import org.keycloak.connections.jpa.util.JpaUtils;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakSessionTask;
import org.keycloak.models.dblock.DBLockManager;
import org.keycloak.models.dblock.DBLockProvider;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ServerInfoAwareProviderFactory;
import org.keycloak.stereotype.ProviderFactory;
import org.keycloak.timer.TimerProvider;
import org.keycloak.transaction.JtaTransactionManagerLookup;
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
import java.util.*;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
@Component("DefaultJpaConnectionProviderFactory")
@ProviderFactory(id = "default", providerClasses = JpaConnectionProvider.class)
public class DefaultJpaConnectionProviderFactory implements JpaConnectionProviderFactory, ServerInfoAwareProviderFactory {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultJpaConnectionProviderFactory.class);

    private Map<String, String> operationalInfo;
    private boolean jtaEnabled;
    private JtaTransactionManagerLookup jtaLookup;

    private int globalStatsInterval = -1;
    private String migrationExport = "keycloak-database-update.sql";
    private String migrationStrategy = "UPDATE";

    @Autowired
    private KeycloakSessionFactory sessionFactory;

    @Autowired
    private DataSource dataSource;
    @Autowired
    private EntityManagerFactory entityManagerFactory;

    @Override
    public JpaConnectionProvider create(KeycloakSession session) {
        LOG.trace("Create JpaConnectionProvider");
        lazyInit(session);

        EntityManager em = PersistenceExceptionConverter.create(entityManagerFactory.createEntityManager());
        if (!jtaEnabled) session.getTransactionManager().enlist(new JpaKeycloakTransaction(em));
        return new DefaultJpaConnectionProvider(em);
    }

    @PreDestroy
    public void destroy() throws Exception {
        if (entityManagerFactory != null) {
            entityManagerFactory.close();
        }
    }

    private void lazyInit(KeycloakSession session) {
        if (entityManagerFactory == null) {
            synchronized (this) {
                if (entityManagerFactory == null) {
                    KeycloakModelUtils.suspendJtaTransaction(session.getKeycloakSessionFactory(), () -> {
                        LOG.debug("Initializing JPA connections");

                        Map<String, Object> properties = new HashMap<>();

                        String unitName = "keycloak-default";

                        properties.put(AvailableSettings.JPA_JDBC_URL, "jdbc:h2:mem:keycloak");
                        properties.put(AvailableSettings.JPA_JDBC_DRIVER, "org.h2.Driver");
                        properties.put(AvailableSettings.JPA_JDBC_USER, "sa");
                        properties.put(AvailableSettings.JPA_JDBC_PASSWORD, "sa");

                        String schema = getSchema();
                        if (schema != null) {
                            properties.put(JpaUtils.HIBERNATE_DEFAULT_SCHEMA, schema);
                        }

                        MigrationStrategy migrationStrategy = getMigrationStrategy();
                        boolean initializeEmpty = true; // config.getBoolean("initializeEmpty", true);
                        File databaseUpdateFile = getDatabaseUpdateFile();

                        properties.put("hibernate.show_sql", true);
                        properties.put("hibernate.format_sql", true);

                        Connection connection = getConnection();
                        try {
                            prepareOperationalInfo(connection);

                            String driverDialect = detectDialect(connection);
                            if (driverDialect != null) {
                                properties.put("hibernate.dialect", driverDialect);
                            }

                            migration(migrationStrategy, initializeEmpty, schema, databaseUpdateFile, connection, session);

                            int globalStatsInterval = this.globalStatsInterval;
                            if (globalStatsInterval != -1) {
                                properties.put("hibernate.generate_statistics", true);
                            }

                            LOG.trace("Creating EntityManagerFactory");
                            Collection<ClassLoader> classLoaders = new ArrayList<>();
                            if (properties.containsKey(AvailableSettings.CLASSLOADERS)) {
                                classLoaders.addAll((Collection<ClassLoader>) properties.get(AvailableSettings.CLASSLOADERS));
                            }
                            classLoaders.add(getClass().getClassLoader());
                            properties.put(AvailableSettings.CLASSLOADERS, classLoaders);
                            entityManagerFactory = JpaUtils.createEntityManagerFactory(session, unitName, properties, jtaEnabled);
                            LOG.trace("EntityManagerFactory created");

                            if (globalStatsInterval != -1) {
                                startGlobalStats(session, globalStatsInterval);
                            }
                        } finally {
                            // Close after creating EntityManagerFactory to prevent in-mem databases from closing
                            if (connection != null) {
                                try {
                                    connection.close();
                                } catch (SQLException e) {
                                    LOG.warn("Can't close connection", e);
                                }
                            }
                        }
                    });
                }
            }
        }
    }

    private File getDatabaseUpdateFile() {
        return new File(migrationExport);
    }

    protected void prepareOperationalInfo(Connection connection) {
        try {
            operationalInfo = new LinkedHashMap<>();
            DatabaseMetaData md = connection.getMetaData();
            operationalInfo.put("databaseUrl", md.getURL());
            operationalInfo.put("databaseUser", md.getUserName());
            operationalInfo.put("databaseProduct", md.getDatabaseProductName() + " " + md.getDatabaseProductVersion());
            operationalInfo.put("databaseDriver", md.getDriverName() + " " + md.getDriverVersion());

            LOG.debug("Database info: {}", operationalInfo.toString());
        } catch (SQLException e) {
            LOG.warn("Unable to prepare operational info due database exception: " + e.getMessage());
        }
    }

    protected String detectDialect(Connection connection) {
        try {
            String dbProductName = connection.getMetaData().getDatabaseProductName();
            String dbProductVersion = connection.getMetaData().getDatabaseProductVersion();

            // For MSSQL2014, we may need to fix the autodetected dialect by hibernate
            if (dbProductName.equals("Microsoft SQL Server")) {
                String topVersionStr = dbProductVersion.split("\\.")[0];
                boolean shouldSet2012Dialect = true;
                try {
                    int topVersion = Integer.parseInt(topVersionStr);
                    if (topVersion < 12) {
                        shouldSet2012Dialect = false;
                    }
                } catch (NumberFormatException nfe) {
                }
                if (shouldSet2012Dialect) {
                    String sql2012Dialect = "org.hibernate.dialect.SQLServer2012Dialect";
                    LOG.debug("Manually override hibernate dialect to {}", sql2012Dialect);
                    return sql2012Dialect;
                }
            }
            // For Oracle19c, we may need to set dialect explicitly to workaround https://hibernate.atlassian.net/browse/HHH-13184
            if (dbProductName.equals("Oracle") && connection.getMetaData().getDatabaseMajorVersion() > 12) {
                LOG.debug("Manually specify dialect for Oracle to org.hibernate.dialect.Oracle12cDialect");
                return "org.hibernate.dialect.Oracle12cDialect";
            }
        } catch (SQLException e) {
            LOG.warn("Unable to detect hibernate dialect due database exception : {}", e.getMessage());
        }

        return null;
    }

    protected void startGlobalStats(KeycloakSession session, int globalStatsIntervalSecs) {
        LOG.debug("Started Hibernate statistics with the interval {} seconds", globalStatsIntervalSecs);
        TimerProvider timer = session.getProvider(TimerProvider.class);
        timer.scheduleTask(new HibernateStatsReporter(entityManagerFactory), globalStatsIntervalSecs * 1000, "ReportHibernateGlobalStats");
    }

    void migration(MigrationStrategy strategy, boolean initializeEmpty, String schema, File databaseUpdateFile, Connection connection, KeycloakSession session) {
        JpaUpdaterProvider updater = session.getProvider(JpaUpdaterProvider.class);

        JpaUpdaterProvider.Status status = updater.validate(connection, schema);
        if (status == JpaUpdaterProvider.Status.VALID) {
            LOG.debug("Database is up-to-date");
        } else if (status == JpaUpdaterProvider.Status.EMPTY) {
            if (initializeEmpty) {
                update(connection, schema, session, updater);
            } else {
                switch (strategy) {
                    case UPDATE:
                        update(connection, schema, session, updater);
                        break;
                    case MANUAL:
                        export(connection, schema, databaseUpdateFile, session, updater);
                        throw new ServerStartupError("Database not initialized, please initialize database with " + databaseUpdateFile.getAbsolutePath(), false);
                    case VALIDATE:
                        throw new ServerStartupError("Database not initialized, please enable database initialization", false);
                }
            }
        } else {
            switch (strategy) {
                case UPDATE:
                    update(connection, schema, session, updater);
                    break;
                case MANUAL:
                    export(connection, schema, databaseUpdateFile, session, updater);
                    throw new ServerStartupError("Database not up-to-date, please migrate database with " + databaseUpdateFile.getAbsolutePath(), false);
                case VALIDATE:
                    throw new ServerStartupError("Database not up-to-date, please enable database migration", false);
            }
        }
    }

    protected void update(Connection connection, String schema, KeycloakSession session, JpaUpdaterProvider updater) {
        KeycloakModelUtils.runJobInTransaction(session.getKeycloakSessionFactory(), new KeycloakSessionTask() {
            @Override
            public void run(KeycloakSession lockSession) {
                DBLockManager dbLockManager = new DBLockManager(lockSession);
                DBLockProvider dbLock2 = dbLockManager.getDBLock();
                dbLock2.waitForLock(DBLockProvider.Namespace.DATABASE);
                try {
                    updater.update(connection, schema);
                } finally {
                    dbLock2.releaseLock();
                }
            }
        });
    }

    protected void export(Connection connection, String schema, File databaseUpdateFile, KeycloakSession session, JpaUpdaterProvider updater) {
        KeycloakModelUtils.runJobInTransaction(session.getKeycloakSessionFactory(), new KeycloakSessionTask() {
            @Override
            public void run(KeycloakSession lockSession) {
                DBLockManager dbLockManager = new DBLockManager(lockSession);
                DBLockProvider dbLock2 = dbLockManager.getDBLock();
                dbLock2.waitForLock(DBLockProvider.Namespace.DATABASE);
                try {
                    updater.export(connection, schema, databaseUpdateFile);
                } finally {
                    dbLock2.releaseLock();
                }
            }
        });
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
