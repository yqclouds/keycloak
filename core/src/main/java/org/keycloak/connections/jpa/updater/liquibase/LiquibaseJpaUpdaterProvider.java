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

package org.keycloak.connections.jpa.updater.liquibase;

import liquibase.Contexts;
import liquibase.LabelExpression;
import liquibase.Liquibase;
import liquibase.changelog.ChangeLogHistoryService;
import liquibase.changelog.ChangeLogHistoryServiceFactory;
import liquibase.changelog.ChangeSet;
import liquibase.changelog.RanChangeSet;
import liquibase.database.Database;
import liquibase.exception.DatabaseException;
import liquibase.exception.LiquibaseException;
import liquibase.executor.Executor;
import liquibase.executor.ExecutorService;
import liquibase.executor.LoggingExecutor;
import liquibase.snapshot.SnapshotControl;
import liquibase.snapshot.SnapshotGeneratorFactory;
import liquibase.statement.SqlStatement;
import liquibase.statement.core.AddColumnStatement;
import liquibase.statement.core.CreateDatabaseChangeLogTableStatement;
import liquibase.statement.core.SetNullableStatement;
import liquibase.statement.core.UpdateStatement;
import liquibase.structure.core.Column;
import liquibase.structure.core.Table;
import liquibase.util.StreamUtil;
import org.keycloak.common.util.reflections.Reflections;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.keycloak.connections.jpa.updater.JpaUpdaterProvider;
import org.keycloak.connections.jpa.updater.liquibase.conn.LiquibaseConnectionProvider;
import org.keycloak.connections.jpa.util.JpaUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class LiquibaseJpaUpdaterProvider implements JpaUpdaterProvider {

    public static final String CHANGELOG = "META-INF/jpa-changelog-master.xml";
    public static final String DEPLOYMENT_ID_COLUMN = "DEPLOYMENT_ID";
    private static final Logger LOG = LoggerFactory.getLogger(LiquibaseJpaUpdaterProvider.class);

    @Autowired
    private LiquibaseConnectionProvider connectionProvider;

    public static String getTable(String table, String defaultSchema) {
        return defaultSchema != null ? defaultSchema + "." + table : table;
    }

    @Override
    public void update(Connection connection, String defaultSchema) {
        update(connection, null, defaultSchema);
    }

    @Override
    public void export(Connection connection, String defaultSchema, File file) {
        update(connection, file, defaultSchema);
    }

    @Autowired
    private Set<JpaEntityProvider> jpaProviders;

    private void update(Connection connection, File file, String defaultSchema) {
        LOG.debug("Starting database update");

        Writer exportWriter = null;
        try {
            // Run update with keycloak master changelog first
            Liquibase liquibase = getLiquibaseForKeycloakUpdate(connection, defaultSchema);
            if (file != null) {
                exportWriter = new FileWriter(file);
            }
            updateChangeSet(liquibase, connection, exportWriter);

            // Run update for each custom JpaEntityProvider
            for (JpaEntityProvider jpaProvider : jpaProviders) {
                String customChangelog = jpaProvider.getChangelogLocation();
                if (customChangelog != null) {
                    String factoryId = jpaProvider.getFactoryId();
                    String changelogTableName = JpaUtils.getCustomChangelogTableName(factoryId);
                    liquibase = getLiquibaseForCustomProviderUpdate(connection, defaultSchema, customChangelog, jpaProvider.getClass().getClassLoader(), changelogTableName);
                    updateChangeSet(liquibase, connection, exportWriter);
                }
            }
        } catch (LiquibaseException | IOException | SQLException e) {
            throw new RuntimeException("Failed to update database", e);
        } finally {
            if (exportWriter != null) {
                try {
                    exportWriter.close();
                } catch (IOException ioe) {
                    // ignore
                }
            }
        }
    }

    protected void updateChangeSet(Liquibase liquibase, Connection connection, Writer exportWriter) throws LiquibaseException, SQLException {
        String changelog = liquibase.getChangeLogFile();
        Database database = liquibase.getDatabase();
        Table changelogTable = SnapshotGeneratorFactory.getInstance().getDatabaseChangeLogTable(new SnapshotControl(database, false, Table.class, Column.class), database);

        if (changelogTable != null) {
            boolean hasDeploymentIdColumn = changelogTable.getColumn(DEPLOYMENT_ID_COLUMN) != null;

            // create DEPLOYMENT_ID column if it doesn't exist
            if (!hasDeploymentIdColumn) {
                ChangeLogHistoryService changelogHistoryService = ChangeLogHistoryServiceFactory.getInstance().getChangeLogService(database);
                changelogHistoryService.generateDeploymentId();
                String deploymentId = changelogHistoryService.getDeploymentId();

                LOG.debug("Adding missing column {}={} to {} table", DEPLOYMENT_ID_COLUMN, deploymentId, changelogTable.getName());

                List<SqlStatement> statementsToExecute = new ArrayList<>();
                statementsToExecute.add(new AddColumnStatement(database.getLiquibaseCatalogName(), database.getLiquibaseSchemaName(),
                        changelogTable.getName(), DEPLOYMENT_ID_COLUMN, "VARCHAR(10)", null));
                statementsToExecute.add(new UpdateStatement(database.getLiquibaseCatalogName(), database.getLiquibaseSchemaName(), changelogTable.getName())
                        .addNewColumnValue(DEPLOYMENT_ID_COLUMN, deploymentId));
                statementsToExecute.add(new SetNullableStatement(database.getLiquibaseCatalogName(), database.getLiquibaseSchemaName(),
                        changelogTable.getName(), DEPLOYMENT_ID_COLUMN, "VARCHAR(10)", false));

                ExecutorService executorService = ExecutorService.getInstance();
                Executor executor = executorService.getExecutor(liquibase.getDatabase());

                for (SqlStatement sql : statementsToExecute) {
                    executor.execute(sql);
                    database.commit();
                }
            }
        }

        List<ChangeSet> changeSets = getLiquibaseUnrunChangeSets(liquibase);
        if (!changeSets.isEmpty()) {
            List<RanChangeSet> ranChangeSets = liquibase.getDatabase().getRanChangeSetList();
            if (ranChangeSets.isEmpty()) {
                LOG.info("Initializing database schema. Using changelog {}", changelog);
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Updating database from {} to {}. Using changelog {}", ranChangeSets.get(ranChangeSets.size() - 1).getId(), changeSets.get(changeSets.size() - 1).getId(), changelog);
                } else {
                    LOG.info("Updating database. Using changelog {}", changelog);
                }
            }

            if (exportWriter != null) {
                if (ranChangeSets.isEmpty()) {
                    outputChangeLogTableCreationScript(liquibase, exportWriter);
                }
                liquibase.update((Contexts) null, new LabelExpression(), exportWriter, false);
            } else {
                liquibase.update((Contexts) null);
            }

            LOG.debug("Completed database update for changelog {}", changelog);
        } else {
            LOG.debug("Database is up to date for changelog {}", changelog);
        }

        // Needs to restart liquibase services to clear ChangeLogHistoryServiceFactory.getInstance().
        // See https://issues.jboss.org/browse/KEYCLOAK-3769 for discussion relevant to why reset needs to be here
        resetLiquibaseServices(liquibase);
    }

    private void outputChangeLogTableCreationScript(Liquibase liquibase, final Writer exportWriter) throws DatabaseException {
        Database database = liquibase.getDatabase();

        Executor oldTemplate = ExecutorService.getInstance().getExecutor(database);
        LoggingExecutor executor = new LoggingExecutor(ExecutorService.getInstance().getExecutor(database), exportWriter, database);
        ExecutorService.getInstance().setExecutor(database, executor);

        executor.comment("*********************************************************************");
        executor.comment("* Keycloak database creation script - apply this script to empty DB *");
        executor.comment("*********************************************************************" + StreamUtil.getLineSeparator());

        executor.execute(new CreateDatabaseChangeLogTableStatement());

        executor.comment("*********************************************************************" + StreamUtil.getLineSeparator());

        ExecutorService.getInstance().setExecutor(database, oldTemplate);
    }

    @Override
    public Status validate(Connection connection, String defaultSchema) {
        LOG.debug("Validating if database is updated");
        try {
            // Validate with keycloak master changelog first
            Liquibase liquibase = getLiquibaseForKeycloakUpdate(connection, defaultSchema);

            Status status = validateChangeSet(liquibase, liquibase.getChangeLogFile());
            if (status != Status.VALID) {
                return status;
            }

            // Validate each custom JpaEntityProvider
            for (JpaEntityProvider jpaProvider : jpaProviders) {
                String customChangelog = jpaProvider.getChangelogLocation();
                if (customChangelog != null) {
                    String factoryId = jpaProvider.getFactoryId();
                    String changelogTableName = JpaUtils.getCustomChangelogTableName(factoryId);
                    liquibase = getLiquibaseForCustomProviderUpdate(connection, defaultSchema, customChangelog, jpaProvider.getClass().getClassLoader(), changelogTableName);
                    if (validateChangeSet(liquibase, liquibase.getChangeLogFile()) != Status.VALID) {
                        return Status.OUTDATED;
                    }
                }
            }
        } catch (LiquibaseException e) {
            throw new RuntimeException("Failed to validate database", e);
        }

        return Status.VALID;
    }

    protected Status validateChangeSet(Liquibase liquibase, String changelog) throws LiquibaseException {
        final Status result;
        List<ChangeSet> changeSets = getLiquibaseUnrunChangeSets(liquibase);

        if (!changeSets.isEmpty()) {
            if (changeSets.size() == liquibase.getDatabaseChangeLog().getChangeSets().size()) {
                result = Status.EMPTY;
            } else {
                LOG.debug("Validation failed. Database is not up-to-date for changelog {}", changelog);
                result = Status.OUTDATED;
            }
        } else {
            LOG.debug("Validation passed. Database is up-to-date for changelog {}", changelog);
            result = Status.VALID;
        }

        // Needs to restart liquibase services to clear ChangeLogHistoryServiceFactory.getInstance().
        // See https://issues.jboss.org/browse/KEYCLOAK-3769 for discussion relevant to why reset needs to be here
        resetLiquibaseServices(liquibase);

        return result;
    }

    private void resetLiquibaseServices(Liquibase liquibase) {
        Method resetServices = Reflections.findDeclaredMethod(Liquibase.class, "resetServices");
        Reflections.invokeMethod(true, resetServices, liquibase);
    }

    @SuppressWarnings("unchecked")
    private List<ChangeSet> getLiquibaseUnrunChangeSets(Liquibase liquibase) {
        // TODO tracked as: https://issues.jboss.org/browse/KEYCLOAK-3730
        // TODO: When https://liquibase.jira.com/browse/CORE-2919 is resolved, replace the following two lines with:
        // List<ChangeSet> changeSets = liquibase.listUnrunChangeSets((Contexts) null, new LabelExpression(), false);
        Method listUnrunChangeSets = Reflections.findDeclaredMethod(Liquibase.class, "listUnrunChangeSets", Contexts.class, LabelExpression.class, boolean.class);
        return Reflections.invokeMethod(true, listUnrunChangeSets, List.class, liquibase, (Contexts) null, new LabelExpression(), false);
    }

    private Liquibase getLiquibaseForKeycloakUpdate(Connection connection, String defaultSchema) throws LiquibaseException {
        return connectionProvider.getLiquibase(connection, defaultSchema);
    }

    private Liquibase getLiquibaseForCustomProviderUpdate(Connection connection, String defaultSchema, String changelogLocation, ClassLoader classloader, String changelogTableName) throws LiquibaseException {
        return connectionProvider.getLiquibaseForCustomUpdate(connection, defaultSchema, changelogLocation, classloader, changelogTableName);
    }

    @Override
    public void close() {
    }
}
