package org.keycloak.web.listener;

import com.fasterxml.jackson.core.type.TypeReference;
import org.keycloak.Config;
import org.keycloak.common.util.Resteasy;
import org.keycloak.exportimport.ExportImportManager;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.ApplianceBootstrap;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.services.managers.UserStorageSyncManager;
import org.keycloak.services.resources.KeycloakApplication;
import org.keycloak.services.scheduled.*;
import org.keycloak.timer.TimerProvider;
import org.keycloak.transaction.JtaTransactionManagerLookup;
import org.keycloak.util.JsonSerialization;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.stereotype.Component;
import org.springframework.web.context.WebApplicationContext;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.servlet.ServletContext;
import javax.transaction.SystemException;
import javax.transaction.Transaction;
import java.io.*;
import java.util.List;
import java.util.Objects;
import java.util.StringTokenizer;

@Component
public class KeycloakApplicationListener implements ApplicationListener<ContextRefreshedEvent> {
    private static final Logger LOG = LoggerFactory.getLogger(KeycloakApplicationListener.class);

    private KeycloakSessionFactory sessionFactory;

    @Autowired
    public KeycloakApplicationListener(KeycloakSessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
    }

    @Override
    public void onApplicationEvent(ContextRefreshedEvent contextRefreshedEvent) {
        WebApplicationContext context = (WebApplicationContext) contextRefreshedEvent.getApplicationContext();

        LOG.debug("RestEasy provider: {}", Resteasy.getProvider().getClass().getName());
        Resteasy.pushContext(ServletContext.class, context.getServletContext());

        Objects.requireNonNull(context.getServletContext()).setAttribute(KeycloakSessionFactory.class.getName(), this.sessionFactory);

        startup();
    }

    @PostConstruct
    protected void startup() {
        ExportImportManager[] exportImportManager = new ExportImportManager[1];
        KeycloakModelUtils.runJobInTransaction(sessionFactory, lockSession -> {
            exportImportManager[0] = migrateAndBootstrap();
        });

        if (exportImportManager[0].isRunExport()) {
            exportImportManager[0].runExport();
        }

        KeycloakModelUtils.runJobInTransaction(sessionFactory, session -> {
            boolean shouldBootstrapAdmin = new ApplianceBootstrap(session).isNoMasterUser();
            KeycloakApplication.BOOTSTRAP_ADMIN_USER.set(shouldBootstrapAdmin);
        });

        sessionFactory.publish(new PostMigrationEvent());

        setupScheduledTasks(sessionFactory);
    }

    // Migrate model, bootstrap master realm, import realms and create admin user. This is done with acquired dbLock
    protected ExportImportManager migrateAndBootstrap() {
        ExportImportManager exportImportManager;

        LOG.debug("bootstrap");
        KeycloakSession session = sessionFactory.create();
        try {
            session.getTransactionManager().begin();
            JtaTransactionManagerLookup lookup = (JtaTransactionManagerLookup) sessionFactory.getProviderFactory(JtaTransactionManagerLookup.class);
            if (lookup != null) {
                if (lookup.getTransactionManager() != null) {
                    try {
                        Transaction transaction = lookup.getTransactionManager().getTransaction();
                        LOG.debug("bootstrap current transaction? {}", transaction != null);
                        if (transaction != null) {
                            LOG.debug("bootstrap current transaction status? {}", transaction.getStatus());
                        }
                    } catch (SystemException e) {
                        throw new RuntimeException(e);
                    }
                }
            }

            ApplianceBootstrap applianceBootstrap = new ApplianceBootstrap(session);
            exportImportManager = new ExportImportManager(session);

            boolean createMasterRealm = applianceBootstrap.isNewInstall();
            if (exportImportManager.isRunImport() && exportImportManager.isImportMasterIncluded()) {
                createMasterRealm = false;
            }

            if (createMasterRealm) {
                applianceBootstrap.createMasterRealm();
            }
            session.getTransactionManager().commit();
        } catch (RuntimeException re) {
            if (session.getTransactionManager().isActive()) {
                session.getTransactionManager().rollback();
            }
            throw re;
        } finally {
            session.close();
        }

        if (exportImportManager.isRunImport()) {
            exportImportManager.runImport();
        } else {
            importRealms();
        }

        importAddUser();

        return exportImportManager;
    }

    @PreDestroy
    protected void shutdown() {
        if (sessionFactory != null) {
            sessionFactory.close();
        }
    }

    @Autowired
    private TimerProvider timerProvider;

    public void setupScheduledTasks(final KeycloakSessionFactory sessionFactory) {
        long interval = Config.scope("scheduled").getLong("interval", 60L) * 1000;

        KeycloakSession session = sessionFactory.create();
        try {
            timerProvider.schedule(new ClusterAwareScheduledTaskRunner(sessionFactory, new ClearExpiredEvents(), interval), interval, "ClearExpiredEvents");
            timerProvider.schedule(new ClusterAwareScheduledTaskRunner(sessionFactory, new ClearExpiredClientInitialAccessTokens(), interval), interval, "ClearExpiredClientInitialAccessTokens");
            timerProvider.schedule(new ScheduledTaskRunner(sessionFactory, new ClearExpiredUserSessions()), interval, ClearExpiredUserSessions.TASK_NAME);
            new UserStorageSyncManager().bootstrapPeriodic(sessionFactory, timerProvider);
        } finally {
            session.close();
        }
    }

    public void importRealms() {
        String files = System.getProperty("keycloak.import");
        if (files != null) {
            StringTokenizer tokenizer = new StringTokenizer(files, ",");
            while (tokenizer.hasMoreTokens()) {
                String file = tokenizer.nextToken().trim();
                RealmRepresentation rep;
                try {
                    rep = loadJson(new FileInputStream(file), RealmRepresentation.class);
                } catch (FileNotFoundException e) {
                    throw new RuntimeException(e);
                }
                importRealm(rep, "file " + file);
            }
        }
    }

    public void importRealm(RealmRepresentation rep, String from) {
        KeycloakSession session = sessionFactory.create();
        boolean exists = false;
        try {
            session.getTransactionManager().begin();

            try {
                RealmManager manager = new RealmManager(session);

                if (rep.getId() != null && manager.getRealm(rep.getId()) != null) {
//                    ServicesLogger.LOGGER.realmExists(rep.getRealm(), from);
                    exists = true;
                }

                if (manager.getRealmByName(rep.getRealm()) != null) {
//                    ServicesLogger.LOGGER.realmExists(rep.getRealm(), from);
                    exists = true;
                }
                if (!exists) {
                    RealmModel realm = manager.importRealm(rep);
//                    ServicesLogger.LOGGER.importedRealm(realm.getName(), from);
                }
                session.getTransactionManager().commit();
            } catch (Throwable t) {
                session.getTransactionManager().rollback();
                if (!exists) {
//                    ServicesLogger.LOGGER.unableToImportRealm(t, rep.getRealm(), from);
                }
            }
        } finally {
            session.close();
        }
    }

    public void importAddUser() {
        String configDir = System.getProperty("jboss.server.config.dir");
        if (configDir != null) {
            File addUserFile = new File(configDir + File.separator + "keycloak-add-user.json");
            if (addUserFile.isFile()) {
//                ServicesLogger.LOGGER.imprtingUsersFrom(addUserFile);

                List<RealmRepresentation> realms;
                try {
                    realms = JsonSerialization.readValue(new FileInputStream(addUserFile), new TypeReference<List<RealmRepresentation>>() {
                    });
                } catch (IOException e) {
//                    ServicesLogger.LOGGER.failedToLoadUsers(e);
                    return;
                }

                for (RealmRepresentation realmRep : realms) {
                    for (UserRepresentation userRep : realmRep.getUsers()) {
                        KeycloakSession session = sessionFactory.create();

                        try {
                            session.getTransactionManager().begin();
                            RealmModel realm = session.realms().getRealmByName(realmRep.getRealm());

                            if (realm == null) {
//                                ServicesLogger.LOGGER.addUserFailedRealmNotFound(userRep.getUsername(), realmRep.getRealm());
                            }

                            UserProvider users = session.users();

                            if (users.getUserByUsername(userRep.getUsername(), realm) != null) {
//                                ServicesLogger.LOGGER.notCreatingExistingUser(userRep.getUsername());
                            } else {
                                UserModel user = users.addUser(realm, userRep.getUsername());
                                user.setEnabled(userRep.isEnabled());
                                RepresentationToModel.createCredentials(userRep, session, realm, user, false);
                                RepresentationToModel.createRoleMappings(userRep, user, realm);
//                                ServicesLogger.LOGGER.addUserSuccess(userRep.getUsername(), realmRep.getRealm());
                            }

                            session.getTransactionManager().commit();
                        } catch (ModelDuplicateException e) {
                            session.getTransactionManager().rollback();
//                            ServicesLogger.LOGGER.addUserFailedUserExists(userRep.getUsername(), realmRep.getRealm());
                        } catch (Throwable t) {
                            session.getTransactionManager().rollback();
//                            ServicesLogger.LOGGER.addUserFailed(t, userRep.getUsername(), realmRep.getRealm());
                        } finally {
                            session.close();
                        }
                    }
                }

                if (!addUserFile.delete()) {
//                    ServicesLogger.LOGGER.failedToDeleteFile(addUserFile.getAbsolutePath());
                }
            }
        }
    }

    private static <T> T loadJson(InputStream is, Class<T> type) {
        try {
            return JsonSerialization.readValue(is, type);
        } catch (IOException e) {
            throw new RuntimeException("Failed to parse json", e);
        }
    }
}
