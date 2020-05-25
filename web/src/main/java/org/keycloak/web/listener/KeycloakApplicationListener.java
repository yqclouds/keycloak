package org.keycloak.web.listener;

import com.fasterxml.jackson.core.type.TypeReference;
import com.hsbc.unified.iam.core.util.JsonSerialization;
import org.keycloak.Config;
import org.keycloak.common.util.Resteasy;
import org.keycloak.exportimport.ExportImportManager;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.services.managers.ApplianceBootstrap;
import com.hsbc.unified.iam.facade.spi.impl.RealmFacadeImpl;
import org.keycloak.services.managers.UserStorageSyncManager;
import org.keycloak.services.resources.KeycloakApplication;
import org.keycloak.services.scheduled.*;
import org.keycloak.timer.TimerProvider;
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
        KeycloakModelUtils.runJobInTransaction(() -> {
            exportImportManager[0] = migrateAndBootstrap();
        });

        if (exportImportManager[0].isRunExport()) {
            exportImportManager[0].runExport();
        }

        KeycloakModelUtils.runJobInTransaction(() -> {
            boolean shouldBootstrapAdmin = new ApplianceBootstrap().isNoMasterUser();
            KeycloakApplication.BOOTSTRAP_ADMIN_USER.set(shouldBootstrapAdmin);
        });

        sessionFactory.publish(new PostMigrationEvent(this));

        setupScheduledTasks(sessionFactory);
    }

    // Migrate model, bootstrap master realm, import realms and create admin user. This is done with acquired dbLock
    protected ExportImportManager migrateAndBootstrap() {
        ExportImportManager exportImportManager;

        LOG.debug("bootstrap");
        try {
            ApplianceBootstrap applianceBootstrap = new ApplianceBootstrap();
            exportImportManager = new ExportImportManager();

            boolean createMasterRealm = applianceBootstrap.isNewInstall();
            if (exportImportManager.isRunImport() && exportImportManager.isImportMasterIncluded()) {
                createMasterRealm = false;
            }

            if (createMasterRealm) {
                applianceBootstrap.createMasterRealm();
            }
        } catch (RuntimeException re) {
            throw re;
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

        timerProvider.schedule(new ClusterAwareScheduledTaskRunner(new ClearExpiredEvents(), interval), interval, "ClearExpiredEvents");
        timerProvider.schedule(new ClusterAwareScheduledTaskRunner(new ClearExpiredClientInitialAccessTokens(), interval), interval, "ClearExpiredClientInitialAccessTokens");
        timerProvider.schedule(new ScheduledTaskRunner(new ClearExpiredUserSessions()), interval, ClearExpiredUserSessions.TASK_NAME);
        new UserStorageSyncManager().bootstrapPeriodic(timerProvider);
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
        boolean exists = false;
        try {
            RealmFacadeImpl manager = new RealmFacadeImpl();

            if (rep.getId() != null && manager.getRealm(rep.getId()) != null) {
//                    ServicesLogger.LOGGER.realmExists(rep.getRealm(), from);
                exists = true;
            }

            if (manager.getRealmByName(rep.getRealm()) != null) {
//                    ServicesLogger.LOGGER.realmExists(rep.getRealm(), from);
                exists = true;
            }
            if (!exists) {
                RealmModel realm = manager.createRealm(rep);
//                    ServicesLogger.LOGGER.importedRealm(realm.getName(), from);
            }
        } catch (Throwable t) {
            if (!exists) {
//                    ServicesLogger.LOGGER.unableToImportRealm(t, rep.getRealm(), from);
            }
        }
    }

    @Autowired
    private RepresentationToModel representationToModel;
    @Autowired
    private RealmProvider realmProvider;
    @Autowired
    private UserProvider userProvider;

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
                        try {
                            RealmModel realm = realmProvider.getRealmByName(realmRep.getRealm());

                            if (realm == null) {
//                                ServicesLogger.LOGGER.addUserFailedRealmNotFound(userRep.getUsername(), realmRep.getRealm());
                            }

                            if (userProvider.getUserByUsername(userRep.getUsername(), realm) != null) {
//                                ServicesLogger.LOGGER.notCreatingExistingUser(userRep.getUsername());
                            } else {
                                UserModel user = userProvider.addUser(realm, userRep.getUsername());
                                user.setEnabled(userRep.isEnabled());
                                representationToModel.createCredentials(userRep, realm, user, false);
                                RepresentationToModel.createRoleMappings(userRep, user, realm);
//                                ServicesLogger.LOGGER.addUserSuccess(userRep.getUsername(), realmRep.getRealm());
                            }
                        } catch (ModelDuplicateException e) {
//                            ServicesLogger.LOGGER.addUserFailedUserExists(userRep.getUsername(), realmRep.getRealm());
                        } catch (Throwable t) {
//                            ServicesLogger.LOGGER.addUserFailed(t, userRep.getUsername(), realmRep.getRealm());
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
