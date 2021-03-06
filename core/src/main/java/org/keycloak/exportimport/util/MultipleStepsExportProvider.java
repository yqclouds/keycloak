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

package org.keycloak.exportimport.util;

import org.keycloak.exportimport.ExportImportConfig;
import org.keycloak.exportimport.ExportProvider;
import org.keycloak.exportimport.UsersExportStrategy;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.storage.federated.UserFederatedStorageProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.IOException;
import java.util.List;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public abstract class MultipleStepsExportProvider implements ExportProvider {

    protected final Logger LOG = LoggerFactory.getLogger(getClass());

    @Autowired
    private RealmProvider realmProvider;
    @Autowired
    private UserFederatedStorageProvider userFederatedStorageProvider;

    @Override
    public void exportModel() throws IOException {
        final RealmsHolder holder = new RealmsHolder();
        List<RealmModel> realms = realmProvider.getRealms();
        holder.realms = realms;

        for (RealmModel realm : holder.realms) {
            exportRealmImpl(realm.getName());
        }
    }

    @Override
    public void exportRealm(String realmName) throws IOException {
        exportRealmImpl(realmName);
    }

    @Autowired
    private ExportUtils exportUtils;

    @Autowired
    private UserProvider userProvider;

    protected void exportRealmImpl(final String realmName) throws IOException {
        final UsersExportStrategy usersExportStrategy = ExportImportConfig.getUsersExportStrategy();
        final int usersPerFile = ExportImportConfig.getUsersPerFile();
        final UsersHolder usersHolder = new UsersHolder();
        final boolean exportUsersIntoRealmFile = usersExportStrategy == UsersExportStrategy.REALM_FILE;
        FederatedUsersHolder federatedUsersHolder = new FederatedUsersHolder();

        RealmModel realm = realmProvider.getRealmByName(realmName);
        RealmRepresentation rep = exportUtils.exportRealm(realm, exportUsersIntoRealmFile, true);
        writeRealm(realmName + "-realm.json", rep);
        LOG.info("Realm '" + realmName + "' - data exported");

        // Count total number of users
        if (!exportUsersIntoRealmFile) {
            usersHolder.totalCount = userProvider.getUsersCount(realm, true);
            federatedUsersHolder.totalCount = userFederatedStorageProvider.getStoredUsersCount(realm);
        }

        if (usersExportStrategy != UsersExportStrategy.SKIP && !exportUsersIntoRealmFile) {
            // We need to export users now
            usersHolder.currentPageStart = 0;

            // usersExportStrategy==SAME_FILE  means exporting all users into single file (but separate to realm)
            final int countPerPage = (usersExportStrategy == UsersExportStrategy.SAME_FILE) ? usersHolder.totalCount : usersPerFile;

            while (usersHolder.currentPageStart < usersHolder.totalCount) {
                if (usersHolder.currentPageStart + countPerPage < usersHolder.totalCount) {
                    usersHolder.currentPageEnd = usersHolder.currentPageStart + countPerPage;
                } else {
                    usersHolder.currentPageEnd = usersHolder.totalCount;
                }

                usersHolder.users = userProvider.getUsers(realm, usersHolder.currentPageStart, usersHolder.currentPageEnd - usersHolder.currentPageStart, true);

                writeUsers(realmName + "-users-" + (usersHolder.currentPageStart / countPerPage) + ".json", realm, usersHolder.users);

                LOG.info("Users " + usersHolder.currentPageStart + "-" + (usersHolder.currentPageEnd - 1) + " exported");
                usersHolder.currentPageStart = usersHolder.currentPageEnd;
            }
        }
        if (usersExportStrategy != UsersExportStrategy.SKIP && !exportUsersIntoRealmFile) {
            // We need to export users now
            federatedUsersHolder.currentPageStart = 0;

            // usersExportStrategy==SAME_FILE  means exporting all users into single file (but separate to realm)
            final int countPerPage = (usersExportStrategy == UsersExportStrategy.SAME_FILE) ? federatedUsersHolder.totalCount : usersPerFile;

            while (federatedUsersHolder.currentPageStart < federatedUsersHolder.totalCount) {
                if (federatedUsersHolder.currentPageStart + countPerPage < federatedUsersHolder.totalCount) {
                    federatedUsersHolder.currentPageEnd = federatedUsersHolder.currentPageStart + countPerPage;
                } else {
                    federatedUsersHolder.currentPageEnd = federatedUsersHolder.totalCount;
                }

                federatedUsersHolder.users = userFederatedStorageProvider.getStoredUsers(realm, federatedUsersHolder.currentPageStart, federatedUsersHolder.currentPageEnd - federatedUsersHolder.currentPageStart);

                writeFederatedUsers(realmName + "-federated-users-" + (federatedUsersHolder.currentPageStart / countPerPage) + ".json", realm, federatedUsersHolder.users);

                LOG.info("Users " + federatedUsersHolder.currentPageStart + "-" + (federatedUsersHolder.currentPageEnd - 1) + " exported");


                federatedUsersHolder.currentPageStart = federatedUsersHolder.currentPageEnd;
            }
        }
    }

    protected abstract void writeRealm(String fileName, RealmRepresentation rep) throws IOException;

    protected abstract void writeUsers(String fileName, RealmModel realm, List<UserModel> users) throws IOException;

    protected abstract void writeFederatedUsers(String fileName, RealmModel realm, List<String> users) throws IOException;

    public static class RealmsHolder {
        List<RealmModel> realms;

    }

    public static class UsersHolder {
        List<UserModel> users;
        int totalCount;
        int currentPageStart;
        int currentPageEnd;
    }

    public static class FederatedUsersHolder {
        List<String> users;
        int totalCount;
        int currentPageStart;
        int currentPageEnd;
    }
}
