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

package org.keycloak.exportimport.dir;

import com.hsbc.unified.iam.core.util.JsonSerialization;
import org.keycloak.Config;
import org.keycloak.exportimport.ImportProvider;
import org.keycloak.exportimport.Strategy;
import org.keycloak.exportimport.util.ImportUtils;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.representations.idm.RealmRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.File;
import java.io.FileInputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class DirImportProvider implements ImportProvider {

    private static final Logger LOG = LoggerFactory.getLogger(DirImportProvider.class);

    private final File rootDirectory;

    @Autowired
    private RealmProvider realmProvider;

    public DirImportProvider() {
        // Determine system tmp directory
        String tempDir = System.getProperty("java.io.tmpdir");

        // Delete and recreate directory inside tmp
        this.rootDirectory = new File(tempDir + "/keycloak-export");
        if (!this.rootDirectory.exists()) {
            throw new IllegalStateException("Directory " + this.rootDirectory + " doesn't exists");
        }

        LOG.info("Importing from directory {}", this.rootDirectory.getAbsolutePath());
    }

    public DirImportProvider(File rootDirectory) {
        this.rootDirectory = rootDirectory;

        if (!this.rootDirectory.exists()) {
            throw new IllegalStateException("Directory " + this.rootDirectory + " doesn't exists");
        }

        LOG.info("Importing from directory {}", this.rootDirectory.getAbsolutePath());
    }

    @Override
    public void importModel(Strategy strategy) throws IOException {
        List<String> realmNames = getRealmsToImport();

        for (String realmName : realmNames) {
            importRealm(realmName, strategy);
        }
    }

    @Override
    public boolean isMasterRealmExported() throws IOException {
        List<String> realmNames = getRealmsToImport();
        return realmNames.contains(Config.getAdminRealm());
    }

    private List<String> getRealmsToImport() throws IOException {
        File[] realmFiles = this.rootDirectory.listFiles(new FilenameFilter() {

            @Override
            public boolean accept(File dir, String name) {
                return (name.endsWith("-realm.json"));
            }
        });

        List<String> realmNames = new ArrayList<>();
        for (File file : realmFiles) {
            String fileName = file.getName();
            // Parse "foo" from "foo-realm.json"
            String realmName = fileName.substring(0, fileName.length() - 11);

            // Ensure that master realm is imported first
            if (Config.getAdminRealm().equals(realmName)) {
                realmNames.add(0, realmName);
            } else {
                realmNames.add(realmName);
            }
        }
        return realmNames;
    }

    @Autowired
    private RepresentationToModel representationToModel;
    @Autowired
    private ImportUtils importUtils;

    @Override
    public void importRealm(final String realmName, final Strategy strategy) throws IOException {
        File realmFile = new File(this.rootDirectory + File.separator + realmName + "-realm.json");
        File[] userFiles = this.rootDirectory.listFiles(new FilenameFilter() {

            @Override
            public boolean accept(File dir, String name) {
                return name.matches(realmName + "-users-[0-9]+\\.json");
            }
        });
        File[] federatedUserFiles = this.rootDirectory.listFiles(new FilenameFilter() {

            @Override
            public boolean accept(File dir, String name) {
                return name.matches(realmName + "-federated-users-[0-9]+\\.json");
            }
        });

        // Import realm first
        FileInputStream is = new FileInputStream(realmFile);
        final RealmRepresentation realmRep = JsonSerialization.readValue(is, RealmRepresentation.class);
        final AtomicBoolean realmImported = new AtomicBoolean();

        boolean imported = importUtils.importRealm(realmRep, strategy, true);
        realmImported.set(imported);

        if (realmImported.get()) {
            // Import users
            for (final File userFile : userFiles) {
                final FileInputStream fis = new FileInputStream(userFile);
                importUtils.importUsersFromStream(realmName, JsonSerialization.mapper, fis);
                LOG.info("Imported users from {}", userFile.getAbsolutePath());
            }
            for (final File userFile : federatedUserFiles) {
                final FileInputStream fis = new FileInputStream(userFile);
                importUtils.importFederatedUsersFromStream(realmName, JsonSerialization.mapper, fis);
                LOG.info("Imported federated users from {}", userFile.getAbsolutePath());
            }
        }

        // Import authorization last, as authzPolicies can require users already in DB
        RealmModel realm = realmProvider.getRealmByName(realmName);
        representationToModel.importRealmAuthorizationSettings(realmRep, realm);
    }

    @Override
    public void close() {

    }
}
