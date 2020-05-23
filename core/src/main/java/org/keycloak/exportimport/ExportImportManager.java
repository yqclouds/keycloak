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

package org.keycloak.exportimport;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.IOException;
import java.util.Map;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ExportImportManager {

    private static final Logger LOG = LoggerFactory.getLogger(ExportImportManager.class);
    private final String realmName;
    @Autowired
    private ExportProvider exportProvider;
    @Autowired
    private ImportProvider importProvider;

    @Autowired
    private Map<String, ExportProvider> exportProviders;

    public ExportImportManager() {
        realmName = ExportImportConfig.getRealmName();

        String providerId = ExportImportConfig.getProvider();
        String exportImportAction = ExportImportConfig.getAction();

        if (ExportImportConfig.ACTION_EXPORT.equals(exportImportAction)) {
            if (exportProvider == null) {
                throw new RuntimeException("Export provider '" + providerId + "' not found");
            }
        } else if (ExportImportConfig.ACTION_IMPORT.equals(exportImportAction)) {
            if (importProvider == null) {
                throw new RuntimeException("Import provider '" + providerId + "' not found");
            }
        }
    }

    public boolean isRunImport() {
        return importProvider != null;
    }

    public boolean isImportMasterIncluded() {
        if (!isRunImport()) {
            throw new IllegalStateException("Import not enabled");
        }
        try {
            return importProvider.isMasterRealmExported();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean isRunExport() {
        return exportProvider != null;
    }

    public void runImport() {
        try {
            Strategy strategy = ExportImportConfig.getStrategy();
            if (realmName == null) {
//                ServicesLogger.LOGGER.fullModelImport(strategy.toString());
                importProvider.importModel(strategy);
            } else {
//                ServicesLogger.LOGGER.realmImportRequested(realmName, strategy.toString());
                importProvider.importRealm(realmName, strategy);
            }
//            ServicesLogger.LOGGER.importSuccess();
        } catch (IOException e) {
            throw new RuntimeException("Failed to run import", e);
        }
    }

    public void runExport() {
        try {
            if (realmName == null) {
//                ServicesLogger.LOGGER.fullModelExportRequested();
                exportProvider.exportModel();
            } else {
//                ServicesLogger.LOGGER.realmExportRequested(realmName);
                exportProvider.exportRealm(realmName);
            }
//            ServicesLogger.LOGGER.exportSuccess();
        } catch (IOException e) {
            throw new RuntimeException("Failed to run export");
        }
    }

}
