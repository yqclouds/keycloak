/*
 *
 *  * Copyright 2015-2016 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */
package com.yqboots.menu.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.nio.file.Path;

/**
 * The configuration properties for MenuItem.
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
@ConfigurationProperties(prefix = "yqboots.menu")
public class MenuItemProperties {
    /**
     * The location which places the exported file.
     */
    private Path exportFileLocation;

    /**
     * The prefix for the name of the exported file.
     */
    private String exportFileNamePrefix;

    /**
     * The flag checks whether need import MenuItems after application startup.
     */
    private boolean importEnabled;

    /**
     * The location of the importing file after application startup.
     */
    private String importFileLocation;

    public Path getExportFileLocation() {
        return exportFileLocation;
    }

    public void setExportFileLocation(final Path exportFileLocation) {
        this.exportFileLocation = exportFileLocation;
    }

    public String getExportFileNamePrefix() {
        return exportFileNamePrefix;
    }

    public void setExportFileNamePrefix(final String exportFileNamePrefix) {
        this.exportFileNamePrefix = exportFileNamePrefix;
    }

    public boolean isImportEnabled() {
        return importEnabled;
    }

    public void setImportEnabled(final boolean importEnabled) {
        this.importEnabled = importEnabled;
    }

    public String getImportFileLocation() {
        return importFileLocation;
    }

    public void setImportFileLocation(final String importFileLocation) {
        this.importFileLocation = importFileLocation;
    }
}
