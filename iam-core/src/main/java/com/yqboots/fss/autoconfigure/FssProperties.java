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
package com.yqboots.fss.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.nio.file.Path;

/**
 * The ConfigurationProperties for Data Dictionary related functions.
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
@ConfigurationProperties(prefix = "yqboots.fss")
public class FssProperties {
    /**
     * The root path of file storage. All files will be under this folder.
     */
    private Path root;

    /**
     * Filters the files by file types.
     */
    private String[] fileTypes = new String[]{};

    public Path getRoot() {
        return this.root;
    }

    public void setRoot(Path root) {
        this.root = root;
    }

    public String[] getFileTypes() {
        return fileTypes;
    }

    public void setFileTypes(final String[] fileTypes) {
        this.fileTypes = fileTypes;
    }
}
