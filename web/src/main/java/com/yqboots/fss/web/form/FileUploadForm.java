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
package com.yqboots.fss.web.form;

import org.springframework.web.multipart.MultipartFile;

import java.io.Serializable;

/**
 * The file upload form.
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
public class FileUploadForm implements Serializable {
    /**
     * The uploaded file.
     */
    private MultipartFile file;

    /**
     * The target path where the file puts.
     */
    private String path;

    /**
     * The flag indicates whether need to override the same file in the specified folder.
     */
    private boolean overrideExisting;

    public MultipartFile getFile() {
        return file;
    }

    public void setFile(final MultipartFile file) {
        this.file = file;
    }

    public String getPath() {
        return path;
    }

    public void setPath(final String path) {
        this.path = path;
    }

    public boolean isOverrideExisting() {
        return overrideExisting;
    }

    public void setOverrideExisting(final boolean overrideExisting) {
        this.overrideExisting = overrideExisting;
    }
}
