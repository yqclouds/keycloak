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
package com.yqboots.web.support;

/**
 * The common keys used in the controller class, to unify the key usage.
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
public class WebKeys {
    /**
     * Used as the key for searching form
     */
    public static final String SEARCH_FORM = "searchForm";

    /**
     * Used as the key for file upload form.
     */
    public static final String FILE_UPLOAD_FORM = "fileUploadForm";

    /**
     * Used in the form for domain creation and update.
     */
    public static final String MODEL = "model";

    /**
     * Used in the list of paged data.
     */
    public static final String PAGE = "page";

    /**
     * Used for the multipart file.
     */
    public static final String FILE = "file";

    /**
     * Used for the file path.
     */
    public static final String PATH = "path";

    /**
     * Used in the parameters for the id of domain.
     */
    public static final String ID = "id";

    /**
     * Used in the parameter for creating new domain.
     */
    public static final String ACTION_NEW = "action=new";

    /**
     * Used in the parameter for updating existing domain.
     */
    public static final String ACTION_UPDATE = "action=update";

    /**
     * Used in the parameter for deleting existing domain.
     */
    public static final String ACTION_DELETE = "action=delete";

    /**
     * Used in the parameter for downloading file..
     */
    public static final String ACTION_DOWNLOAD = "action=download";

    /**
     * Used for the value of request mapping, for the root.
     */
    public static final String MAPPING_ROOT = "/";

    /**
     * Used for the value of request mapping, for uploading.
     */
    public static final String MAPPING_UPLOAD = "/upload";

    /**
     * Used for the value of request mapping, for exporting.
     */
    public static final String MAPPING_EXPORTS = "/exports";

    /**
     * Used for the value of request mapping, for importing.
     */
    public static final String MAPPING_IMPORTS = "/imports";
}
