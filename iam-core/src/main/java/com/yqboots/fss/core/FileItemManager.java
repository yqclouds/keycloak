/*
 * Copyright 2015-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yqboots.fss.core;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.io.IOException;
import java.nio.file.Path;

/**
 * The interface that manages the FileItem..
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
public interface FileItemManager {
    /**
     * Finds by directory path.
     *
     * @param path     the directory to search
     * @param pageable the paged information
     * @return paged of FileItem
     * @throws IOException if failed
     */
    Page<FileItem> findByPath(String path, Pageable pageable) throws IOException;

    /**
     * Deletes the file with the specified path.
     *
     * @param path the file path, not directory.
     * @throws IOException
     */
    void delete(String path) throws IOException;

    /**
     * Gets the full path based on the root directory.
     *
     * @param relativePath the relative path to the root
     * @return the full path
     */
    Path getFullPath(String relativePath);

    /**
     * Gets the root path.
     *
     * @return the root path
     */
    Path getRootPath();
}
