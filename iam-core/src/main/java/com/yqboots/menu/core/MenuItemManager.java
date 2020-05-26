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
package com.yqboots.menu.core;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.List;

/**
 * It Manages the MenuItem related functions.
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
public interface MenuItemManager {
    /**
     * Gets all menu items.
     *
     * @return list of MenuItem
     */
    List<MenuItem> getMenuItems();

    /**
     * Searches by wildcard name.
     *
     * @param wildcardName wildcard name
     * @param pageable     pageable
     * @return pages of MenuItem
     */
    Page<MenuItem> getMenuItems(String wildcardName, Pageable pageable);

    /**
     * Gets MenuItem by its id.
     *
     * @param id the id of the MenuItem
     * @return the MenuItem
     */
    MenuItem getMenuItem(Long id);

    /**
     * Gets MenuItem by its name.
     *
     * @param name the name of the MenuItem
     * @return the MenuItem
     */
    MenuItem getMenuItem(String name);

    /**
     * Updates.
     *
     * @param entity the entity to save
     */
    MenuItem update(MenuItem entity);

    /**
     * Deletes.
     *
     * @param id the primary key
     */
    void delete(Long id);

    /**
     * Imports an XML-presented file, which contains menu items.
     *
     * @param inputStream the file stream
     * @throws IOException if failed
     */
    void imports(InputStream inputStream) throws IOException;

    /**
     * Exports all menu items to a file for downloading.
     *
     * @return the exported file path
     * @throws IOException if failed
     */
    Path exports() throws IOException;
}
