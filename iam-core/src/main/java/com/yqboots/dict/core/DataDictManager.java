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
package com.yqboots.dict.core;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

/**
 * The Interface class for Data Dictionary.
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
public interface DataDictManager {
    /**
     * Gets the Data Dictionary by its identity.
     *
     * @param id the primary key
     * @return DataDict
     */
    DataDict getDataDict(Long id);

    /**
     * Searches by wildcard name.
     *
     * @param wildcardName wildcard name
     * @param pageable     pageable
     * @return pages of DataDict
     */
    Page<DataDict> getDataDicts(String wildcardName, Pageable pageable);

    /**
     * Gets the Data Dictionaries by name.
     *
     * @param name the name of one DataDict
     * @return list of DataDict
     */
    List<DataDict> getDataDicts(String name);

    /**
     * Gets the Data Dictionaries by name and locale.
     *
     * @param name   the name of one DataDict
     * @param locale the locale
     * @return list of DataDict
     */
    List<DataDict> getDataDicts(String name, Locale locale);

    /**
     * Gets the displayed text. Usually used in the Thymeleaf html template file.
     *
     * @param name  the name of a DataDict
     * @param value the value of a DataDict
     * @return the displayed text
     */
    String getText(String name, String value);

    /**
     * Gets the displayed text. Usually used in the Thymeleaf html template file.
     *
     * @param name          the name of a DataDict
     * @param value         the value of a DataDict
     * @param valueIncluded whether includes the value
     * @return the displayed text
     */
    String getText(String name, String value, boolean valueIncluded);

    /**
     * Updates.
     *
     * @param dict the DataDict
     * @throws DataDictExistsException if the dict exists
     */
    DataDict update(DataDict dict) throws DataDictExistsException;

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
     * Exports all data dictionaries to a file for downloading.
     *
     * @return the exported file path
     * @throws IOException if failed
     */
    Path exports() throws IOException;
}
