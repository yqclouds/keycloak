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
package com.yqboots.dict.core.repository;

import com.yqboots.dict.core.DataDict;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

/**
 * The Repository class for Data Dictionary.
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
public interface DataDictRepository extends JpaRepository<DataDict, Long>, JpaSpecificationExecutor<DataDict> {
    /**
     * Finds by name, order by text.
     *
     * @param name the name
     * @return list of DataDict
     */
    List<DataDict> findByNameOrderByText(String name);

    /**
     * Finds all names of dictionary.
     *
     * @return different names of dictionary
     */
    @Query("select distinct name from #{#entityName}")
    List<String> findAllDataDictNames();

    /**
     * Finds by name and value.
     *
     * @param name  the name
     * @param value the value
     * @return the DataDict
     */
    DataDict findByNameAndValue(String name, String value);

    /**
     * Finds by wildcard name, ignore case
     *
     * @param name     the name
     * @param pageable the page information
     * @return paged of DataDict
     */
    Page<DataDict> findByNameLikeIgnoreCase(String name, Pageable pageable);
}
