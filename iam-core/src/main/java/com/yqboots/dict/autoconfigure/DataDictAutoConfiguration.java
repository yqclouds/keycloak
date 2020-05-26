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
package com.yqboots.dict.autoconfigure;

import com.yqboots.dict.context.DataDictImportListener;
import com.yqboots.dict.core.DataDictManager;
import com.yqboots.dict.core.DataDictManagerImpl;
import com.yqboots.dict.core.repository.DataDictRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * The Auto Configuration class for Data Dictionary related beans.
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
@Configuration
@EnableConfigurationProperties({DataDictProperties.class})
@Import({DataDictImportListener.class})
public class DataDictAutoConfiguration {
    @Autowired
    private DataDictRepository dataDictRepository;

    @Autowired
    private DataDictProperties properties;

    @Bean
    public DataDictManager dataDictManager() {
        return new DataDictManagerImpl(dataDictRepository, properties);
    }
}
