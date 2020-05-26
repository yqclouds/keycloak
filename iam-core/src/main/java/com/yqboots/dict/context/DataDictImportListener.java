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
package com.yqboots.dict.context;

import com.yqboots.dict.autoconfigure.DataDictProperties;
import com.yqboots.dict.core.DataDictManager;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.util.ResourceUtils;

import java.io.*;

/**
 * A listener, which importing data dictionaries from XML after the application context refreshed.
 *
 * @author Eric H B Zhan
 * @see com.yqboots.dict.core.DataDict
 * @since 1.0.0
 */
public class DataDictImportListener implements ApplicationListener<ContextRefreshedEvent> {
    private static final Logger LOG = LoggerFactory.getLogger(DataDictImportListener.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public void onApplicationEvent(final ContextRefreshedEvent event) {
        final ApplicationContext context = event.getApplicationContext();

        final DataDictManager manager = context.getBean(DataDictManager.class);
        final DataDictProperties properties = context.getBean(DataDictProperties.class);
        if (!properties.isImportEnabled()) {
            return;
        }

        final String location = properties.getImportFileLocation();
        if (StringUtils.isEmpty(location)) {
            LOG.warn("Data Dict Importing is enabled, but location was not set");
            return;
        }

        try {
            final File file = ResourceUtils.getFile(location);
            try (final InputStream inputStream = new FileInputStream(file)) {
                manager.imports(inputStream);
            }
        } catch (IOException e) {
            LOG.error("Failed to import Data Dicts", e);
        }
    }
}
