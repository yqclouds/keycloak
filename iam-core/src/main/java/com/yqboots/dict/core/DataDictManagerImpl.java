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

import com.yqboots.core.util.DBUtils;
import com.yqboots.dict.autoconfigure.DataDictProperties;
import com.yqboots.dict.core.repository.DataDictRepository;
import com.yqboots.fss.core.support.FileType;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.Cache;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

import javax.annotation.PostConstruct;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.util.*;
import java.util.function.Predicate;

/**
 * Manages the Data Dictionary the project has.
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
@Transactional(readOnly = true)
public class DataDictManagerImpl implements DataDictManager {
    private static final Logger LOG = LoggerFactory.getLogger(DataDictManagerImpl.class);

    private final DataDictRepository dataDictRepository;

    private final DataDictProperties properties;

    private final DataDictCache cache = new DefaultDataDictCache();

    /**
     * For marshalling and unmarshalling Data Dictionaries.
     */
    private static Jaxb2Marshaller jaxb2Marshaller;

    static {
        jaxb2Marshaller = new Jaxb2Marshaller();
        jaxb2Marshaller.setClassesToBeBound(DataDicts.class, DataDict.class);
    }

    @PostConstruct
    protected void initialize() {
        final List<String> names = dataDictRepository.findAllDataDictNames();
        for (final String name : names) {
            cache.initialize(name, dataDictRepository.findByNameOrderByText(name));
        }
    }

    /**
     * {@inheritDoc}
     */
    public DataDictManagerImpl(final DataDictRepository dataDictRepository, final DataDictProperties properties) {
        this.dataDictRepository = dataDictRepository;
        this.properties = properties;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public DataDict getDataDict(final Long id) {
        return dataDictRepository.getOne(id);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Page<DataDict> getDataDicts(final String wildcardName, final Pageable pageable) {
        final String searchStr = StringUtils.trim(StringUtils.defaultString(wildcardName));

        return dataDictRepository.findByNameLikeIgnoreCase(DBUtils.wildcard(searchStr), pageable);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<DataDict> getDataDicts(final String name) {
        Assert.hasText(name, "name is required");

        return getDataDicts(name, LocaleContextHolder.getLocale());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<DataDict> getDataDicts(final String name, final Locale locale) {
        Assert.hasText(name, "name is required");
        Assert.notNull(locale, "locale is required");

        List<DataDict> results = cache.get(name, locale);
        if (!results.isEmpty()) {
            return results;
        }

        results = dataDictRepository.findByNameOrderByText(getCachedKey(name, locale));
        if (results.isEmpty()) { // fall back to default
            LOG.warn("data dicts for the specified locale {} of name {} did not set", locale, name);
            results = dataDictRepository.findByNameOrderByText(name);
        }

        return results;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getText(final String name, final String value) {
        return getText(name, value, false);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getText(final String name, final String value, boolean valueIncluded) {
        final List<DataDict> all = getDataDicts(name, LocaleContextHolder.getLocale());

        final DataDict item = (DataDict) CollectionUtils.find(all, o -> {
            final DataDict dict = (DataDict) o;
            return StringUtils.equals(dict.getValue(), value);
        });

        if (item == null) {
            LOG.warn("No data dict for {} with value [{}]", name, value);
            return value;
        }

        return valueIncluded ? StringUtils.join(new String[]{item.getValue(), item.getText()}, " - ") : item.getText();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    public DataDict update(final DataDict entity) throws DataDictExistsException {
        DataDict result;
        if (!entity.isNew()) {
            result = dataDictRepository.save(entity);

            cache.put(result);

            return result;
        }

        Assert.hasText(entity.getName(), "name is required");
        final DataDict existed = dataDictRepository.findByNameAndValue(entity.getName(), entity.getValue());
        if (existed != null) {
            throw new DataDictExistsException("The DataDict has already existed");
        }

        result = dataDictRepository.save(entity);
        cache.put(result);
        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    public void delete(final Long id) {
        Optional<DataDict> optional = dataDictRepository.findById(id);
        if (!optional.isPresent()) {
            dataDictRepository.delete(optional.get());
            cache.evict(optional.get());
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    public void imports(final InputStream inputStream) throws IOException {
        final DataDicts dataDicts = (DataDicts) jaxb2Marshaller.unmarshal(new StreamSource(inputStream));

        for (final DataDict dict : dataDicts.getDataDicts()) {
            LOG.debug("importing data dict with name \"{}\", text \"{}\" and value \"{}\"",
                    dict.getName(), dict.getText(), dict.getValue());
            final DataDict existOne = dataDictRepository.findByNameAndValue(dict.getName(), dict.getValue());
            if (existOne == null) {
                DataDict result = dataDictRepository.save(dict);
                cache.put(result);
                continue;
            }

            existOne.setText(dict.getText());
            existOne.setDescription(dict.getDescription());
            final DataDict result = dataDictRepository.save(existOne);

            cache.put(result);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Path exports() throws IOException {
        final String fileName = properties.getExportFileNamePrefix() + LocalDate.now() + FileType.DOT_XML;

        final Path exportFileLocation = properties.getExportFileLocation();
        if (!Files.exists(exportFileLocation)) {
            Files.createDirectories(exportFileLocation);
        }

        final Path result = Paths.get(exportFileLocation + File.separator + fileName);
        try (final FileWriter writer = new FileWriter(result.toFile())) {
            final List<DataDict> dataDicts = dataDictRepository.findAll();
            jaxb2Marshaller.marshal(new DataDicts(dataDicts), new StreamResult(writer));
        }

        return result;
    }


    /**
     * Gets the cached key.
     *
     * @param name   name
     * @param locale locale
     * @return the caching key
     */
    private static String getCachedKey(final String name, final Locale locale) {
        return name + "_" + locale.toString();
    }

    private static interface DataDictCache {
        /**
         * Initialize the cache.
         *
         * @param key       the caching key
         * @param dataDicts list of data dict for the key
         */
        void initialize(String key, List<DataDict> dataDicts);

        /**
         * Puts to the cache.
         *
         * @param dataDict data dict
         */
        void put(DataDict dataDict);

        /**
         * Evicts from the cache.
         *
         * @param dataDict data dict
         */
        void evict(DataDict dataDict);

        /**
         * Gets from cache.
         *
         * @param name   actual name
         * @param locale locale
         * @return list of data dict
         */
        List<DataDict> get(String name, Locale locale);
    }

    @SuppressWarnings({"unchecked"})
    private static class DefaultDataDictCache implements DataDictCache {
        private static final String CACHE_NAME = "dicts";

        private final ConcurrentMapCache cache = new ConcurrentMapCache(CACHE_NAME, false);

        /**
         * {@inheritDoc}
         */
        @Override
        public void initialize(final String key, final List<DataDict> dicts) {
            cache.put(key, dicts);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void put(final DataDict entity) {
            final Cache.ValueWrapper wrapper = cache.get(entity.getName());
            if (wrapper == null) {
                final List<DataDict> dicts = new ArrayList<>();
                dicts.add(entity);
                cache.put(entity.getName(), dicts);
            } else {
                final List<DataDict> dicts = (List<DataDict>) wrapper.get();
                dicts.removeIf(new DataDictEqualsPredicate(entity));
                dicts.add(entity);
            }
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void evict(final DataDict entity) {
            final Cache.ValueWrapper wrapper = cache.get(entity.getName());
            if (wrapper != null) {
                final List<DataDict> dicts = (List<DataDict>) wrapper.get();
                dicts.removeIf(new DataDictEqualsPredicate(entity));
            }
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public List<DataDict> get(final String name, final Locale locale) {
            List<DataDict> results = new ArrayList<>();

            Cache.ValueWrapper wrapper = cache.get(getCachedKey(name, locale));
            if (wrapper != null) {
                results = (List<DataDict>) wrapper.get();
            } else {// fall back to name
                wrapper = cache.get(name);
                if (wrapper != null) {
                    results = (List<DataDict>) wrapper.get();
                }
            }

            return results;
        }
    }

    private static class DataDictEqualsPredicate implements Predicate<DataDict> {
        private final DataDict dataDict;

        public DataDictEqualsPredicate(final DataDict dataDict) {
            this.dataDict = dataDict;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean test(final DataDict dict) {
            return Objects.equals(dataDict.getId(), dict.getId());
        }
    }
}
