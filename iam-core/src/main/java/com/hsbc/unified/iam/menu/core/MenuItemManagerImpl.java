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
package com.hsbc.unified.iam.menu.core;

import com.hsbc.unified.iam.core.util.DBUtils;
import com.hsbc.unified.iam.fss.core.support.FileType;
import com.hsbc.unified.iam.menu.autoconfigure.MenuItemProperties;
import com.hsbc.unified.iam.menu.core.repository.MenuItemRepository;
import org.apache.commons.lang3.StringUtils;
import org.springframework.cache.Cache;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;
import org.springframework.security.access.prepost.PostFilter;
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
import java.util.stream.Collectors;

/**
 * It Manages the MenuItem related functions.
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
@Transactional(readOnly = true)
public class MenuItemManagerImpl implements MenuItemManager {
    private static final String CACHE_NAME = "menus";

    private final MenuItemRepository menuItemRepository;

    private final MenuItemProperties properties;

    private final ConcurrentMapCache cache = new ConcurrentMapCache(CACHE_NAME, false);

    /**
     * For marshalling and unmarshalling Data Dictionaries.
     */
    private static Jaxb2Marshaller jaxb2Marshaller;

    static {
        jaxb2Marshaller = new Jaxb2Marshaller();
        jaxb2Marshaller.setClassesToBeBound(MenuItems.class, MenuItem.class);
    }

    @PostConstruct
    protected void initialize() {
        final List<MenuItem> menuItems = menuItemRepository.findAll();
        for (final MenuItem menuItem : menuItems) {
            cache.put(menuItem.getName(), menuItem);
        }
    }

    /**
     * Constructs the MenuItemManager.
     *
     * @param menuItemRepository MenuItemRepository
     * @param properties         MenuItemProperties
     */
    public MenuItemManagerImpl(final MenuItemRepository menuItemRepository, final MenuItemProperties properties) {
        this.menuItemRepository = menuItemRepository;
        this.properties = properties;
    }

    /**
     * {@inheritDoc}
     */
    @PostFilter("hasPermission(filterObject, 'READ')")
    @Override
    public List<MenuItem> getMenuItems() {
        final List<MenuItem> results = new ArrayList<>();

        final Map<Object, Object> nativeCache = cache.getNativeCache();
        results.addAll(nativeCache.values().stream().map(value -> (MenuItem) value).collect(Collectors.toList()));
        results.sort(new Comparator<MenuItem>() {
            @Override
            public int compare(final MenuItem o1, final MenuItem o2) {
                return o1.getSequentialOrder().compareTo(o2.getSequentialOrder());
            }
        });

        return results;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Page<MenuItem> getMenuItems(final String wildcardName, final Pageable pageable) {
        final String searchStr = StringUtils.trim(StringUtils.defaultString(wildcardName));
        return menuItemRepository.findByNameLikeIgnoreCaseOrderByName(DBUtils.wildcard(searchStr), pageable);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public MenuItem getMenuItem(final Long id) {
        return menuItemRepository.getOne(id);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public MenuItem getMenuItem(final String name) {
        final Cache.ValueWrapper wrapper = cache.get(name);
        if (wrapper != null) {
            return (MenuItem) wrapper.get();
        }

        return menuItemRepository.findByName(name);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    public MenuItem update(final MenuItem entity) {
        Assert.hasText(entity.getName(), "name is required");

        MenuItem result;
        if (!entity.isNew()) {
            result = menuItemRepository.save(entity);
        } else {
            final MenuItem existed = menuItemRepository.findByName(entity.getName());
            if (existed != null) {
                throw new MenuItemExistsException("The MenuItem has already existed");
            }

            result = menuItemRepository.save(entity);
        }

        cache.put(result.getName(), result);

        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    public void delete(final Long id) {
        final Optional<MenuItem> optional = menuItemRepository.findById(id);
        if (!optional.isPresent()) {
            MenuItem menuItem = optional.get();
            final String name = menuItem.getName();
            menuItemRepository.delete(menuItem);
            cache.evict(name);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    @Transactional
    public void imports(final InputStream inputStream) throws IOException {
        final MenuItems menuItems = (MenuItems) jaxb2Marshaller.unmarshal(new StreamSource(inputStream));
        if (menuItems == null) {
            return;
        }
        for (final MenuItem item : menuItems.getMenuItems()) {
            final MenuItem existOne = menuItemRepository.findByName(item.getName());
            if (existOne == null) {
                final MenuItem result = menuItemRepository.save(item);
                cache.put(result.getName(), result);
                continue;
            }

            existOne.setUrl(item.getUrl());
            existOne.setMenuGroup(item.getMenuGroup());
            existOne.setMenuItemGroup(item.getMenuItemGroup());
            final MenuItem result = menuItemRepository.save(existOne);
            cache.put(result.getName(), result);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Path exports() throws IOException {
        final String fileName = properties.getExportFileNamePrefix() + LocalDate.now() + FileType.DOT_XML;

        if (!Files.exists(properties.getExportFileLocation())) {
            Files.createDirectories(properties.getExportFileLocation());
        }

        final Path result = Paths.get(properties.getExportFileLocation() + File.separator + fileName);

        final List<MenuItem> menuItems = menuItemRepository.findAll();

        try (FileWriter writer = new FileWriter(result.toFile())) {
            jaxb2Marshaller.marshal(new MenuItems(menuItems), new StreamResult(writer));
        }

        return result;
    }
}
