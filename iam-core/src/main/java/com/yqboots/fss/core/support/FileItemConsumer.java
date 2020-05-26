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
package com.yqboots.fss.core.support;

import com.yqboots.fss.core.FileItem;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.function.Consumer;

/**
 * The Consumer for FileItem, to consume the Path.
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
public final class FileItemConsumer implements Consumer<Path> {
    /**
     * the root path.
     */
    private final Path root;

    /**
     * the list to append the consumed item.
     */
    private List<FileItem> items = new ArrayList<>();

    /**
     * Constructs the FileItemConsumer
     *
     * @param root  the root path
     * @param items the list to append the consumed item
     */
    public FileItemConsumer(final Path root, final List<FileItem> items) {
        this.root = root;
        this.items = items;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void accept(final Path path) {
        final File file = path.toFile();
        final FileItem item = new FileItem();
        item.setName(file.getName());

        String relativePath = StringUtils.substringAfter(file.getPath(), root.toString());
        item.setPath(relativePath.replace("\\", "/"));
        item.setLength(file.length());
        item.setLastModifiedDate(LocalDateTime.ofInstant(new Date(file.lastModified()).toInstant(),
                ZoneId.systemDefault()));
        items.add(item);
    }
}
