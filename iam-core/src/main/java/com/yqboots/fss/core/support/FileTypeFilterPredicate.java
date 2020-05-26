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

import org.apache.commons.lang3.StringUtils;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Predicate;

/**
 * The Predicate that filters files by file types.
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
public class FileTypeFilterPredicate implements Predicate<Path> {
    /**
     * the accepted file types.
     */
    private String[] acceptedFileTypes = new String[]{};

    /**
     * Constructs the FileTypeFilterPredicate.
     *
     * @param acceptedFileTypes the accepted file types
     */
    public FileTypeFilterPredicate(final String[] acceptedFileTypes) {
        this.acceptedFileTypes = acceptedFileTypes;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean test(final Path path) {
        if (!Files.isRegularFile(path)) {
            return false;
        }

        boolean result = false;
        for (final String fileType : acceptedFileTypes) {
            if (StringUtils.endsWith(path.getFileName().toString(), fileType)) {
                result = true;
                break;
            }
        }

        return result;
    }
}
