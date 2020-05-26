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
package com.yqboots.fss.util;

import com.yqboots.fss.core.support.FileType;
import org.apache.commons.lang3.StringUtils;
import org.springframework.util.Assert;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * The utility methods for file storage related functions.
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
public class ZipUtils {
    private static final int BUFFER = 2048;

    /**
     * Compresses the specified directory to a zip file
     *
     * @param dir the directory to compress
     * @return the compressed file
     * @throws IOException
     */
    public static Path compress(Path dir) throws IOException {
        Assert.isTrue(Files.exists(dir), "The directory does not exist: " + dir.toAbsolutePath());
        Assert.isTrue(Files.isDirectory(dir), "Should be a directory: " + dir.toAbsolutePath());

        Path result = Paths.get(dir.toAbsolutePath() + FileType.DOT_ZIP);
        try (final ZipOutputStream out = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(result.toFile())))) {
            // out.setMethod(ZipOutputStream.DEFLATED);
            final byte data[] = new byte[BUFFER];
            // get a list of files from current directory
            Files.walkFileTree(dir, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(final Path path, final BasicFileAttributes attrs) throws IOException {
                    final File file = path.toFile();

                    // compress to relative directory, not absolute
                    final String root = StringUtils.substringAfter(file.getParent(), dir.toString());
                    try (final BufferedInputStream origin = new BufferedInputStream(new FileInputStream(file), BUFFER)) {
                        final ZipEntry entry = new ZipEntry(root + File.separator + path.getFileName());
                        out.putNextEntry(entry);
                        int count;
                        while ((count = origin.read(data, 0, BUFFER)) != -1) {
                            out.write(data, 0, count);
                        }
                    }

                    return FileVisitResult.CONTINUE;
                }
            });
        }

        return result;
    }
}
