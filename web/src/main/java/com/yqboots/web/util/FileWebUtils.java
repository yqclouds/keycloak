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
package com.yqboots.web.util;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Utility methods for web operations.
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
public class FileWebUtils {
    /**
     * Downloads the specified file with the specified media type.
     *
     * @param file      the file to operate
     * @param mediaType the media type of the file
     * @return bytes of the file
     * @throws IOException
     */
    public static HttpEntity<byte[]> downloadFile(Path file, MediaType mediaType) throws IOException {
        HttpHeaders header = new HttpHeaders();
        header.setContentType(mediaType);
        header.set("Content-Disposition", "attachment; filename=" + file.getFileName());
        header.setContentLength(Files.size(file));

        return new HttpEntity<>(Files.readAllBytes(file), header);
    }
}
