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
package com.yqboots.menu.web.form;

import com.yqboots.fss.core.support.FileType;
import com.yqboots.web.support.WebKeys;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;
import org.springframework.web.multipart.MultipartFile;

/**
 * Validates the FileUploadForm.
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
public class FileUploadFormValidator implements Validator {
    /**
     * {@inheritDoc}
     */
    @Override
    public boolean supports(final Class<?> clazz) {
        return FileUploadForm.class.equals(clazz);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void validate(final Object target, final Errors errors) {
        final MultipartFile file = ((FileUploadForm) target).getFile();
        if (file.isEmpty()) {
            errors.rejectValue(WebKeys.FILE, "I0002");
            return;
        }

        if (!file.getOriginalFilename().endsWith(FileType.DOT_XML)) {
            errors.rejectValue(WebKeys.FILE, "I0003");
        }
    }
}
