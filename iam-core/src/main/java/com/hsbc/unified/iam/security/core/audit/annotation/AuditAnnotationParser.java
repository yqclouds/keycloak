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
package com.hsbc.unified.iam.security.core.audit.annotation;

import com.hsbc.unified.iam.security.core.audit.interceptor.AuditAttribute;

import java.lang.reflect.AnnotatedElement;

/**
 * Audit annotation parser.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public interface AuditAnnotationParser {
    /**
     * Parses the audit annotation.
     *
     * @param annotatedElement annotated element
     * @return audit attribute
     */
    AuditAttribute parseAuditAnnotation(AnnotatedElement annotatedElement);
}