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
package com.yqboots.security.core.audit.annotation;

import com.yqboots.security.core.audit.interceptor.AuditAttributeImpl;
import com.yqboots.security.core.audit.interceptor.AuditAttribute;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.stereotype.Component;

import java.lang.reflect.AnnotatedElement;

/**
 * Simple implementation of {@link AuditAnnotationParser}.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
@Component
public class AuditAnnotationParserImpl implements AuditAnnotationParser {
    /**
     * {@inheritDoc}
     */
    @Override
    public AuditAttribute parseAuditAnnotation(AnnotatedElement ae) {
        AuditAttribute result = null;

        final Auditable ann = AnnotationUtils.getAnnotation(ae, Auditable.class);
        if (ann != null) {
            result = parseAuditAnnotation(ann);
        }

        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        return HashCodeBuilder.reflectionHashCode(this);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(Object obj) {
        return EqualsBuilder.reflectionEquals(this, obj);
    }

    /**
     * Parses the audit annotation.
     *
     * @param annotation the annotation class
     * @return audit attribute
     */
    private AuditAttribute parseAuditAnnotation(Auditable annotation) {
        return new AuditAttributeImpl(annotation.code());
    }
}
