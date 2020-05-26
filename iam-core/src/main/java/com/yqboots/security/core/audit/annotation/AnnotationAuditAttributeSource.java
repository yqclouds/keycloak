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

import com.yqboots.security.core.audit.interceptor.AuditAttribute;
import com.yqboots.security.core.audit.interceptor.AuditAttributeSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

/**
 * Simple implementation of {@link AuditAttributeSource}
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
@SuppressWarnings("serial")
@Component
public class AnnotationAuditAttributeSource implements AuditAttributeSource, Serializable {
	private final AuditAnnotationParser auditAnnotationParser;

	/**
	 * {@inheritDoc}
	 */
	@Autowired
	public AnnotationAuditAttributeSource(AuditAnnotationParser auditAnnotationParser) {
		super();
		this.auditAnnotationParser = auditAnnotationParser;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public AuditAttribute getAuditAttribute(Method method) {
		if (!Modifier.isPublic(method.getModifiers())) {
			return null;
		}

		return this.auditAnnotationParser.parseAuditAnnotation(method);
	}
}
