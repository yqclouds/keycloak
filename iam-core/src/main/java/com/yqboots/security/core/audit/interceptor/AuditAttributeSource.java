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
package com.yqboots.security.core.audit.interceptor;

import java.lang.reflect.Method;

/**
 * Provides the attribute source for audit.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public interface AuditAttributeSource {
    /**
     * Gets audit attribute from advised method.
     *
     * @param method the method
     * @return audit attribute
     */
    AuditAttribute getAuditAttribute(Method method);
}
