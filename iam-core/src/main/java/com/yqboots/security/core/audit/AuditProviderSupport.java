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
package com.yqboots.security.core.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Method;

/**
 * The wrapper class for {@link AuditProvider}.
 * <p>You can implement either of them or both, depending on your needs.</p>
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public abstract class AuditProviderSupport implements AuditProvider {
    /**
     * The LOGGER.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(AuditProviderSupport.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public void beforeInvocation(Method method, Object[] arguments) {
        LOGGER.debug(method.getName());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void afterInvocation(Method method, Object[] arguments, Object returnObj) {
        LOGGER.debug(method.getName());
    }
}
