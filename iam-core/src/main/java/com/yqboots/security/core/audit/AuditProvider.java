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

import java.lang.reflect.Method;

/**
 * Audit Provider.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public interface AuditProvider {
    /**
     * Checks whether the provider supports the specified class.
     *
     * @param clazz the class
     * @return whether the provider supports the specified class
     */
    boolean supports(Class<?> clazz);

    /**
     * Invokes before the method execution.
     *
     * @param method    advised method
     * @param arguments arguments of the method
     */
    void beforeInvocation(Method method, Object[] arguments);

    /**
     * Invokes after the method execution.
     *
     * @param method    advised method
     * @param arguments arguments of the method
     * @param returnObj the return object of the method
     */
    void afterInvocation(Method method, Object[] arguments, Object returnObj);
}
