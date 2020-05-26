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

import com.yqboots.security.core.audit.AuditProvider;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Interceptor which intercepts the auditable method.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
@SuppressWarnings("serial")
@Component
public class AuditInterceptor implements MethodInterceptor, Serializable {
    /**
     * List of {@link AuditProvider}, defaults to empty.
     */
    private List<AuditProvider> auditProviders = new ArrayList<>();

    /**
     * Constructs the audit interceptor.
     *
     * @param auditProviders audit providers
     */
    @Autowired
    public AuditInterceptor(List<AuditProvider> auditProviders) {
        super();
        this.auditProviders = auditProviders;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Object invoke(MethodInvocation invocation) throws Throwable {
        Object returnObj = null;

        boolean found = false;

        for (AuditProvider auditProvider : auditProviders) {
            if (auditProvider.supports(invocation.getMethod().getDeclaringClass())) {
                found = true;

                final Object[] arguments = invocation.getArguments();

                auditProvider.beforeInvocation(invocation.getMethod(), arguments);

                returnObj = invocation.proceed();

                auditProvider.afterInvocation(invocation.getMethod(), arguments, returnObj);

                break;
            }
        }

        if (!found) {
            returnObj = invocation.proceed();
        }

        return returnObj;
    }
}
