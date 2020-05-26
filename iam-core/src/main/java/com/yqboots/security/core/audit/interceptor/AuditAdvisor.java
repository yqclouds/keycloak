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

import org.aopalliance.aop.Advice;
import org.springframework.aop.Pointcut;
import org.springframework.aop.support.AbstractPointcutAdvisor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Pointcut advisor for audit.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
@SuppressWarnings("serial")
@Component
public class AuditAdvisor extends AbstractPointcutAdvisor {
    /**
     * Audit pointcut.
     */
    @Autowired
    private AuditPointcut pointcut;

    /**
     * Audit advice.
     */
    @Autowired
    private AuditInterceptor advice;

    /**
     * {@inheritDoc}
     */
    @Override
    public Pointcut getPointcut() {
        return this.pointcut;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Advice getAdvice() {
        return this.advice;
    }
}
