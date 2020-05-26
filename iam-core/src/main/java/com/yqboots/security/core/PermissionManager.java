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
package com.yqboots.security.core;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

/**
 * Permission Manager.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public interface PermissionManager {
    /**
     * Finds permissions.
     *
     * @param sidFilter wildcard securityIdentity
     * @param pageable  pageable
     * @return page of {@link Permission}
     */
    Page<Permission> findPermissions(String sidFilter, Pageable pageable);
}
