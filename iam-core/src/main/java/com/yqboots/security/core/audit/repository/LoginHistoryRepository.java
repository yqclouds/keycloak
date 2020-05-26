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
package com.yqboots.security.core.audit.repository;

import com.yqboots.security.core.audit.LoginHistory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Repository for {@link LoginHistory}.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public interface LoginHistoryRepository extends JpaRepository<LoginHistory, Long> {
    /**
     * Finds by username.
     *
     * @param username username
     * @param pageable pageable
     * @return page of {@link LoginHistory}
     */
    Page<LoginHistory> findByUsername(String username, Pageable pageable);

    /**
     * Finds by session id.
     *
     * @param sessionId http session id
     * @return {@link LoginHistory}
     */
    LoginHistory findBySessionId(String sessionId);
}
