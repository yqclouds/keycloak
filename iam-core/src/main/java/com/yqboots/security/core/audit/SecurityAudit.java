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

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;

/**
 * Audit for security related entities.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
@SuppressWarnings("serial")
@Entity
@Table(name = "SEC_AUDIT")
public class SecurityAudit extends AbstractAudit {
    public static final int CODE_ADD_USER = 1;
    public static final int CODE_UPDATE_USER = 2;
    public static final int CODE_UPDATE_GROUPS_OF_USER = 20;
    public static final int CODE_UPDATE_ROLES_OF_USER = 21;
    public static final int CODE_REMOVE_USER = 3;
    public static final int CODE_REMOVE_GROUPS_FROM_USER = 30;
    public static final int CODE_REMOVE_ROLES_FROM_USER = 31;

    public static final int CODE_ADD_GROUP = 4;
    public static final int CODE_UPDATE_GROUP = 5;
    public static final int CODE_UPDATE_USERS_OF_GROUP = 50;
    public static final int CODE_UPDATE_ROLES_OF_GROUP = 51;
    public static final int CODE_REMOVE_GROUP = 6;
    public static final int CODE_REMOVE_USERS_FROM_GROUP = 60;
    public static final int CODE_REMOVE_ROLES_FROM_GROUP = 61;

    public static final int CODE_ADD_ROLE = 7;
    public static final int CODE_UPDATE_ROLE = 8;
    public static final int CODE_UPDATE_USERS_OF_ROLE = 80;
    public static final int CODE_UPDATE_GROUPS_OF_ROLE = 81;
    public static final int CODE_REMOVE_ROLE = 9;
    public static final int CODE_REMOVE_USERS_FROM_ROLE = 90;
    public static final int CODE_REMOVE_GROUPS_FROM_ROLE = 91;

    @Column(name = "TARGET", nullable = false)
    private String target;

    public SecurityAudit(int code) {
        super(code);
    }

    protected SecurityAudit() {
        super();
    }

    public String getTarget() {
        return target;
    }

    public void setTarget(String target) {
        this.target = target;
    }
}
