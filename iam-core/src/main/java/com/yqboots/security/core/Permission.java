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

import javax.persistence.*;
import java.io.Serializable;

/**
 * Permission entity.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
@SuppressWarnings("serial")
@Entity
@Table(name = "SEC_PERMISSIONS")
@IdClass(PermissionId.class)
public class Permission implements Serializable {
    @Id
    private String securityIdentity;

    @Id
    private long objectIdIdentity;

    @Id
    private String objectIdClass;

    @Id
    private int mask;

    public String getSecurityIdentity() {
        return securityIdentity;
    }

    public void setSecurityIdentity(final String securityIdentity) {
        this.securityIdentity = securityIdentity;
    }

    public long getObjectIdIdentity() {
        return objectIdIdentity;
    }

    public void setObjectIdIdentity(final long objectIdIdentity) {
        this.objectIdIdentity = objectIdIdentity;
    }

    public String getObjectIdClass() {
        return objectIdClass;
    }

    public void setObjectIdClass(final String objectIdClass) {
        this.objectIdClass = objectIdClass;
    }

    public int getMask() {
        return mask;
    }

    public void setMask(final int mask) {
        this.mask = mask;
    }
}
