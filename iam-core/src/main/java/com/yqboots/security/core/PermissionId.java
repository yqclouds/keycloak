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

import org.apache.commons.lang3.builder.ToStringBuilder;

import java.io.Serializable;

/**
 * PermissionId
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public class PermissionId implements Serializable {
    private String securityIdentity;

    private long objectIdIdentity;

    private String objectIdClass;

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

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        final PermissionId that = (PermissionId) o;

        if (mask != that.mask) return false;
        if (objectIdIdentity != that.objectIdIdentity) return false;
        if (objectIdClass != null ? !objectIdClass.equals(that.objectIdClass) : that.objectIdClass != null)
            return false;
        if (securityIdentity != null ? !securityIdentity.equals(that.securityIdentity) : that.securityIdentity != null)
            return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = securityIdentity != null ? securityIdentity.hashCode() : 0;
        result = 31 * result + (int) (objectIdIdentity ^ (objectIdIdentity >>> 32));
        result = 31 * result + (objectIdClass != null ? objectIdClass.hashCode() : 0);
        result = 31 * result + mask;
        return result;
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this)
                .append("securityIdentity", securityIdentity)
                .append("objectIdIdentity", objectIdIdentity)
                .append("objectIdClass", objectIdClass)
                .append("mask", mask)
                .toString();
    }
}
