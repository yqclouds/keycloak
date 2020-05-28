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
package com.hsbc.unified.iam.menu.security.access;

import com.hsbc.unified.iam.menu.core.MenuItem;
import com.hsbc.unified.iam.security.access.support.ObjectIdentityRetrieval;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.model.ObjectIdentity;

import java.io.Serializable;

/**
 * Retrieve {@link ObjectIdentity} for {@link MenuItem}
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public class MenuItemObjectIdentityRetrieval implements ObjectIdentityRetrieval {
    /**
     * {@inheritDoc}
     */
    @Override
    public boolean supports(final Class<?> domainObject) {
        return domainObject.isAssignableFrom(MenuItem.class);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ObjectIdentity retrieve(final Object domainObject) {
        MenuItem menuItem = (MenuItem) domainObject;
        return new ObjectIdentityImpl(MenuItem.class, (long) menuItem.getUrl().hashCode());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ObjectIdentity retrieve(final Serializable id) {
        return new ObjectIdentityImpl(MenuItem.class, (long) id.hashCode());
    }
}
