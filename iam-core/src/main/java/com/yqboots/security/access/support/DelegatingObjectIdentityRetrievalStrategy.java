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
package com.yqboots.security.access.support;

import org.apache.commons.collections.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.acls.domain.ObjectIdentityRetrievalStrategyImpl;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.ObjectIdentityGenerator;
import org.springframework.security.acls.model.ObjectIdentityRetrievalStrategy;

import java.io.Serializable;
import java.util.List;

/**
 * Delegates the retrieval strategy to others.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public class DelegatingObjectIdentityRetrievalStrategy implements ObjectIdentityRetrievalStrategy, ObjectIdentityGenerator {
    /**
     * The LOG.
     */
    private static final Logger LOG = LoggerFactory.getLogger(DelegatingObjectIdentityRetrievalStrategy.class);

    /**
     * Default ObjectIdentityRetrievalStrategy.
     */
    private ObjectIdentityRetrievalStrategy objectIdentityRetrievalStrategy = new ObjectIdentityRetrievalStrategyImpl();

    /**
     * Default ObjectIdentityGenerator
     */
    private ObjectIdentityGenerator objectIdentityGenerator = new ObjectIdentityRetrievalStrategyImpl();

    /**
     * List of ObjectIdentityRetrieval. If empty, use the default ObjectIdentityGenerator and ObjectIdentityRetrievalStrategy.
     */
    private List<ObjectIdentityRetrieval> objectIdentityRetrievals;

    /**
     * Constructs the DelegatingObjectIdentityRetrievalStrategy.
     *
     * @param objectIdentityRetrievals list of ObjectIdentityRetrieval
     */
    public DelegatingObjectIdentityRetrievalStrategy(final List<ObjectIdentityRetrieval> objectIdentityRetrievals) {
        this.objectIdentityRetrievals = objectIdentityRetrievals;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ObjectIdentity getObjectIdentity(final Object domainObject) {
        ObjectIdentity result = null;
        if (CollectionUtils.isNotEmpty(objectIdentityRetrievals)) {
            for (ObjectIdentityRetrieval retrieval : objectIdentityRetrievals) {
                if (retrieval.supports(domainObject.getClass())) {
                    result = retrieval.retrieve(domainObject);
                    break;
                }
            }
        } else {
            result = objectIdentityRetrievalStrategy.getObjectIdentity(domainObject);
        }

        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ObjectIdentity createObjectIdentity(final Serializable id, final String type) {
        ObjectIdentity result = null;
        if (CollectionUtils.isNotEmpty(objectIdentityRetrievals)) {
            try {
                Class<?> clazz = Class.forName(type);
                for (ObjectIdentityRetrieval retrieval : objectIdentityRetrievals) {
                    if (retrieval.supports(clazz)) {
                        result = retrieval.retrieve(id);
                        break;
                    }
                }
            } catch (ClassNotFoundException e) {
                LOG.error(type, e);
            }
        } else {
            result = objectIdentityGenerator.createObjectIdentity(id, type);
        }

        return result;
    }

    /**
     * Sets the ObjectIdentityRetrievalStrategy.
     *
     * @param objectIdentityRetrievalStrategy objectIdentityRetrievalStrategy
     */
    public void setObjectIdentityRetrievalStrategy(final ObjectIdentityRetrievalStrategy objectIdentityRetrievalStrategy) {
        this.objectIdentityRetrievalStrategy = objectIdentityRetrievalStrategy;
    }

    /**
     * Sets the ObjectIdentityGenerator.
     *
     * @param objectIdentityGenerator objectIdentityGenerator
     */
    public void setObjectIdentityGenerator(final ObjectIdentityGenerator objectIdentityGenerator) {
        this.objectIdentityGenerator = objectIdentityGenerator;
    }
}
