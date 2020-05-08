/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.storage.ldap.mappers;

import org.keycloak.models.AbstractKeycloakTransaction;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class LDAPTransaction extends AbstractKeycloakTransaction {
    public static final Logger LOG = LoggerFactory.getLogger(LDAPTransaction.class);

    private final LDAPStorageProvider ldapProvider;
    private final LDAPObject ldapUser;

    public LDAPTransaction(LDAPStorageProvider ldapProvider, LDAPObject ldapUser) {
        this.ldapProvider = ldapProvider;
        this.ldapUser = ldapUser;
    }


    @Override
    protected void commitImpl() {
        if (LOG.isTraceEnabled()) {
            LOG.trace("Transaction commit! Updating LDAP attributes for object " + ldapUser.getDn().toString() + ", attributes: " + ldapUser.getAttributes());
        }

        ldapProvider.getLdapIdentityStore().update(ldapUser);
    }


    @Override
    protected void rollbackImpl() {
        LOG.warn("Transaction rollback! Ignoring LDAP updates for object " + ldapUser.getDn().toString());
    }

}

