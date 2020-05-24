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
package org.keycloak.transaction;

import org.keycloak.models.KeycloakTransaction;
import org.keycloak.provider.ExceptionConverter;
import org.keycloak.provider.ProviderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.transaction.RollbackException;
import javax.transaction.Status;
import javax.transaction.Transaction;
import javax.transaction.TransactionManager;
import java.util.List;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class JtaTransactionWrapper implements KeycloakTransaction {
    private static final Logger LOG = LoggerFactory.getLogger(JtaTransactionWrapper.class);
    protected TransactionManager tm;
    protected Transaction ut;
    protected Transaction suspended;
    protected Exception ended;

    public JtaTransactionWrapper(TransactionManager tm) {
        this.tm = tm;
        try {

            suspended = tm.suspend();
            LOG.debug("new JtaTransactionWrapper");
            LOG.debug("was existing? {}", suspended != null);
            tm.begin();
            ut = tm.getTransaction();
            //ended = new Exception();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Autowired
    private List<ExceptionConverter> exceptionConverters;

    public void handleException(Throwable e) {
        if (e instanceof RollbackException) {
            e = e.getCause() != null ? e.getCause() : e;
        }

        for (ProviderFactory factory : exceptionConverters) {
            ExceptionConverter converter = (ExceptionConverter) factory;
            Throwable throwable = converter.convert(e);
            if (throwable == null) continue;
            if (throwable instanceof RuntimeException) {
                throw (RuntimeException) throwable;
            } else {
                throw new RuntimeException(throwable);
            }
        }

        if (e instanceof RuntimeException) {
            throw (RuntimeException) e;
        } else {
            throw new RuntimeException(e);
        }


    }

    @Override
    public void begin() {
    }

    @Override
    public void commit() {
        try {
            LOG.debug("JtaTransactionWrapper  commit");
            tm.commit();
        } catch (Exception e) {
            handleException(e);
        } finally {
            end();
        }
    }

    @Override
    public void rollback() {
        try {
            LOG.debug("JtaTransactionWrapper rollback");
            tm.rollback();
        } catch (Exception e) {
            handleException(e);
        } finally {
            end();
        }

    }

    @Override
    public void setRollbackOnly() {
        try {
            tm.setRollbackOnly();
        } catch (Exception e) {
            handleException(e);
        }
    }

    @Override
    public boolean getRollbackOnly() {
        try {
            return tm.getStatus() == Status.STATUS_MARKED_ROLLBACK;
        } catch (Exception e) {
            handleException(e);
        }
        return false;
    }

    @Override
    public boolean isActive() {
        try {
            return tm.getStatus() == Status.STATUS_ACTIVE;
        } catch (Exception e) {
            handleException(e);
        }
        return false;
    }
    /*

    @Override
    protected void finalize() throws Throwable {
        if (ended != null) {
            LOG.error("TX didn't close at position", ended);
        }

    }
    */

    protected void end() {
        ended = null;
        LOG.debug("JtaTransactionWrapper end");
        if (suspended != null) {
            try {
                LOG.debug("JtaTransactionWrapper resuming suspended");
                tm.resume(suspended);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

    }
}
