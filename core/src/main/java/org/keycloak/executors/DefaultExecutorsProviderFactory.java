/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.executors;

import org.keycloak.Config;
import org.keycloak.stereotype.ProviderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.annotation.PreDestroy;
import javax.naming.InitialContext;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@Component("DefaultExecutorsProviderFactory")
@ProviderFactory(id = "default", providerClasses = ExecutorsProvider.class)
public class DefaultExecutorsProviderFactory implements ExecutorsProviderFactory {

    protected static final Logger LOG = LoggerFactory.getLogger(DefaultExecutorsProviderFactory.class);

    private static final int DEFAULT_MIN_THREADS = 4;
    private static final int DEFAULT_MAX_THREADS = 64;

    private static final String MANAGED_EXECUTORS_SERVICE_JNDI_PREFIX = "java:jboss/ee/concurrency/executor/";

    // Default executor is bound on Wildfly under this name
    private static final String DEFAULT_MANAGED_EXECUTORS_SERVICE_JNDI = MANAGED_EXECUTORS_SERVICE_JNDI_PREFIX + "default";
    private final Map<String, ExecutorService> executors = new ConcurrentHashMap<>();
    private Config.Scope config;
    private Boolean managed = null;

    @Override
    public ExecutorsProvider create() {
        return new ExecutorsProvider() {

            @Override
            public ExecutorService getExecutor(String taskType) {
                return DefaultExecutorsProviderFactory.this.getExecutor(taskType);
            }

            @Override
            public void close() {

            }
        };
    }

    @PreDestroy
    public void destroy() throws Exception {
        if (managed != null && !managed) {
            for (Map.Entry<String, ExecutorService> executor : executors.entrySet()) {
                LOG.debug("Shutting down executor for task '%s'", executor.getKey());
                executor.getValue().shutdown();
            }
        }
    }

    @Override
    public String getId() {
        return "default";
    }
    // IMPL

    protected ExecutorService getExecutor(String taskType) {
        ExecutorService existing = executors.get(taskType);

        if (existing == null) {
            synchronized (this) {
                if (!executors.containsKey(taskType)) {
                    ExecutorService executor = retrievePool(taskType);
                    executors.put(taskType, executor);
                }

                existing = executors.get(taskType);
            }
        }

        return existing;
    }


    protected ExecutorService retrievePool(String taskType) {
        if (managed == null) {
            detectManaged();
        }

        if (managed) {
            return getPoolManaged(taskType);
        } else {
            return createPoolEmbedded(taskType);
        }
    }

    protected void detectManaged() {
        String jndiName = MANAGED_EXECUTORS_SERVICE_JNDI_PREFIX + "default";
        try {
            new InitialContext().lookup(jndiName);
            LOG.debug("We are in managed environment. Executor '%s' was available.", jndiName);
            managed = true;
        } catch (NamingException nnfe) {
            LOG.debug("We are not in managed environment. Executor '%s' was not available.", jndiName);
            managed = false;
        }
    }


    protected ExecutorService getPoolManaged(String taskType) {
        try {
            InitialContext ctx = new InitialContext();

            // First check if specific pool for the task
            String jndiName = MANAGED_EXECUTORS_SERVICE_JNDI_PREFIX + taskType;
            try {
                ExecutorService executor = (ExecutorService) ctx.lookup(jndiName);
                LOG.debug("Found executor for '%s' under JNDI name '%s'", taskType, jndiName);
                return executor;
            } catch (NameNotFoundException nnfe) {
                LOG.debug("Not found executor for '%s' under specific JNDI name '%s'. Fallback to the default pool", taskType, jndiName);

                ExecutorService executor = (ExecutorService) ctx.lookup(DEFAULT_MANAGED_EXECUTORS_SERVICE_JNDI);
                LOG.debug("Found default executor for '%s' of JNDI name '%s'", taskType, DEFAULT_MANAGED_EXECUTORS_SERVICE_JNDI);
                return executor;
            }
        } catch (NamingException ne) {
            throw new IllegalStateException(ne);
        }
    }


    protected ExecutorService createPoolEmbedded(String taskType) {
        Config.Scope currentScope = config.scope(taskType);
        int min = DEFAULT_MIN_THREADS;
        int max = DEFAULT_MAX_THREADS;

        if (currentScope != null) {
            min = currentScope.getInt("min", DEFAULT_MIN_THREADS);
            max = currentScope.getInt("max", DEFAULT_MAX_THREADS);
        }

        LOG.debug("Creating pool for task '{}': min={}, max={}", taskType, min, max);

        ThreadFactory threadFactory = createThreadFactory(taskType);

        if (min == max) {
            return Executors.newFixedThreadPool(min, threadFactory);
        } else {
            // Same like Executors.newCachedThreadPool. Besides that "min" and "max" are configurable
            return new ThreadPoolExecutor(min, max,
                    60L, TimeUnit.SECONDS,
                    new SynchronousQueue<Runnable>(),
                    threadFactory);
        }
    }


    protected ThreadFactory createThreadFactory(String taskType) {
        return new ThreadFactory() {

            private AtomicInteger i = new AtomicInteger(0);
            private int group = new Random().nextInt(2048);

            @Override
            public Thread newThread(Runnable r) {
                int threadNumber = i.getAndIncrement();
                String threadName = "kc-" + taskType + "-" + group + "-" + threadNumber;

                if (LOG.isTraceEnabled()) {
                    LOG.trace("Creating thread: %s", threadName);
                }

                return new Thread(r, threadName);
            }

        };
    }

}
