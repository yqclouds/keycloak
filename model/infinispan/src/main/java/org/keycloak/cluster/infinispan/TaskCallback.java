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

package org.keycloak.cluster.infinispan;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
class TaskCallback {
    protected static final Logger LOG = LoggerFactory.getLogger(TaskCallback.class);

    static final int LATCH_TIMEOUT_MS = 10000;
    private final CountDownLatch taskCompletedLatch = new CountDownLatch(1);
    private final CountDownLatch futureAvailableLatch = new CountDownLatch(1);
    private volatile boolean success;
    private volatile Future<Boolean> future;

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public Future<Boolean> getFuture() {
        try {
            this.futureAvailableLatch.await(LATCH_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        } catch (InterruptedException ie) {
            LOG.error("Interrupted thread!");
            Thread.currentThread().interrupt();
        }

        return future;
    }

    public void setFuture(Future<Boolean> future) {
        this.future = future;
        this.futureAvailableLatch.countDown();
    }

    public CountDownLatch getTaskCompletedLatch() {
        return taskCompletedLatch;
    }
}
