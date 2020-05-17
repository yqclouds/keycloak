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

package org.keycloak.timer.basic;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.scheduled.ScheduledTaskRunner;
import org.keycloak.timer.ScheduledTask;
import org.keycloak.timer.TimerProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Timer;
import java.util.TimerTask;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class BasicTimerProvider implements TimerProvider {

    private static final Logger LOG = LoggerFactory.getLogger(BasicTimerProvider.class);

    private final KeycloakSession session;
    private final Timer timer;
    private final BasicTimerProviderFactory factory;

    public BasicTimerProvider(KeycloakSession session, Timer timer, BasicTimerProviderFactory factory) {
        this.session = session;
        this.timer = timer;
        this.factory = factory;
    }

    @Override
    public void schedule(final Runnable runnable, final long intervalMillis, String taskName) {
        TimerTask task = new TimerTask() {
            @Override
            public void run() {
                runnable.run();
            }
        };

        TimerTaskContextImpl taskContext = new TimerTaskContextImpl(runnable, task, intervalMillis);
        TimerTaskContextImpl existingTask = factory.putTask(taskName, taskContext);
        if (existingTask != null) {
            LOG.debug("Existing timer task '{}' found. Cancelling it", taskName);
            existingTask.timerTask.cancel();
        }

        LOG.debug("Starting task '{}' with interval '{}'", taskName, intervalMillis);
        timer.schedule(task, intervalMillis, intervalMillis);
    }

    @Override
    public void scheduleTask(ScheduledTask scheduledTask, long intervalMillis, String taskName) {
        ScheduledTaskRunner scheduledTaskRunner = new ScheduledTaskRunner(session.getSessionFactory(), scheduledTask);
        this.schedule(scheduledTaskRunner, intervalMillis, taskName);
    }

    @Override
    public TimerTaskContext cancelTask(String taskName) {
        TimerTaskContextImpl existingTask = factory.removeTask(taskName);
        if (existingTask != null) {
            LOG.debug("Cancelling task '{}'", taskName);
            existingTask.timerTask.cancel();
        }

        return existingTask;
    }

    @Override
    public void close() {
        // do nothing
    }

}