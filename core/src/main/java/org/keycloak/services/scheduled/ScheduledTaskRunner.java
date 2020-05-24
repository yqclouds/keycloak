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

package org.keycloak.services.scheduled;

import org.keycloak.timer.ScheduledTask;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class ScheduledTaskRunner implements Runnable {

    private static final Logger LOG = LoggerFactory.getLogger(ScheduledTaskRunner.class);

    protected final ScheduledTask task;

    public ScheduledTaskRunner(ScheduledTask task) {
        this.task = task;
    }

    @Override
    public void run() {
        runTask();
    }

    protected void runTask() {
        LOG.debug("Executed scheduled task " + task.getClass().getSimpleName());
    }

}
