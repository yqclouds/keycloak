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

/**
 * Ensures that there are not concurrent executions of same task (either on this host or any other cluster host)
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ClusterAwareScheduledTaskRunner extends ScheduledTaskRunner {
    private final int intervalSecs;

    public ClusterAwareScheduledTaskRunner(ScheduledTask task, long intervalMillis) {
        super(task);
        this.intervalSecs = (int) (intervalMillis / 1000);
    }

    @Override
    protected void runTask() {
        String taskKey = task.getClass().getSimpleName();
    }
}
