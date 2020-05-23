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

import org.keycloak.cluster.ClusterProvider;
import org.keycloak.cluster.ExecutionResult;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.timer.ScheduledTask;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.concurrent.Callable;

/**
 * Ensures that there are not concurrent executions of same task (either on this host or any other cluster host)
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ClusterAwareScheduledTaskRunner extends ScheduledTaskRunner {

    private static final Logger LOG = LoggerFactory.getLogger(ClusterAwareScheduledTaskRunner.class);

    private final int intervalSecs;

    public ClusterAwareScheduledTaskRunner(ScheduledTask task, long intervalMillis) {
        super(task);
        this.intervalSecs = (int) (intervalMillis / 1000);
    }

    @Autowired
    private ClusterProvider clusterProvider;

    @Override
    protected void runTask() {
        String taskKey = task.getClass().getSimpleName();
    }


}
