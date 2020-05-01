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
import org.keycloak.stereotype.ProviderFactory;
import org.keycloak.timer.TimerProvider;
import org.keycloak.timer.TimerProviderFactory;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.util.Timer;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
@ProviderFactory(id = "basic", providerClasses = TimerProvider.class)
public class BasicTimerProviderFactory implements TimerProviderFactory {

    private Timer timer;

    private ConcurrentMap<String, TimerTaskContextImpl> scheduledTasks = new ConcurrentHashMap<>();

    @Override
    public TimerProvider create(KeycloakSession session) {
        return new BasicTimerProvider(session, timer, this);
    }

    @PostConstruct
    public void afterPropertiesSet() throws Exception {
        timer = new Timer();
    }

    @PreDestroy
    public void destroy() throws Exception {
        timer.cancel();
        timer = null;
    }

    @Override
    public String getId() {
        return "basic";
    }

    protected TimerTaskContextImpl putTask(String taskName, TimerTaskContextImpl task) {
        return scheduledTasks.put(taskName, task);
    }

    protected TimerTaskContextImpl removeTask(String taskName) {
        return scheduledTasks.remove(taskName);
    }
}
