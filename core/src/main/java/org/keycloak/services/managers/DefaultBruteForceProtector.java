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
package org.keycloak.services.managers;


import com.hsbc.unified.iam.common.ClientConnection;
import com.hsbc.unified.iam.common.util.Time;
import org.keycloak.models.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * A single thread will log failures.  This is so that we can avoid concurrent writes as we want an accurate failure count
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@Component
public class DefaultBruteForceProtector implements Runnable, BruteForceProtector {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultBruteForceProtector.class);

    public static final int TRANSACTION_SIZE = 20;
    protected volatile boolean run = true;
    protected int maxDeltaTimeSeconds = 60 * 60 * 12; // 12 hours
    protected KeycloakSessionFactory factory;
    protected CountDownLatch shutdownLatch = new CountDownLatch(1);
    protected volatile long failures;
    protected volatile long lastFailure;
    protected volatile long totalTime;
    protected LinkedBlockingQueue<LoginEvent> queue = new LinkedBlockingQueue<LoginEvent>();

    public DefaultBruteForceProtector(@Autowired KeycloakSessionFactory factory) {
        this.factory = factory;
    }

    @PostConstruct
    public void afterPropertiesSet() throws Exception {
        this.start();
    }

    @PreDestroy
    public void destroy() throws Exception {
        this.shutdown();
    }

    public void failure(KeycloakSession session, LoginEvent event) {
        LOG.debug("failure");
        RealmModel realm = getRealmModel(session, event);
        logFailure(event);

        String userId = event.userId;
        UserModel user = session.users().getUserById(userId, realm);
        if (user == null) {
            return;
        }

        UserLoginFailureModel userLoginFailure = getUserModel(session, event);
        if (userLoginFailure == null) {
            userLoginFailure = session.sessions().addUserLoginFailure(realm, userId);
        }
        userLoginFailure.setLastIPFailure(event.ip);
        long currentTime = Time.currentTimeMillis();
        long last = userLoginFailure.getLastFailure();
        long deltaTime = 0;
        if (last > 0) {
            deltaTime = currentTime - last;
        }
        userLoginFailure.setLastFailure(currentTime);

        if (realm.isPermanentLockout()) {
            userLoginFailure.incrementFailures();
            LOG.debug("new num failures: {}", userLoginFailure.getNumFailures());

            if (userLoginFailure.getNumFailures() == realm.getFailureFactor()) {
                LOG.debug("user {} locked permanently due to too many login attempts", user.getUsername());
                user.setEnabled(false);
                return;
            }

            if (last > 0 && deltaTime < realm.getQuickLoginCheckMilliSeconds()) {
                LOG.debug("quick login, set min wait seconds");
                int waitSeconds = realm.getMinimumQuickLoginWaitSeconds();
                int notBefore = (int) (currentTime / 1000) + waitSeconds;
                LOG.debug("set notBefore: {}", notBefore);
                userLoginFailure.setFailedLoginNotBefore(notBefore);
            }
            return;
        }

        if (deltaTime > 0) {
            // if last failure was more than MAX_DELTA clear failures
            if (deltaTime > (long) realm.getMaxDeltaTimeSeconds() * 1000L) {
                userLoginFailure.clearFailures();
            }
        }
        userLoginFailure.incrementFailures();
        LOG.debug("new num failures: {}", userLoginFailure.getNumFailures());

        int waitSeconds = realm.getWaitIncrementSeconds() * (userLoginFailure.getNumFailures() / realm.getFailureFactor());
        LOG.debug("waitSeconds: {}", waitSeconds);
        LOG.debug("deltaTime: {}", deltaTime);

        if (waitSeconds == 0) {
            if (last > 0 && deltaTime < realm.getQuickLoginCheckMilliSeconds()) {
                LOG.debug("quick login, set min wait seconds");
                waitSeconds = realm.getMinimumQuickLoginWaitSeconds();
            }
        }
        if (waitSeconds > 0) {
            waitSeconds = Math.min(realm.getMaxFailureWaitSeconds(), waitSeconds);
            int notBefore = (int) (currentTime / 1000) + waitSeconds;
            LOG.debug("set notBefore: {}", notBefore);
            userLoginFailure.setFailedLoginNotBefore(notBefore);
        }
    }

    protected UserLoginFailureModel getUserModel(KeycloakSession session, LoginEvent event) {
        RealmModel realm = getRealmModel(session, event);
        if (realm == null) return null;
        UserLoginFailureModel user = session.sessions().getUserLoginFailure(realm, event.userId);
        if (user == null) return null;
        return user;
    }

    protected RealmModel getRealmModel(KeycloakSession session, LoginEvent event) {
        RealmModel realm = session.realms().getRealm(event.realmId);
        if (realm == null) return null;
        return realm;
    }

    public void start() {
        new Thread(this, "Brute Force Protector").start();
    }

    public void shutdown() {
        run = false;
        try {
            queue.offer(new ShutdownEvent());
            shutdownLatch.await(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    public void run() {
        final ArrayList<LoginEvent> events = new ArrayList<LoginEvent>(TRANSACTION_SIZE + 1);
        try {
            while (run) {
                try {
                    LoginEvent take = queue.poll(2, TimeUnit.SECONDS);
                    if (take == null) {
                        continue;
                    }
                    try {
                        events.add(take);
                        queue.drainTo(events, TRANSACTION_SIZE);
                        Collections.sort(events); // we sort to avoid deadlock due to ordered updates.  Maybe I'm overthinking this.
                        KeycloakSession session = factory.create();
                        session.getTransactionManager().begin();
                        try {
                            for (LoginEvent event : events) {
                                if (event instanceof FailedLogin) {
                                    failure(session, event);
                                } else if (event instanceof SuccessfulLogin) {
                                    success(session, event);
                                } else if (event instanceof ShutdownEvent) {
                                    run = false;
                                }
                            }
                            session.getTransactionManager().commit();
                        } catch (Exception e) {
                            session.getTransactionManager().rollback();
                            throw e;
                        } finally {
                            for (LoginEvent event : events) {
                                if (event instanceof FailedLogin) {
                                    ((FailedLogin) event).latch.countDown();
                                } else if (event instanceof SuccessfulLogin) {
                                    ((SuccessfulLogin) event).latch.countDown();
                                }
                            }
                            events.clear();
                            session.close();
                        }
                    } catch (Exception e) {
//                        ServicesLogger.LOGGER.failedProcessingType(e);
                    }
                } catch (InterruptedException e) {
                    break;
                }
            }
        } finally {
            shutdownLatch.countDown();
        }
    }

    private void success(KeycloakSession session, LoginEvent event) {
        String userId = event.userId;
        UserModel model = session.users().getUserById(userId, getRealmModel(session, event));

        UserLoginFailureModel user = getUserModel(session, event);
        if (user == null) return;

        LOG.debug("user {} successfully logged in, clearing all failures", model.getUsername());
        user.clearFailures();
    }

    protected void logFailure(LoginEvent event) {
//        ServicesLogger.LOGGER.loginFailure(event.userId, event.ip);
        failures++;
        long delta = 0;
        if (lastFailure > 0) {
            delta = Time.currentTimeMillis() - lastFailure;
            if (delta > (long) maxDeltaTimeSeconds * 1000L) {
                totalTime = 0;

            } else {
                totalTime += delta;
            }
        }
    }

    @Override
    public void failedLogin(RealmModel realm, UserModel user, ClientConnection clientConnection) {
        try {
            FailedLogin event = new FailedLogin(realm.getId(), user.getId(), clientConnection.getRemoteAddr());
            queue.offer(event);
            // wait a minimum of seconds for type to process so that a hacker
            // cannot flood with failed logins and overwhelm the queue and not have notBefore updated to block next requests
            // todo failure HTTP responses should be queued via async HTTP
            event.latch.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
        }
        LOG.trace("sent failure event");
    }

    @Override
    public void successfulLogin(final RealmModel realm, final UserModel user, final ClientConnection clientConnection) {
        try {
            SuccessfulLogin event = new SuccessfulLogin(realm.getId(), user.getId(), clientConnection.getRemoteAddr());
            queue.offer(event);

            event.latch.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
        }
        LOG.trace("sent success event");
    }

    @Override
    public boolean isTemporarilyDisabled(KeycloakSession session, RealmModel realm, UserModel user) {
        UserLoginFailureModel failure = session.sessions().getUserLoginFailure(realm, user.getId());

        if (failure != null) {
            int currTime = (int) (Time.currentTimeMillis() / 1000);
            int failedLoginNotBefore = failure.getFailedLoginNotBefore();
            if (currTime < failedLoginNotBefore) {
                LOG.debug("Current: {} notBefore: {}", currTime, failedLoginNotBefore);
                return true;
            }
        }


        return false;
    }

    @Override
    public void close() {

    }

    protected abstract class LoginEvent implements Comparable<LoginEvent> {
        protected final String realmId;
        protected final String userId;
        protected final String ip;

        protected LoginEvent(String realmId, String userId, String ip) {
            this.realmId = realmId;
            this.userId = userId;
            this.ip = ip;
        }

        @Override
        public int compareTo(LoginEvent o) {
            return userId.compareTo(o.userId);
        }
    }

    protected class ShutdownEvent extends LoginEvent {
        public ShutdownEvent() {
            super(null, null, null);
        }
    }

    protected class FailedLogin extends LoginEvent {
        protected final CountDownLatch latch = new CountDownLatch(1);

        public FailedLogin(String realmId, String userId, String ip) {
            super(realmId, userId, ip);
        }
    }

    protected class SuccessfulLogin extends LoginEvent {
        protected final CountDownLatch latch = new CountDownLatch(1);

        public SuccessfulLogin(String realmId, String userId, String ip) {
            super(realmId, userId, ip);
        }
    }
}
