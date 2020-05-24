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

import com.hsbc.unified.iam.core.util.Time;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.UserStorageProviderFactory;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.user.ImportSynchronization;
import org.keycloak.storage.user.SynchronizationResult;
import org.keycloak.timer.TimerProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class UserStorageSyncManager {

    private static final String USER_STORAGE_TASK_KEY = "user-storage";

    private static final Logger LOG = LoggerFactory.getLogger(UserStorageSyncManager.class);

    @Autowired
    private RealmProvider realmProvider;
    @Autowired
    private Map<String, UserStorageProviderFactory> userStorageProviderFactories;

    /**
     * Check federationProviderModel of all realms and possibly start periodic sync for them
     *
     * @param timer
     */
    public void bootstrapPeriodic(final TimerProvider timer) {
        List<RealmModel> realms = realmProvider.getRealmsWithProviderType(UserStorageProvider.class);
        for (final RealmModel realm : realms) {
            List<UserStorageProviderModel> providers = realm.getUserStorageProviders();
            for (final UserStorageProviderModel provider : providers) {
                UserStorageProviderFactory factory = userStorageProviderFactories.get(provider.getProviderId());
                if (factory instanceof ImportSynchronization && provider.isImportEnabled()) {
                    refreshPeriodicSyncForProvider(timer, provider, realm.getId());
                }
            }
        }
    }

    public SynchronizationResult syncAllUsers(final String realmId, final UserStorageProviderModel provider) {
        UserStorageProviderFactory factory = userStorageProviderFactories.get(provider.getProviderId());
        if (!(factory instanceof ImportSynchronization) || !provider.isImportEnabled() || !provider.isEnabled()) {
            return SynchronizationResult.ignored();
        }

        return SynchronizationResult.ignored();
    }

    public SynchronizationResult syncChangedUsers(final String realmId, final UserStorageProviderModel provider) {
        UserStorageProviderFactory factory = userStorageProviderFactories.get(provider.getProviderId());
        if (!(factory instanceof ImportSynchronization) || !provider.isImportEnabled() || !provider.isEnabled()) {
            return SynchronizationResult.ignored();
        }

        return SynchronizationResult.ignored();
    }

    @Autowired
    private UserStorageProviderFactory userStorageProviderFactory;

    // Ensure all cluster nodes are notified
    public void notifyToRefreshPeriodicSync(RealmModel realm, UserStorageProviderModel provider, boolean removed) {
        if (!(userStorageProviderFactory instanceof ImportSynchronization) || !provider.isImportEnabled()) {
            return;
        }
    }

    // Executed once it receives notification that some UserFederationProvider was created or updated
    protected void refreshPeriodicSyncForProvider(TimerProvider timer, final UserStorageProviderModel provider, final String realmId) {
        LOG.debug("Going to refresh periodic sync for provider '{}' . Full sync period: {} , changed users sync period: {}",
                provider.getName(), provider.getFullSyncPeriod(), provider.getChangedSyncPeriod());

        if (provider.getFullSyncPeriod() > 0) {
            // We want periodic full sync for this provider
            timer.schedule(new Runnable() {

                @Override
                public void run() {
                    try {
                        boolean shouldPerformSync = shouldPerformNewPeriodicSync(provider.getLastSync(), provider.getChangedSyncPeriod());
                        if (shouldPerformSync) {
                            syncAllUsers(realmId, provider);
                        } else {
                            LOG.debug("Ignored periodic full sync with storage provider {} due small time since last sync", provider.getName());
                        }
                    } catch (Throwable t) {
                        LOG.error("", t);
                    }
                }

            }, provider.getFullSyncPeriod() * 1000, provider.getId() + "-FULL");
        } else {
            timer.cancelTask(provider.getId() + "-FULL");
        }

        if (provider.getChangedSyncPeriod() > 0) {
            // We want periodic sync of just changed users for this provider
            timer.schedule(new Runnable() {

                @Override
                public void run() {
                    try {
                        boolean shouldPerformSync = shouldPerformNewPeriodicSync(provider.getLastSync(), provider.getChangedSyncPeriod());
                        if (shouldPerformSync) {
                            syncChangedUsers(realmId, provider);
                        } else {
                            LOG.debug("Ignored periodic changed-users sync with storage provider {} due small time since last sync", provider.getName());
                        }
                    } catch (Throwable t) {
                        LOG.error("", t);
                    }
                }

            }, provider.getChangedSyncPeriod() * 1000, provider.getId() + "-CHANGED");

        } else {
            timer.cancelTask(provider.getId() + "-CHANGED");
        }
    }

    // Skip syncing if there is short time since last sync time.
    private boolean shouldPerformNewPeriodicSync(int lastSyncTime, int period) {
        if (lastSyncTime <= 0) {
            return true;
        }

        int currentTime = Time.currentTime();
        int timeSinceLastSync = currentTime - lastSyncTime;

        return (timeSinceLastSync * 2 > period);
    }

    // Executed once it receives notification that some UserFederationProvider was removed
    protected void removePeriodicSyncForProvider(TimerProvider timer, UserStorageProviderModel fedProvider) {
        LOG.debug("Removing periodic sync for provider {}", fedProvider.getName());
        timer.cancelTask(fedProvider.getId() + "-FULL");
        timer.cancelTask(fedProvider.getId() + "-CHANGED");
    }

    // Update interval of last sync for given UserFederationProviderModel. Do it in separate transaction
    private void updateLastSyncInterval(UserStorageProviderModel provider, final String realmId) {
        RealmModel persistentRealm = realmProvider.getRealm(realmId);
        List<UserStorageProviderModel> persistentFedProviders = persistentRealm.getUserStorageProviders();
        for (UserStorageProviderModel persistentFedProvider : persistentFedProviders) {
            if (provider.getId().equals(persistentFedProvider.getId())) {
                // Update persistent provider in DB
                int lastSync = Time.currentTime();
                persistentFedProvider.setLastSync(lastSync);
                persistentRealm.updateComponent(persistentFedProvider);

                // Update "cached" reference
                provider.setLastSync(lastSync);
            }
        }
    }
}
