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
package org.keycloak.storage;

import com.hsbc.unified.iam.core.util.Time;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.PrioritizedComponentModel;

import java.util.Calendar;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class CacheableStorageProviderModel extends PrioritizedComponentModel {
    public static final String CACHE_POLICY = "cachePolicy";
    public static final String MAX_LIFESPAN = "maxLifespan";
    public static final String EVICTION_HOUR = "evictionHour";
    public static final String EVICTION_MINUTE = "evictionMinute";
    public static final String EVICTION_DAY = "evictionDay";
    public static final String CACHE_INVALID_BEFORE = "cacheInvalidBefore";
    public static final String ENABLED = "enabled";

    private transient CachePolicy cachePolicy;
    private transient long maxLifespan = -1;
    private transient int evictionHour = -1;
    private transient int evictionMinute = -1;
    private transient int evictionDay = -1;
    private transient long cacheInvalidBefore = -1;
    private transient Boolean enabled;

    public CacheableStorageProviderModel() {
    }

    public CacheableStorageProviderModel(ComponentModel copy) {
        super(copy);
    }

    public static long dailyTimeout(int hour, int minute) {
        Calendar cal = Calendar.getInstance();
        Calendar cal2 = Calendar.getInstance();
        cal.setTimeInMillis(Time.currentTimeMillis());
        cal2.setTimeInMillis(Time.currentTimeMillis());
        cal2.set(Calendar.HOUR_OF_DAY, hour);
        cal2.set(Calendar.MINUTE, minute);
        if (cal2.getTimeInMillis() < cal.getTimeInMillis()) {
            int add = (24 * 60 * 60 * 1000);
            cal.add(Calendar.MILLISECOND, add);
        } else {
            cal = cal2;
        }
        return cal.getTimeInMillis();
    }

    public static long weeklyTimeout(int day, int hour, int minute) {
        Calendar cal = Calendar.getInstance();
        Calendar cal2 = Calendar.getInstance();
        cal.setTimeInMillis(Time.currentTimeMillis());
        cal2.setTimeInMillis(Time.currentTimeMillis());
        cal2.set(Calendar.HOUR_OF_DAY, hour);
        cal2.set(Calendar.MINUTE, minute);
        cal2.set(Calendar.DAY_OF_WEEK, day);
        if (cal2.getTimeInMillis() < cal.getTimeInMillis()) {
            int add = (7 * 24 * 60 * 60 * 1000);
            cal2.add(Calendar.MILLISECOND, add);
        }

        return cal2.getTimeInMillis();
    }

    public CachePolicy getCachePolicy() {
        if (cachePolicy == null) {
            String str = getConfig().getFirst(CACHE_POLICY);
            if (str == null) return null;
            cachePolicy = CachePolicy.valueOf(str);
        }
        return cachePolicy;
    }

    public long getMaxLifespan() {
        if (maxLifespan < 0) {
            String str = getConfig().getFirst(MAX_LIFESPAN);
            if (str == null) return -1;
            maxLifespan = Long.valueOf(str);
        }
        return maxLifespan;
    }

    public int getEvictionHour() {
        if (evictionHour < 0) {
            String str = getConfig().getFirst(EVICTION_HOUR);
            if (str == null) return -1;
            evictionHour = Integer.valueOf(str);
        }
        return evictionHour;
    }

    public int getEvictionMinute() {
        if (evictionMinute < 0) {
            String str = getConfig().getFirst(EVICTION_MINUTE);
            if (str == null) return -1;
            evictionMinute = Integer.valueOf(str);
        }
        return evictionMinute;
    }

    public int getEvictionDay() {
        if (evictionDay < 0) {
            String str = getConfig().getFirst(EVICTION_DAY);
            if (str == null) return -1;
            evictionDay = Integer.valueOf(str);
        }
        return evictionDay;
    }

    public long getCacheInvalidBefore() {
        if (cacheInvalidBefore < 0) {
            String str = getConfig().getFirst(CACHE_INVALID_BEFORE);
            if (str == null) return -1;
            cacheInvalidBefore = Long.valueOf(str);
        }
        return cacheInvalidBefore;
    }

    public boolean isEnabled() {
        if (enabled == null) {
            String val = getConfig().getFirst(ENABLED);
            if (val == null) {
                enabled = true;
            } else {
                enabled = Boolean.valueOf(val);
            }
        }
        return enabled;

    }

    public void setEnabled(boolean flag) {
        enabled = flag;
        getConfig().putSingle(ENABLED, Boolean.toString(flag));
    }

    public long getLifespan() {
        UserStorageProviderModel.CachePolicy policy = getCachePolicy();
        long lifespan = -1;
        if (policy == null || policy == UserStorageProviderModel.CachePolicy.DEFAULT) {
            lifespan = -1;
        } else if (policy == CacheableStorageProviderModel.CachePolicy.EVICT_DAILY) {
            if (getEvictionHour() > -1 && getEvictionMinute() > -1) {
                lifespan = dailyTimeout(getEvictionHour(), getEvictionMinute()) - Time.currentTimeMillis();
            }
        } else if (policy == CacheableStorageProviderModel.CachePolicy.EVICT_WEEKLY) {
            if (getEvictionDay() > 0 && getEvictionHour() > -1 && getEvictionMinute() > -1) {
                lifespan = weeklyTimeout(getEvictionDay(), getEvictionHour(), getEvictionMinute()) - Time.currentTimeMillis();
            }
        } else if (policy == CacheableStorageProviderModel.CachePolicy.MAX_LIFESPAN) {
            lifespan = getMaxLifespan();
        }
        return lifespan;
    }

    public enum CachePolicy {
        NO_CACHE,
        DEFAULT,
        EVICT_DAILY,
        EVICT_WEEKLY,
        MAX_LIFESPAN
    }
}
