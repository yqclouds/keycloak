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

package org.keycloak.keys.infinispan;

import org.keycloak.crypto.KeyWrapper;

import java.io.Serializable;
import java.util.Map;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class PublicKeysEntry implements Serializable {

    private final int lastRequestTime;

    private final Map<String, KeyWrapper> currentKeys;

    public PublicKeysEntry(int lastRequestTime, Map<String, KeyWrapper> currentKeys) {
        this.lastRequestTime = lastRequestTime;
        this.currentKeys = currentKeys;
    }

    public int getLastRequestTime() {
        return lastRequestTime;
    }

    public Map<String, KeyWrapper> getCurrentKeys() {
        return currentKeys;
    }
}
