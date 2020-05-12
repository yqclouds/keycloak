/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.core.entity;

import javax.persistence.*;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@Entity
@Table(name = "CLIENT_INITIAL_ACCESS")
@NamedQueries({
        @NamedQuery(name = "findClientInitialAccessByRealm", query = "select ia from ClientInitialAccess ia where ia.realm = :realm order by timestamp"),
        @NamedQuery(name = "removeClientInitialAccessByRealm", query = "delete from ClientInitialAccess ia where ia.realm = :realm"),
        @NamedQuery(name = "removeExpiredClientInitialAccess", query = "delete from ClientInitialAccess ia where (ia.expiration > 0 and (ia.timestamp + ia.expiration) < :currentTime) or ia.remainingCount = 0"),
        @NamedQuery(name = "decreaseClientInitialAccessRemainingCount", query = "update ClientInitialAccess ia set ia.remainingCount = ia.remainingCount - 1 where ia.id = :id")
})
public class ClientInitialAccess {

    @Id
    @Column(name = "ID", length = 36)
    @Access(AccessType.PROPERTY)
    // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    protected String id;
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "REALM_ID")
    protected Realm realm;
    @Column(name = "TIMESTAMP")
    private int timestamp;
    @Column(name = "EXPIRATION")
    private int expiration;
    @Column(name = "COUNT")
    private int count;
    @Column(name = "REMAINING_COUNT")
    private int remainingCount;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public int getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(int timestamp) {
        this.timestamp = timestamp;
    }

    public int getExpiration() {
        return expiration;
    }

    public void setExpiration(int expiration) {
        this.expiration = expiration;
    }

    public int getCount() {
        return count;
    }

    public void setCount(int count) {
        this.count = count;
    }

    public int getRemainingCount() {
        return remainingCount;
    }

    public void setRemainingCount(int remainingCount) {
        this.remainingCount = remainingCount;
    }

    public Realm getRealm() {
        return realm;
    }

    public void setRealm(Realm realm) {
        this.realm = realm;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (!(o instanceof ClientInitialAccess)) return false;

        ClientInitialAccess that = (ClientInitialAccess) o;

        if (!id.equals(that.id)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }
}
