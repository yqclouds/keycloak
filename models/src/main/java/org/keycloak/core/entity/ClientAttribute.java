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
import java.io.Serializable;


/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
@Table(name = "CLIENT_ATTRIBUTES")
@Entity
@IdClass(ClientAttribute.Key.class)
public class ClientAttribute {
    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "CLIENT_ID")
    protected Client client;

    @Id
    @Column(name = "NAME")
    protected String name;

    @Column(name = "VALUE", length = 4000)
    protected String value;

    public Client getClient() {
        return client;
    }

    public void setClient(Client client) {
        this.client = client;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!(o instanceof ClientAttribute)) return false;

        ClientAttribute key = (ClientAttribute) o;

        if (client != null ? !client.getId().equals(key.client != null ? key.client.getId() : null) : key.client != null)
            return false;
        if (name != null ? !name.equals(key.name != null ? key.name : null) : key.name != null) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = client != null ? client.getId().hashCode() : 0;
        result = 31 * result + (name != null ? name.hashCode() : 0);
        return result;
    }

    public static class Key implements Serializable {

        protected Client client;

        protected String name;

        public Key() {
        }

        public Key(Client client, String name) {
            this.client = client;
            this.name = name;
        }

        public Client getClient() {
            return client;
        }

        public String getName() {
            return name;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            ClientAttribute.Key key = (ClientAttribute.Key) o;

            if (client != null ? !client.getId().equals(key.client != null ? key.client.getId() : null) : key.client != null)
                return false;
            if (name != null ? !name.equals(key.name != null ? key.name : null) : key.name != null) return false;

            return true;
        }

        @Override
        public int hashCode() {
            int result = client != null ? client.getId().hashCode() : 0;
            result = 31 * result + (name != null ? name.hashCode() : 0);
            return result;
        }
    }
}
