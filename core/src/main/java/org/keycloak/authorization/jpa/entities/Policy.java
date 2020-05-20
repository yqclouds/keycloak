/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.authorization.jpa.entities;

import org.hibernate.annotations.Nationalized;
import org.keycloak.representations.idm.authorization.DecisionStrategy;
import org.keycloak.representations.idm.authorization.Logic;

import javax.persistence.*;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@Entity
@Table(name = "RESOURCE_SERVER_POLICY", uniqueConstraints = {
        @UniqueConstraint(columnNames = {"NAME", "RESOURCE_SERVER_ID"})
})
public class Policy {

    @Id
    @Column(name = "ID", length = 36)
    @Access(AccessType.PROPERTY)
    // we do this because relationships often fetch id, but not entity.  This avoids an extra SQL
    private String id;

    @Column(name = "NAME")
    private String name;

    @Nationalized
    @Column(name = "DESCRIPTION")
    private String description;

    @Column(name = "TYPE")
    private String type;

    @Column(name = "DECISION_STRATEGY")
    private DecisionStrategy decisionStrategy = DecisionStrategy.UNANIMOUS;

    @Column(name = "LOGIC")
    private Logic logic = Logic.POSITIVE;

    @ElementCollection(fetch = FetchType.LAZY)
    @MapKeyColumn(name = "NAME")
    @Column(name = "VALUE", columnDefinition = "TEXT")
    @CollectionTable(name = "POLICY_CONFIG", joinColumns = {@JoinColumn(name = "POLICY_ID")})
    private Map<String, String> config = new HashMap();

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "RESOURCE_SERVER_ID")
    private ResourceServer resourceServer;

    @OneToMany(fetch = FetchType.LAZY, cascade = {})
    @JoinTable(name = "ASSOCIATED_POLICY", joinColumns = @JoinColumn(name = "POLICY_ID"), inverseJoinColumns = @JoinColumn(name = "ASSOCIATED_POLICY_ID"))
    private Set<Policy> associatedPolicies = new HashSet<>();

    @OneToMany(fetch = FetchType.LAZY, cascade = {})
    @JoinTable(name = "RESOURCE_POLICY", joinColumns = @JoinColumn(name = "POLICY_ID"), inverseJoinColumns = @JoinColumn(name = "RESOURCE_ID"))
    private Set<Resource> resources = new HashSet<>();

    @OneToMany(fetch = FetchType.LAZY, cascade = {})
    @JoinTable(name = "SCOPE_POLICY", joinColumns = @JoinColumn(name = "POLICY_ID"), inverseJoinColumns = @JoinColumn(name = "SCOPE_ID"))
    private Set<Scope> scopes = new HashSet<>();

    @Column(name = "OWNER")
    private String owner;

    public String getId() {
        return this.id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getType() {
        return this.type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public DecisionStrategy getDecisionStrategy() {
        return this.decisionStrategy;
    }

    public void setDecisionStrategy(DecisionStrategy decisionStrategy) {
        this.decisionStrategy = decisionStrategy;
    }

    public Logic getLogic() {
        return this.logic;
    }

    public void setLogic(Logic logic) {
        this.logic = logic;
    }

    public Map<String, String> getConfig() {
        return this.config;
    }

    public void setConfig(Map<String, String> config) {
        this.config = config;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return this.description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public ResourceServer getResourceServer() {
        return this.resourceServer;
    }

    public void setResourceServer(ResourceServer resourceServer) {
        this.resourceServer = resourceServer;
    }

    public Set<Resource> getResources() {
        return this.resources;
    }

    public void setResources(Set<Resource> resources) {
        this.resources = resources;
    }

    public Set<Scope> getScopes() {
        return this.scopes;
    }

    public void setScopes(Set<Scope> scopes) {
        this.scopes = scopes;
    }

    public Set<Policy> getAssociatedPolicies() {
        return associatedPolicies;
    }

    public void setAssociatedPolicies(Set<Policy> associatedPolicies) {
        this.associatedPolicies = associatedPolicies;
    }

    public String getOwner() {
        return owner;
    }

    public void setOwner(String owner) {
        this.owner = owner;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Policy that = (Policy) o;

        return getId().equals(that.getId());
    }

    @Override
    public int hashCode() {
        return getId().hashCode();
    }
}
