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

package org.keycloak.events.jpa;

import org.keycloak.events.EventModel;
import org.keycloak.events.EventQuery;
import org.keycloak.events.EventType;
import org.springframework.beans.factory.annotation.Autowired;

import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class JpaEventQuery implements EventQuery {

    @Autowired
    private EntityManager em;
    private final CriteriaBuilder cb;
    private final CriteriaQuery<Event> cq;
    private final Root<Event> root;
    private final ArrayList<Predicate> predicates;
    private Integer firstResult;
    private Integer maxResults;

    public JpaEventQuery() {
        cb = em.getCriteriaBuilder();
        cq = cb.createQuery(Event.class);
        root = cq.from(Event.class);
        predicates = new ArrayList<>(4);
    }

    @Override
    public EventQuery type(EventType... types) {
        List<String> eventStrings = new LinkedList<>();
        for (EventType e : types) {
            eventStrings.add(e.toString());
        }
        predicates.add(root.get("type").in(eventStrings));
        return this;
    }

    @Override
    public EventQuery realm(String realmId) {
        predicates.add(cb.equal(root.get("realmId"), realmId));
        return this;
    }

    @Override
    public EventQuery client(String clientId) {
        predicates.add(cb.equal(root.get("clientId"), clientId));
        return this;
    }

    @Override
    public EventQuery user(String userId) {
        predicates.add(cb.equal(root.get("userId"), userId));
        return this;
    }

    @Override
    public EventQuery fromDate(Date fromDate) {
        predicates.add(cb.greaterThanOrEqualTo(root.get("time"), fromDate.getTime()));
        return this;
    }

    @Override
    public EventQuery toDate(Date toDate) {
        predicates.add(cb.lessThanOrEqualTo(root.get("time"), toDate.getTime()));
        return this;
    }

    @Override
    public EventQuery ipAddress(String ipAddress) {
        predicates.add(cb.equal(root.get("ipAddress"), ipAddress));
        return this;
    }

    @Override
    public EventQuery firstResult(int firstResult) {
        this.firstResult = firstResult;
        return this;
    }

    @Override
    public EventQuery maxResults(int maxResults) {
        this.maxResults = maxResults;
        return this;
    }

    @Override
    public List<EventModel> getResultList() {
        if (!predicates.isEmpty()) {
            cq.where(cb.and(predicates.toArray(new Predicate[0])));
        }

        cq.orderBy(cb.desc(root.get("time")));

        TypedQuery<Event> query = em.createQuery(cq);

        if (firstResult != null) {
            query.setFirstResult(firstResult);
        }

        if (maxResults != null) {
            query.setMaxResults(maxResults);
        }

        List<EventModel> events = new LinkedList<>();
        for (Event e : query.getResultList()) {
            events.add(JpaEventStoreProvider.convertEvent(e));
        }

        return events;
    }

}
