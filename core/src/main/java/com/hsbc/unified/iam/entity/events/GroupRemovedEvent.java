package com.hsbc.unified.iam.entity.events;

import lombok.Getter;
import org.keycloak.models.GroupModel;
import org.keycloak.models.RealmModel;
import org.springframework.context.ApplicationEvent;

public class GroupRemovedEvent extends ApplicationEvent {
    @Getter
    private final RealmModel realm;
    @Getter
    private final GroupModel group;

    /**
     * Create a new {@code ApplicationEvent}.
     *
     * @param source the object on which the event initially occurred or with
     *               which the event is associated (never {@code null})
     */
    public GroupRemovedEvent(Object source, RealmModel realm, GroupModel group) {
        super(source);
        this.realm = realm;
        this.group = group;
    }

    public RealmModel getRealm() {
        return realm;
    }

    public GroupModel getGroup() {
        return group;
    }
}
