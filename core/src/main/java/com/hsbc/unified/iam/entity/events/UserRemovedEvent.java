package com.hsbc.unified.iam.entity.events;

import lombok.Getter;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.springframework.context.ApplicationEvent;

public class UserRemovedEvent extends ApplicationEvent {
    @Getter
    private final RealmModel realm;
    @Getter
    private final UserModel user;

    /**
     * Create a new {@code ApplicationEvent}.
     *
     * @param source the object on which the event initially occurred or with
     *               which the event is associated (never {@code null})
     */
    public UserRemovedEvent(Object source, RealmModel realm, UserModel user) {
        super(source);
        this.realm = realm;
        this.user = user;
    }

    public RealmModel getRealm() {
        return realm;
    }

    public UserModel getUser() {
        return user;
    }
}
