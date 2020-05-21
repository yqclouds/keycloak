package com.hsbc.unified.iam.entity.events;

import org.springframework.context.ApplicationEvent;

public class RealmPostCreateEvent extends ApplicationEvent {
    /**
     * Create a new {@code ApplicationEvent}.
     *
     * @param source the object on which the event initially occurred or with
     *               which the event is associated (never {@code null})
     */
    public RealmPostCreateEvent(Object source) {
        super(source);
    }
}
