package com.hsbc.unified.iam.core.entity.events;

import org.springframework.context.ApplicationEvent;

public class GroupRemovedEvent extends ApplicationEvent {
    /**
     * Create a new {@code ApplicationEvent}.
     *
     * @param source the object on which the event initially occurred or with
     *               which the event is associated (never {@code null})
     */
    public GroupRemovedEvent(Object source) {
        super(source);
    }
}
