package com.yqboots.security.context;

import org.springframework.context.ApplicationEvent;

/**
 * Event happened when removing user.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public class UserRemovedEvent extends ApplicationEvent {
    private final String username;

    public UserRemovedEvent(final Object source, String username) {
        super(source);
        this.username = username;
    }

    public String getUsername() {
        return username;
    }
}
