package com.yqboots.menu.core;

/**
 * The exception thrown when the menu item exists.
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
public class MenuItemExistsException extends RuntimeException {
    /**
     * {@inheritDoc}
     */
    public MenuItemExistsException(final String message) {
        super(message);
    }
}
