package com.yqboots.menu.web.access;

/**
 * Permission constants for {@link com.yqboots.menu.core.MenuItem}.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public abstract class MenuItemPermissions {
    /**
     * READ permission expression.
     */
    public static final String READ = "hasPermission('/menu', 'com.yqboots.menu.core.MenuItem', 'READ')";

    /**
     * WRITE permission expression.
     */
    public static final String WRITE = "hasPermission('/menu', 'com.yqboots.menu.core.MenuItem', 'WRITE')";

    /**
     * CREATE permission expression.
     */
    public static final String CREATE = "hasPermission('/menu', 'com.yqboots.menu.core.MenuItem', 'CREATE')";

    /**
     * DELETE permission expression.
     */
    public static final String DELETE = "hasPermission('/menu', 'com.yqboots.menu.core.MenuItem', 'DELETE')";

    /**
     * ADMINISTRATION permission expression.
     */
    public static final String ADMINISTRATION = "hasPermission('/menu', 'com.yqboots.menu.core.MenuItem', 'ADMINISTRATION')";
}
