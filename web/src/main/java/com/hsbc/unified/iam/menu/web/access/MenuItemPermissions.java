package com.hsbc.unified.iam.menu.web.access;

import com.hsbc.unified.iam.menu.core.MenuItem;

/**
 * Permission constants for {@link MenuItem}.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public abstract class MenuItemPermissions {
    /**
     * READ permission expression.
     */
    public static final String READ = "hasPermission('/menu', 'MenuItem', 'READ')";

    /**
     * WRITE permission expression.
     */
    public static final String WRITE = "hasPermission('/menu', 'MenuItem', 'WRITE')";

    /**
     * CREATE permission expression.
     */
    public static final String CREATE = "hasPermission('/menu', 'MenuItem', 'CREATE')";

    /**
     * DELETE permission expression.
     */
    public static final String DELETE = "hasPermission('/menu', 'MenuItem', 'DELETE')";

    /**
     * ADMINISTRATION permission expression.
     */
    public static final String ADMINISTRATION = "hasPermission('/menu', 'MenuItem', 'ADMINISTRATION')";
}
