package com.yqboots.dict.web.access;

/**
 * Permission constants for {@link com.yqboots.dict.core.DataDict}.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public abstract class DataDictPermissions {
    /**
     * READ permission expression.
     */
    public static final String READ = "hasPermission('/dict', 'com.yqboots.menu.core.MenuItem', 'READ')";

    /**
     * WRITE permission expression.
     */
    public static final String WRITE = "hasPermission('/dict', 'com.yqboots.menu.core.MenuItem', 'WRITE')";

    /**
     * CREATE permission expression.
     */
    public static final String CREATE = "hasPermission('/dict', 'com.yqboots.menu.core.MenuItem', 'CREATE')";

    /**
     * DELETE permission expression.
     */
    public static final String DELETE = "hasPermission('/dict', 'com.yqboots.menu.core.MenuItem', 'DELETE')";

    /**
     * ADMINISTRATION permission expression.
     */
    public static final String ADMINISTRATION = "hasPermission('/dict', 'com.yqboots.menu.core.MenuItem', 'ADMINISTRATION')";
}
