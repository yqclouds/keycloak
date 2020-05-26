package com.yqboots.fss.web.access;

/**
 * Permission constants for {@link com.yqboots.fss.core.FileItem}.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public abstract class FileItemPermissions {
    /**
     * READ permission expression.
     */
    public static final String READ = "hasPermission('/fss', 'com.yqboots.menu.core.MenuItem', 'READ')";

    /**
     * WRITE permission expression.
     */
    public static final String WRITE = "hasPermission('/fss', 'com.yqboots.menu.core.MenuItem', 'WRITE')";

    /**
     * CREATE permission expression.
     */
    public static final String CREATE = "hasPermission('/fss', 'com.yqboots.menu.core.MenuItem', 'CREATE')";

    /**
     * DELETE permission expression.
     */
    public static final String DELETE = "hasPermission('/fss', 'com.yqboots.menu.core.MenuItem', 'DELETE')";

    /**
     * ADMINISTRATION permission expression.
     */
    public static final String ADMINISTRATION = "hasPermission('/fss', 'com.yqboots.menu.core.MenuItem', 'ADMINISTRATION')";
}
