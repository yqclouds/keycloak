package com.hsbc.unified.iam.fss.web.access;

import com.hsbc.unified.iam.fss.core.FileItem;

/**
 * Permission constants for {@link FileItem}.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public abstract class FileItemPermissions {
    /**
     * READ permission expression.
     */
    public static final String READ = "hasPermission('/fss', 'MenuItem', 'READ')";

    /**
     * WRITE permission expression.
     */
    public static final String WRITE = "hasPermission('/fss', 'MenuItem', 'WRITE')";

    /**
     * CREATE permission expression.
     */
    public static final String CREATE = "hasPermission('/fss', 'MenuItem', 'CREATE')";

    /**
     * DELETE permission expression.
     */
    public static final String DELETE = "hasPermission('/fss', 'MenuItem', 'DELETE')";

    /**
     * ADMINISTRATION permission expression.
     */
    public static final String ADMINISTRATION = "hasPermission('/fss', 'MenuItem', 'ADMINISTRATION')";
}
