package com.hsbc.unified.iam.dict.web.access;

import com.hsbc.unified.iam.dict.core.DataDict;

/**
 * Permission constants for {@link DataDict}.
 *
 * @author Eric H B Zhan
 * @since 1.1.0
 */
public abstract class DataDictPermissions {
    /**
     * READ permission expression.
     */
    public static final String READ = "hasPermission('/dict', 'MenuItem', 'READ')";

    /**
     * WRITE permission expression.
     */
    public static final String WRITE = "hasPermission('/dict', 'MenuItem', 'WRITE')";

    /**
     * CREATE permission expression.
     */
    public static final String CREATE = "hasPermission('/dict', 'MenuItem', 'CREATE')";

    /**
     * DELETE permission expression.
     */
    public static final String DELETE = "hasPermission('/dict', 'MenuItem', 'DELETE')";

    /**
     * ADMINISTRATION permission expression.
     */
    public static final String ADMINISTRATION = "hasPermission('/dict', 'MenuItem', 'ADMINISTRATION')";
}
