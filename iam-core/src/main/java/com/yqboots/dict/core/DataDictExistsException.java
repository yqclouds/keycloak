package com.yqboots.dict.core;

/**
 * The exception thrown when the data dictionary exists.
 *
 * @author Eric H B Zhan
 * @since 1.0.0
 */
public class DataDictExistsException extends RuntimeException {
    /**
     * {@inheritDoc}
     */
    public DataDictExistsException(final String message) {
        super(message);
    }
}
