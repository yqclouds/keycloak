/*
 * JBoss, Home of Professional Open Source
 * Copyright 2018 Red Hat Inc. and/or its affiliates and other contributors
 * as indicated by the @authors tag. All rights reserved.
 */
package org.keycloak.theme.beans;

import freemarker.template.TemplateMethodModelEx;
import freemarker.template.TemplateModelException;

import java.util.List;
import java.util.Locale;
import java.util.Properties;

/**
 * Method used to format link expiration time period in emails.
 *
 * @author Vlastimil Elias (velias at redhat dot com)
 */
public class LinkExpirationFormatterMethod implements TemplateMethodModelEx {

    protected final Properties messages;
    protected final Locale locale;

    public LinkExpirationFormatterMethod(Properties messages, Locale locale) {
        this.messages = messages;
        this.locale = locale;
    }

    @SuppressWarnings("rawtypes")
    @Override
    public Object exec(List arguments) throws TemplateModelException {
        Object val = arguments.isEmpty() ? null : arguments.get(0);
        if (val == null)
            return "";

        try {
            //input value is in minutes, as defined in EmailTemplateProvider!
            return format(Long.parseLong(val.toString().trim()) * 60);
        } catch (NumberFormatException e) {
            // not a number, return it as is
            return val.toString();
        }

    }

    protected String format(long valueInSeconds) {

        String unitKey = "seconds";
        long value = valueInSeconds;

        if (value > 0 && value % 60 == 0) {
            unitKey = "minutes";
            value = value / 60;
            if (value % 60 == 0) {
                unitKey = "hours";
                value = value / 60;
                if (value % 24 == 0) {
                    unitKey = "days";
                    value = value / 24;
                }
            }
        }

        return value + " " + getUnitTextFromMessages(unitKey, value);
    }

    protected String getUnitTextFromMessages(String unitKey, long value) {
        String msg = messages.getProperty("linkExpirationFormatter.timePeriodUnit." + unitKey + "." + value);
        if (msg != null)
            return msg;
        return messages.getProperty("linkExpirationFormatter.timePeriodUnit." + unitKey);
    }

}
