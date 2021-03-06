/*
 * Copyright 2019 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.device;

import com.hsbc.unified.iam.core.util.Base64;
import com.hsbc.unified.iam.core.util.JsonSerialization;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.account.DeviceRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import ua_parser.Client;
import ua_parser.Parser;

import javax.ws.rs.core.HttpHeaders;
import java.io.IOException;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DeviceActivityManager {

    private static final String DEVICE_NOTE = "KC_DEVICE_NOTE";
    private static final Logger LOG = LoggerFactory.getLogger(DeviceActivityManager.class);
    private static final int USER_AGENT_MAX_LENGTH = 512;
    private static final Parser UA_PARSER;

    static {
        try {
            UA_PARSER = new Parser();
        } catch (IOException cause) {
            throw new RuntimeException("Failed to create user agent parser", cause);
        }
    }

    /**
     * Returns the device information associated with the given {@code userSession}.
     *
     * @param userSession the userSession
     * @return the device information or null if no device is attached to the user session
     */
    public static DeviceRepresentation getCurrentDevice(UserSessionModel userSession) {
        String deviceInfo = userSession.getNote(DEVICE_NOTE);

        if (deviceInfo == null) {
            return null;
        }

        try {
            return JsonSerialization.readValue(Base64.decode(deviceInfo), DeviceRepresentation.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Attaches a device to the given {@code userSession} where the device information is obtained from the {@link HttpHeaders#USER_AGENT} in the current
     * request, if available.
     *
     * @param userSession the user session
     */
    public void attachDevice(UserSessionModel userSession) {
        DeviceRepresentation current = getDeviceFromUserAgent();

        if (current != null) {
            try {
                userSession.setNote(DEVICE_NOTE, Base64.encodeBytes(JsonSerialization.writeValueAsBytes(current)));
            } catch (IOException cause) {
                throw new RuntimeException(cause);
            }
        }
    }

    @Autowired
    private KeycloakContext context;

    private DeviceRepresentation getDeviceFromUserAgent() {
        String userAgent = context.getRequestHeaders().getHeaderString(HttpHeaders.USER_AGENT);

        if (userAgent == null) {
            return null;
        }

        if (userAgent.length() > USER_AGENT_MAX_LENGTH) {
            LOG.warn("Ignoring User-Agent header. Length is above the permitted: " + USER_AGENT_MAX_LENGTH);
            return null;
        }

        DeviceRepresentation current;

        try {
            Client client = UA_PARSER.parse(userAgent);
            current = new DeviceRepresentation();

            current.setDevice(client.device.family);

            String browserVersion = client.userAgent.major;

            if (client.userAgent.minor != null) {
                browserVersion += "." + client.userAgent.minor;
            }

            if (client.userAgent.patch != null) {
                browserVersion += "." + client.userAgent.patch;
            }

            if (browserVersion == null) {
                browserVersion = DeviceRepresentation.UNKNOWN;
            }

            current.setBrowser(client.userAgent.family, browserVersion);
            current.setOs(client.os.family);

            String osVersion = client.os.major;

            if (client.os.minor != null) {
                osVersion += "." + client.os.minor;
            }

            if (client.os.patch != null) {
                osVersion += "." + client.os.patch;
            }

            if (client.os.patchMinor != null) {
                osVersion += "." + client.os.patchMinor;
            }

            current.setOsVersion(osVersion);
            current.setIpAddress(context.getConnection().getRemoteAddr());
            current.setMobile(userAgent.toLowerCase().contains("mobile"));
        } catch (Exception cause) {
            LOG.error("Failed to create device info from user agent header", cause);
            return null;
        }

        return current;
    }
}
