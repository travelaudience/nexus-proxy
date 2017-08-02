package com.travelaudience.nexus.proxy;

import io.vertx.ext.web.RoutingContext;

/**
 * Holds strings corresponding to keys frequently set on {@link RoutingContext#session()}.
 */
public final class SessionKeys {
    /**
     * The key that holds the currently authenticated user's ID.
     */
    public static final String USER_ID = "user-id";

    private SessionKeys() {
    }
}
