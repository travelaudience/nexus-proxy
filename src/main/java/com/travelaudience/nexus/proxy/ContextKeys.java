package com.travelaudience.nexus.proxy;

import io.vertx.ext.web.RoutingContext;

/**
 * Holds strings corresponding to keys frequently set on {@link RoutingContext#data()}.
 */
public final class ContextKeys {
    /**
     * The key that holds the fact that there's an {@code Authorization} header on the current request.
     */
    public static final String HAS_AUTHORIZATION_HEADER = "has-authorization-header";
    /**
     * The key that holds the instance of {@link NexusHttpProxy} to use when serving the current request.
     */
    public static final String PROXY = "proxy";

    private ContextKeys() {
    }
}
