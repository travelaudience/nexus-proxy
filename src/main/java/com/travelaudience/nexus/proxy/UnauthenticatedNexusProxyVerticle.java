package com.travelaudience.nexus.proxy;

import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

public class UnauthenticatedNexusProxyVerticle extends BaseNexusProxyVerticle {
    @Override
    protected void preconfigureRouting(final Router router) {
        // Do nothing.
    }

    @Override
    protected void configureRouting(final Router router) {
        // Do nothing.
    }

    @Override
    protected String getUserId(final RoutingContext ctx) {
        return null;
    }
}
