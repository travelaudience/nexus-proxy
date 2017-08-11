package com.travelaudience.nexus.proxy;

import io.vertx.core.Vertx;

public class Main {
    private static final boolean CLOUD_IAM_AUTH_ENABLED = Boolean.valueOf(System.getenv("CLOUD_IAM_AUTH_ENABLED"));

    public static void main(String[] args) {
        Vertx.vertx().deployVerticle(
                CLOUD_IAM_AUTH_ENABLED ? new CloudIamAuthNexusProxyVerticle() : new UnauthenticatedNexusProxyVerticle()
        );
    }
}
