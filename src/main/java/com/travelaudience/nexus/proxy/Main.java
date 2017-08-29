package com.travelaudience.nexus.proxy;

import io.vertx.core.Vertx;
import io.vertx.core.logging.SLF4JLogDelegateFactory;

import static io.vertx.core.logging.LoggerFactory.LOGGER_DELEGATE_FACTORY_CLASS_NAME;

public class Main {
    private static final boolean CLOUD_IAM_AUTH_ENABLED = Boolean.valueOf(System.getenv("CLOUD_IAM_AUTH_ENABLED"));

    static {
        // Make Vert.x use SLF4J.
        System.setProperty(LOGGER_DELEGATE_FACTORY_CLASS_NAME, SLF4JLogDelegateFactory.class.getName());
    }

    public static void main(String[] args) {
        Vertx.vertx().deployVerticle(
                CLOUD_IAM_AUTH_ENABLED ? new CloudIamAuthNexusProxyVerticle() : new UnauthenticatedNexusProxyVerticle()
        );
    }
}
