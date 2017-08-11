package com.travelaudience.nexus.proxy;

import static org.junit.Assert.assertEquals;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpHeaders;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.modules.junit4.PowerMockRunnerDelegate;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.HashMap;
import java.util.Map;

@RunWith(PowerMockRunner.class)
@PowerMockRunnerDelegate(VertxUnitRunner.class)
@PrepareForTest({ NexusHttpProxy.class, UnauthenticatedNexusProxyVerticle.class })
public class UnauthenticatedNexusProxyVerticleTests {
    private static final String HOST = "localhost";
    private static final int PORT = findRandomUnusedPort();

    private static final Map<String, String> VARS = new HashMap<String, String>() {
        {
            put("ALLOWED_USER_AGENTS_ON_ROOT_REGEX", "GoogleHC");
            put("BIND_PORT", String.valueOf(PORT));
            put("CLOUD_IAM_AUTH_ENABLED", "false");
            put("NEXUS_DOCKER_HOST", "containers.example.com");
            put("NEXUS_HTTP_HOST", "nexus.example.com");
            put("NEXUS_RUT_HEADER", "X-Forwarded-User");
            put("TLS_CERT_PK12_PATH", "cert.pk12");
            put("TLS_CERT_PK12_PASS", "safe#passw0rd!");
            put("TLS_ENABLED", "false");
            put("UPSTREAM_DOCKER_PORT", "5003");
            put("UPSTREAM_HOST", "localhost");
            put("UPSTREAM_HTTP_PORT", "8081");
        }
    };

    private NexusHttpProxy proxy;
    private Vertx vertx;

    @Before
    public void setUp(final TestContext context) throws Exception {
        PowerMockito.mockStatic(System.class);
        VARS.entrySet().stream().forEach(e -> PowerMockito.when(System.getenv(e.getKey())).thenReturn(e.getValue()));

        this.vertx = Vertx.vertx();
        this.vertx.deployVerticle(UnauthenticatedNexusProxyVerticle.class.getName(), context.asyncAssertSuccess());
    }

    @After
    public void tearDown(TestContext context) {
        vertx.close(context.asyncAssertSuccess());
    }

    @Test
    public void root_responds_with_200_to_allowed_user_agents(final TestContext ctx) {
        final Async async = ctx.async();

        vertx.createHttpClient().get(PORT, HOST, "/", res -> {
            assertEquals(200, res.statusCode());
            assertEquals("0", res.headers().get(HttpHeaders.CONTENT_LENGTH));
            async.complete();
        }).putHeader(HttpHeaders.USER_AGENT, "GoogleHC/1.0").end();
    }

    private static final int findRandomUnusedPort() {
        try (final ServerSocket socket = new ServerSocket(0, 50, InetAddress.getLocalHost())) {
            return socket.getLocalPort();
        } catch (final IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }
}
