package com.travelaudience.nexus.proxy;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpHeaders;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.modules.junit4.PowerMockRunnerDelegate;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.ServerSocket;
import java.net.URL;
import java.net.URLDecoder;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import static java.util.stream.Collectors.toMap;
import static org.junit.Assert.assertEquals;

@RunWith(PowerMockRunner.class)
@PowerMockRunnerDelegate(VertxUnitRunner.class)
@PrepareForTest(NexusProxyVerticle.class)
public class NexusProxyVerticleTests {
    private static final String HOST = "localhost";
    private static final int PORT = findRandomUnusedPort();

    private static final Map<String, String> VARS = new HashMap<String, String>() {
        {
            /* GCP Organization stuff, not needed at this point */
            put("ORGANIZATION_ID", System.getProperty("ORGANIZATION_ID"));
            put("CLIENT_ID", System.getProperty("CLIENT_ID"));
            put("CLIENT_SECRET", System.getProperty("CLIENT_SECRET"));

            put("ALLOWED_USER_AGENTS_ON_ROOT_REGEX", "GoogleHC");
            put("AUTH_CACHE_TTL", "60");
            put("BIND_PORT", String.valueOf(PORT));
            put("KEYSTORE_PATH", "keystore.jceks");
            put("KEYSTORE_PASS", "safe#passw0rd!");
            put("NEXUS_DOCKER_HOST", "containers.example.com");
            put("NEXUS_HTTP_HOST", "nexus.example.com");
            put("NEXUS_RUT_HEADER", "X-Forwarded-User");
            put("REDIRECT_URL", "https://nexus.example.com/oauth/callback");
            put("SESSION_TTL", "1440000");
            put("TLS_CERT_PK12_PATH", "cert.pk12");
            put("TLS_CERT_PK12_PASS", "safe#passw0rd!");
            put("TLS_ENABLED", "false");
            put("UPSTREAM_DOCKER_PORT", "5003");
            put("UPSTREAM_HOST", "localhost");
            put("UPSTREAM_HTTP_PORT", "8081");
        }
    };


    private Vertx vertx;

    @BeforeClass
    public static void setUpBeforeClass() {
        PowerMockito.mockStatic(System.class);
        VARS.entrySet().stream().forEach(e -> PowerMockito.when(System.getenv(e.getKey())).thenReturn(e.getValue()));
    }

    @Before
    public void setUp(final TestContext context) {
        this.vertx = Vertx.vertx();
        this.vertx.deployVerticle(NexusProxyVerticle.class.getName(), context.asyncAssertSuccess());
    }

    @After
    public void tearDown(TestContext context) {
        vertx.close(context.asyncAssertSuccess());
    }

    @Test
    public void root_responds_with_302(final TestContext ctx) {
        final Async async = ctx.async();

        vertx.createHttpClient().get(PORT, HOST, "/", res -> {
            assertEquals(302, res.statusCode());
            assertEquals("/oauth/callback", res.headers().get(HttpHeaders.LOCATION));
            async.complete();
        }).putHeader(HttpHeaders.USER_AGENT, "SomeUserAgent/1.0").end();
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

    @Test
    public void maven_repository_root_path_responds_with_401_when_no_authentication_is_present(final TestContext ctx) {
        final Async async = ctx.async();

        vertx.createHttpClient().get(PORT, HOST, "/repository/maven-public/", res -> {
            assertEquals(401, res.statusCode());
            assertEquals("Basic Realm=\"nexus-proxy\"", res.headers().get("WWW-Authenticate"));
            async.complete();
        }).putHeader(HttpHeaders.HOST, VARS.get("NEXUS_HTTP_HOST")).end();
    }

    @Test
    public void docker_repository_root_path_responds_with_401_when_no_authentication_is_present(final TestContext ctx) {
        final Async async = ctx.async();

        vertx.createHttpClient().get(PORT, HOST, "/v2/", res -> {
            assertEquals(401, res.statusCode());
            assertEquals("Basic Realm=\"nexus-proxy\"", res.headers().get("WWW-Authenticate"));
            assertEquals("registry/2.0", res.headers().get("Docker-Distribution-Api-Version"));
            async.complete();
        }).putHeader(HttpHeaders.HOST, VARS.get("NEXUS_DOCKER_HOST")).end();
    }

    @Test
    public void callback_path_responds_with_302_when_no_auth_code_param_is_present(final TestContext ctx) {
        final Async async = ctx.async();

        vertx.createHttpClient().get(PORT, HOST, "/oauth/callback", res -> {
            assertEquals(302, res.statusCode());
            final URL redirectUrl = buildUrl(res.headers().get(HttpHeaders.LOCATION));
            assertEquals("accounts.google.com", redirectUrl.getHost());
            final Map<String, String> params = parseQuery(redirectUrl);
            assertEquals("offline", params.get("access_type"));
            assertEquals("force", params.get("approval_prompt"));
            assertEquals(System.getenv("CLIENT_ID"), params.get("client_id"));
            assertEquals(System.getenv("REDIRECT_URL"), params.get("redirect_uri"));
            assertEquals("code", params.get("response_type"));
            async.complete();
        }).putHeader(HttpHeaders.USER_AGENT, "SomeUserAgent/1.0").end();
    }

    private static final URL buildUrl(final String url) {
        try {
            return new URL(url);
        } catch (final MalformedURLException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    private static final int findRandomUnusedPort() {
        try (final ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (final IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    private static final Map<String, String> parseQuery(final URL url) {
        return Pattern.compile("&").splitAsStream(url.getQuery())
                .map(s -> Arrays.copyOf(s.split("="), 2))
                .map(o -> new AbstractMap.SimpleEntry<>(urlDecode(o[0]), urlDecode(o[1])))
                .collect(toMap(e -> e.getKey(), e -> e.getValue()));
    }

    private static final String urlDecode(final String encoded) {
        try {
            return encoded == null ? null : URLDecoder.decode(encoded, "UTF-8");
        } catch (final UnsupportedEncodingException ex) {
            throw new UncheckedIOException(ex);
        }
    }
}
