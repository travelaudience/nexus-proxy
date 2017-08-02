package com.travelaudience.nexus.proxy;

import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.util.Base64;
import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableList;
import com.google.common.net.MediaType;
import com.google.common.primitives.Ints;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.PfxOptions;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.CookieHandler;
import io.vertx.ext.web.handler.SessionHandler;
import io.vertx.ext.web.handler.VirtualHostHandler;
import io.vertx.ext.web.sstore.LocalSessionStore;

import java.util.Optional;
import java.util.regex.Pattern;

/**
 * A verticle which implements a simple proxy for authenticating Nexus users against Google Cloud IAM.
 */
public class NexusProxyVerticle extends AbstractVerticle {
    private static final String ALLOWED_USER_AGENTS_ON_ROOT_REGEX = System.getenv("ALLOWED_USER_AGENTS_ON_ROOT_REGEX");
    private static final Integer AUTH_CACHE_TTL = Ints.tryParse(System.getenv("AUTH_CACHE_TTL"));
    private static final Integer BIND_PORT = Ints.tryParse(System.getenv(("BIND_PORT")));
    private static final String CLIENT_ID = System.getenv("CLIENT_ID");
    private static final String CLIENT_SECRET = System.getenv("CLIENT_SECRET");
    private static final String KEYSTORE_PATH = System.getenv("KEYSTORE_PATH");
    private static final String KEYSTORE_PASS = System.getenv("KEYSTORE_PASS");
    private static final String NEXUS_DOCKER_HOST = System.getenv("NEXUS_DOCKER_HOST");
    private static final String NEXUS_HTTP_HOST = System.getenv("NEXUS_HTTP_HOST");
    private static final String NEXUS_RUT_HEADER = System.getenv("NEXUS_RUT_HEADER");
    private static final String ORGANIZATION_ID = System.getenv("ORGANIZATION_ID");
    private static final String REDIRECT_URL = System.getenv("REDIRECT_URL");
    private static final Integer SESSION_TTL = Ints.tryParse(System.getenv("SESSION_TTL"));
    private static final String TLS_CERT_PK12_PATH = System.getenv("TLS_CERT_PK12_PATH");
    private static final String TLS_CERT_PK12_PASS = System.getenv("TLS_CERT_PK12_PASS");
    private static final String TLS_ENABLED = System.getenv("TLS_ENABLED");
    private static final Integer UPSTREAM_DOCKER_PORT = Ints.tryParse(System.getenv("UPSTREAM_DOCKER_PORT"));
    private static final String UPSTREAM_HOST = System.getenv("UPSTREAM_HOST");
    private static final Integer UPSTREAM_HTTP_PORT = Ints.tryParse(System.getenv("UPSTREAM_HTTP_PORT"));

    /**
     * The pattern against which to match 'User-Agent' headers.
     */
    private static final Pattern ALLOWED_USER_AGENTS_ON_ROOT_PATTERN = Pattern.compile(
            ALLOWED_USER_AGENTS_ON_ROOT_REGEX,
            Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE
    );

    /**
     * The path that corresponds to all possible paths within the proxy and Nexus.
     */
    private static final String ALL_PATHS = "/*";
    /**
     * The path that corresponds to the callback URL to be called by Google.
     */
    private static final String CALLBACK_PATH = "/oauth/callback";
    /**
     * The path that corresponds to the URL where users may get their CLI credentials from.
     */
    private static final String CLI_CREDENTIALS_PATH = "/cli/credentials";
    /**
     * The path that corresponds to all possible paths within the Nexus Docker registry.
     */
    private static final String DOCKER_V2_API_PATHS = "/v2/*";
    /**
     * The path that corresponds to all possible paths within the Nexus Maven repositories.
     */
    private static final String NEXUS_REPOSITORY_PATHS = "/repository/*";
    /**
     * The path that corresponds to the application's root.
     */
    private static final String ROOT_PATH = "/";

    /**
     * The name of the parameters conveying the authorization code when {@code CALLBACK_PATH} is called.
     */
    private static final String AUTH_CODE_PARAM_NAME = "code";

    /**
     * The name of the response header conveying information about the Docker registry's version.
     */
    private static final CharSequence DOCKER_DISTRIBUTION_API_VERSION_NAME =
            HttpHeaders.createOptimized("Docker-Distribution-Api-Version");
    /**
     * The value of the response header conveying information about the Docker registry's version.
     */
    private static final CharSequence DOCKER_DISTRIBUTION_API_VERSION_VALUE =
            HttpHeaders.createOptimized("registry/2.0");
    /**
     * The name of the 'WWW-Authenticate' header.
     */
    private static final CharSequence WWW_AUTHENTICATE_HEADER_NAME =
            HttpHeaders.createOptimized("WWW-Authenticate");
    /**
     * The value of the 'WWW-Authenticate' header.
     */
    private static final CharSequence WWW_AUTHENTICATE_HEADER_VALUE =
            HttpHeaders.createOptimized("Basic Realm=\"nexus-proxy\"");

    /**
     * Returns the currently authenticated user, or {@null} if no valid authentication info is present.
     *
     * @param ctx the current routing context.
     * @return the currently authenticated user, or {@null} if no valid authentication info is present.
     */
    private static final String getUserId(final RoutingContext ctx) {
        return Optional.ofNullable(
                (String) ctx.data().get(SessionKeys.USER_ID)
        ).orElse(
                ctx.session().get(SessionKeys.USER_ID)
        );
    }

    @Override
    public void start() throws Exception {
        final CachingGoogleAuthCodeFlow flow = CachingGoogleAuthCodeFlow.create(
                this.AUTH_CACHE_TTL,
                this.CLIENT_ID,
                this.CLIENT_SECRET,
                this.ORGANIZATION_ID,
                this.REDIRECT_URL
        );

        final JwtAuth jwtAuth = JwtAuth.create(
                vertx,
                KEYSTORE_PATH,
                KEYSTORE_PASS,
                ImmutableList.of(NEXUS_DOCKER_HOST, NEXUS_HTTP_HOST)
        );
        final NexusHttpProxy dockerProxy = NexusHttpProxy.create(
                vertx,
                UPSTREAM_HOST,
                UPSTREAM_DOCKER_PORT,
                NEXUS_RUT_HEADER
        );
        final NexusHttpProxy httpProxy = NexusHttpProxy.create(
                vertx,
                UPSTREAM_HOST,
                UPSTREAM_HTTP_PORT,
                NEXUS_RUT_HEADER
        );
        final Router router = Router.router(
                vertx
        );

        router.route().handler(CookieHandler.create());
        router.route().handler(SessionHandler.create(LocalSessionStore.create(vertx)).setSessionTimeout(SESSION_TTL));

        router.route(ROOT_PATH).handler(ctx -> {
            final String agent = ctx.request().headers().get(HttpHeaders.USER_AGENT);

            if (agent != null && ALLOWED_USER_AGENTS_ON_ROOT_PATTERN.matcher(agent).find()) {
                ctx.response().setStatusCode(200).end();
            } else {
                ctx.next();
            }
        });

        router.route(DOCKER_V2_API_PATHS).handler(VirtualHostHandler.create(NEXUS_DOCKER_HOST, ctx -> {
            if (ctx.request().headers().get(HttpHeaders.AUTHORIZATION) == null) {
                ctx.response().putHeader(WWW_AUTHENTICATE_HEADER_NAME, WWW_AUTHENTICATE_HEADER_VALUE);
                ctx.response().putHeader(DOCKER_DISTRIBUTION_API_VERSION_NAME, DOCKER_DISTRIBUTION_API_VERSION_VALUE);
                ctx.fail(401);
            } else {
                ctx.data().put(ContextKeys.HAS_AUTHORIZATION_HEADER, true);
                ctx.data().put(ContextKeys.PROXY, dockerProxy);
                ctx.next();
            }
        }));

        router.route(ALL_PATHS).handler(VirtualHostHandler.create(NEXUS_HTTP_HOST, ctx -> {
            ctx.data().put(ContextKeys.PROXY, httpProxy);
            ctx.next();
        }));

        router.route(NEXUS_REPOSITORY_PATHS).handler(VirtualHostHandler.create(NEXUS_HTTP_HOST, ctx -> {
            if (ctx.request().headers().get(HttpHeaders.AUTHORIZATION) == null) {
                ctx.response().putHeader(WWW_AUTHENTICATE_HEADER_NAME, WWW_AUTHENTICATE_HEADER_VALUE);
                ctx.fail(401);
            } else {
                ctx.data().put(ContextKeys.HAS_AUTHORIZATION_HEADER, true);
                ctx.next();
            }
        }));

        router.route(CALLBACK_PATH).handler(ctx -> {
            if (!ctx.request().params().contains(AUTH_CODE_PARAM_NAME)) {
                ctx.response().setStatusCode(302).putHeader(HttpHeaders.LOCATION, flow.buildAuthorizationUri()).end();
            } else {
                final GoogleTokenResponse token = flow.requestToken(ctx.request().params().get(AUTH_CODE_PARAM_NAME));
                flow.storeCredential(token);
                ctx.session().put(SessionKeys.USER_ID, flow.getPrincipal(token));
                ctx.response().setStatusCode(302).putHeader(HttpHeaders.LOCATION, ROOT_PATH).end();
            }
        });

        router.route(ALL_PATHS).handler(ctx -> {
            final String authHeader = ctx.request().headers().get(HttpHeaders.AUTHORIZATION);

            if (authHeader == null) {
                ctx.next();
                return;
            }

            final String[] parts = authHeader.split("\\s+");

            if (parts.length != 2) {
                ctx.next();
                return;
            }
            if (!"Basic".equals(parts[0])) {
                ctx.next();
                return;
            }

            final String credentials = new String(Base64.decodeBase64(parts[1]), Charsets.UTF_8);
            final int colonIdx = credentials.indexOf(":");

            final String password;

            if (colonIdx != -1) {
                password = credentials.substring(colonIdx + 1);
            } else {
                password = credentials;
            }

            jwtAuth.validate(password, userId -> {
                ctx.data().put(SessionKeys.USER_ID, userId);
                ctx.next();
            });
        });

        router.route(ALL_PATHS).handler(ctx -> {
            final String userId = getUserId(ctx);

            if (userId == null && !((Boolean) ctx.data().getOrDefault(ContextKeys.HAS_AUTHORIZATION_HEADER, false))) {
                ctx.response().setStatusCode(302).putHeader(HttpHeaders.LOCATION, CALLBACK_PATH).end();
                return;
            }
            if (userId == null || !flow.isOrganizationMember(userId)) {
                ctx.response().setStatusCode(403).end();
                return;
            }

            ctx.next();
        });

        router.get(CLI_CREDENTIALS_PATH).produces(MediaType.JSON_UTF_8.toString()).handler(ctx -> {
            final String userId = ctx.session().get(SessionKeys.USER_ID);

            final JsonObject body = new JsonObject()
                    .put("username", userId)
                    .put("password", jwtAuth.generate(userId));

            ctx.response().putHeader(HttpHeaders.CONTENT_TYPE, MediaType.JSON_UTF_8.toString()).end(body.encode());
        });

        router.route(ALL_PATHS).handler(ctx -> {
            ((NexusHttpProxy) ctx.data().get(ContextKeys.PROXY)).proxyUserRequest(getUserId(ctx), ctx.request(), ctx.response());
        });

        final PfxOptions pfxOptions = new PfxOptions().setPath(TLS_CERT_PK12_PATH).setPassword(TLS_CERT_PK12_PASS);

        vertx.createHttpServer(
                new HttpServerOptions().setSsl("true".equalsIgnoreCase(TLS_ENABLED)).setPfxKeyCertOptions(pfxOptions)
        ).requestHandler(
                router::accept
        ).listen(BIND_PORT);
    }
}
