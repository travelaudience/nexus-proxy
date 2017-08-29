package com.travelaudience.nexus.proxy;

import static com.travelaudience.nexus.proxy.ContextKeys.HAS_AUTHORIZATION_HEADER;
import static com.travelaudience.nexus.proxy.Paths.ALL_PATHS;
import static com.travelaudience.nexus.proxy.Paths.ROOT_PATH;

import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.util.Base64;
import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableList;
import com.google.common.net.MediaType;
import com.google.common.primitives.Ints;
import io.vertx.core.Context;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.CookieHandler;
import io.vertx.ext.web.handler.SessionHandler;
import io.vertx.ext.web.handler.VirtualHostHandler;
import io.vertx.ext.web.sstore.LocalSessionStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UncheckedIOException;
import java.util.Optional;

/**
 * A verticle which implements a simple proxy for authenticating Nexus users against Google Cloud IAM.
 */
public class CloudIamAuthNexusProxyVerticle extends BaseNexusProxyVerticle {
    private static final Logger LOGGER = LoggerFactory.getLogger(CloudIamAuthNexusProxyVerticle.class);

    private static final Integer AUTH_CACHE_TTL = Ints.tryParse(System.getenv("AUTH_CACHE_TTL"));
    private static final String CLIENT_ID = System.getenv("CLIENT_ID");
    private static final String CLIENT_SECRET = System.getenv("CLIENT_SECRET");
    private static final String KEYSTORE_PATH = System.getenv("KEYSTORE_PATH");
    private static final String KEYSTORE_PASS = System.getenv("KEYSTORE_PASS");
    private static final String ORGANIZATION_ID = System.getenv("ORGANIZATION_ID");
    private static final String REDIRECT_URL = System.getenv("REDIRECT_URL");
    private static final Integer SESSION_TTL = Ints.tryParse(System.getenv("SESSION_TTL"));

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


    private CachingGoogleAuthCodeFlow flow;
    private JwtAuth jwtAuth;

    @Override
    public void init(final Vertx vertx,
                     final Context context) {
        super.init(vertx, context);

        this.flow = CachingGoogleAuthCodeFlow.create(
                AUTH_CACHE_TTL,
                CLIENT_ID,
                CLIENT_SECRET,
                ORGANIZATION_ID,
                REDIRECT_URL
        );

        this.jwtAuth = JwtAuth.create(
                vertx,
                KEYSTORE_PATH,
                KEYSTORE_PASS,
                ImmutableList.of(nexusDockerHost, nexusHttpHost)
        );
    }

    @Override
    protected void preconfigureRouting(final Router router) {
        router.route().handler(CookieHandler.create());
        router.route().handler(SessionHandler.create(LocalSessionStore.create(vertx)).setSessionTimeout(SESSION_TTL));
    }

    @Override
    protected void configureRouting(Router router) {
        router.route(DOCKER_V2_API_PATHS).handler(VirtualHostHandler.create(nexusDockerHost, ctx -> {
            if (ctx.request().headers().get(HttpHeaders.AUTHORIZATION) == null) {
                ctx.response().putHeader(WWW_AUTHENTICATE_HEADER_NAME, WWW_AUTHENTICATE_HEADER_VALUE);
                ctx.response().putHeader(DOCKER_DISTRIBUTION_API_VERSION_NAME, DOCKER_DISTRIBUTION_API_VERSION_VALUE);
                ctx.fail(401);
            } else {
                ctx.data().put(HAS_AUTHORIZATION_HEADER, true);
                ctx.next();
            }
        }));

        router.route(NEXUS_REPOSITORY_PATHS).handler(VirtualHostHandler.create(nexusHttpHost, ctx -> {
            if (ctx.request().headers().get(HttpHeaders.AUTHORIZATION) == null) {
                ctx.response().putHeader(WWW_AUTHENTICATE_HEADER_NAME, WWW_AUTHENTICATE_HEADER_VALUE);
                ctx.fail(401);
            } else {
                ctx.data().put(HAS_AUTHORIZATION_HEADER, true);
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

            if (userId == null && !((Boolean) ctx.data().getOrDefault(HAS_AUTHORIZATION_HEADER, false))) {
                ctx.response().setStatusCode(302).putHeader(HttpHeaders.LOCATION, CALLBACK_PATH).end();
                return;
            }
            if (userId == null) {
                ctx.response().setStatusCode(403).end();
                return;
            }

            boolean isOrganizationMember = false;

            try {
                isOrganizationMember = flow.isOrganizationMember(userId);
            } catch (final UncheckedIOException ex) {
                // Destroy the user's session in case of an error while validating membership.
                ctx.session().destroy();
                LOGGER.error("Couldn't check membership for {}. Their session has been destroyed.", userId, ex);
            }

            if (isOrganizationMember) {
                // The user is an organization member.
                LOGGER.debug("{} is organization member. Allowing.", userId);
                ctx.next();
            } else if ((Boolean) ctx.data().getOrDefault(HAS_AUTHORIZATION_HEADER, false)) {
                // The user is not an organization member AND is most probably using a CLI tool. --> Forbid.
                LOGGER.debug("{} has an auth token but is not an organization member. Forbidding.", userId);
                ctx.response().setStatusCode(403).end();
            } else {
                // The user is not an organization member AND is most probably browsing Nexus UI. --> Redirect.
                LOGGER.debug("{} does not have an auth token and is not an organization member. Redirecting.", userId);
                ctx.response().setStatusCode(302).putHeader(HttpHeaders.LOCATION, CALLBACK_PATH).end();
            }
        });

        router.get(CLI_CREDENTIALS_PATH).produces(MediaType.JSON_UTF_8.toString()).handler(ctx -> {
            final String userId = ctx.session().get(SessionKeys.USER_ID);

            final JsonObject body = new JsonObject()
                    .put("username", userId)
                    .put("password", jwtAuth.generate(userId));

            ctx.response().putHeader(HttpHeaders.CONTENT_TYPE, MediaType.JSON_UTF_8.toString()).end(body.encode());
        });
    }

    @Override
    protected String getUserId(final RoutingContext ctx) {
        return Optional.ofNullable(
                (String) ctx.data().get(SessionKeys.USER_ID)
        ).orElse(
                ctx.session().get(SessionKeys.USER_ID)
        );
    }
}
