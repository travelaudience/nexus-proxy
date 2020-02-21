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
    // JWT_REQUIRES_MEMBERSHIP_VERIFICATION indicates whether a user presenting a valid JWT token must still be verified for membership within the organization.
    private static final Boolean JWT_REQUIRES_MEMBERSHIP_VERIFICATION = Boolean.parseBoolean(System.getenv("JWT_REQUIRES_MEMBERSHIP_VERIFICATION"));
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

        final ImmutableList<String> audience;
        if (DOCKER_PROXY_ENABLED) {
            audience = ImmutableList.of(NEXUS_DOCKER_HOST, NEXUS_HTTP_HOST);
        } else {
            audience = ImmutableList.of(NEXUS_HTTP_HOST);
        }
        this.jwtAuth = JwtAuth.create(
                vertx,
                KEYSTORE_PATH,
                KEYSTORE_PASS,
                audience
        );
    }

    @Override
    protected void preconfigureRouting(final Router router) {
        router.route().handler(CookieHandler.create());
        router.route().handler(SessionHandler.create(LocalSessionStore.create(vertx)).setSessionTimeout(SESSION_TTL));
    }

    @Override
    protected void configureRouting(Router router) {
        if (DOCKER_PROXY_ENABLED) {
            // Enforce authentication for the Docker API.
            router.route(DOCKER_V2_API_PATHS).handler(VirtualHostHandler.create(NEXUS_DOCKER_HOST, ctx -> {
                if (ctx.request().headers().get(HttpHeaders.AUTHORIZATION) == null) {
                    LOGGER.debug("No authorization header found. Denying.");
                    ctx.response().putHeader(WWW_AUTHENTICATE_HEADER_NAME, WWW_AUTHENTICATE_HEADER_VALUE);
                    ctx.response().putHeader(DOCKER_DISTRIBUTION_API_VERSION_NAME, DOCKER_DISTRIBUTION_API_VERSION_VALUE);
                    ctx.fail(401);
                } else {
                    LOGGER.debug("Authorization header found.");
                    ctx.data().put(HAS_AUTHORIZATION_HEADER, true);
                    ctx.next();
                }
            }));
        }

        // Enforce authentication for the Nexus UI and API.
        router.route(NEXUS_REPOSITORY_PATHS).handler(VirtualHostHandler.create(NEXUS_HTTP_HOST, ctx -> {
            if (ctx.request().headers().get(HttpHeaders.AUTHORIZATION) == null) {
                LOGGER.debug("No authorization header found. Denying.");
                ctx.response().putHeader(WWW_AUTHENTICATE_HEADER_NAME, WWW_AUTHENTICATE_HEADER_VALUE);
                ctx.fail(401);
            } else {
                LOGGER.debug("Authorization header found.");
                ctx.data().put(HAS_AUTHORIZATION_HEADER, true);
                ctx.next();
            }
        }));

        // Configure the callback used by the OAuth2 consent screen.
        router.route(CALLBACK_PATH).handler(ctx -> {
            final String authorizationUri = flow.buildAuthorizationUri();

            // Check if the request contains an authentication code.
            // If it doesn't, redirect to the OAuth2 consent screen.
            if (!ctx.request().params().contains(AUTH_CODE_PARAM_NAME)) {
                LOGGER.debug("No authentication code found. Redirecting to consent screen.");
                ctx.response().setStatusCode(302).putHeader(HttpHeaders.LOCATION, authorizationUri).end();
                return;
            }

            // The request contains an authentication code.
            // We must now use it to request an access token for the user and know their identity.
            final GoogleTokenResponse token;
            final String principal;

            try {
                LOGGER.debug("Requesting access token from Google.");
                token = flow.requestToken(ctx.request().params().get(AUTH_CODE_PARAM_NAME));
                flow.storeCredential(token);
                principal = flow.getPrincipal(token);
                LOGGER.debug("Got access token for principal {}.", principal);
            } catch (final UncheckedIOException ex) {
                // We've failed to request the access token.
                // Our best bet is to redirect the user back to the consent screen so the process can be retried.
                LOGGER.error("Couldn't request access token from Google. Redirecting to consent screen.", ex);
                ctx.response().setStatusCode(302).putHeader(HttpHeaders.LOCATION, authorizationUri).end();
                return;
            }

            // We've got the required access token, so we redirect the user to the root.
            LOGGER.debug("Redirecting principal {} to {}.", principal, ROOT_PATH);
            ctx.session().put(SessionKeys.USER_ID, principal);
            ctx.response().setStatusCode(302).putHeader(HttpHeaders.LOCATION, ROOT_PATH).end();
        });

        // Configure token-based authentication for all paths in order to support authentication for CLI tools such as Maven and Docker.
        router.route(ALL_PATHS).handler(ctx -> {
            // Check for the presence of an authorization header so we can validate it.
            // If an authorization header is present, this must be a request from a CLI tool.
            final String authHeader = ctx.request().headers().get(HttpHeaders.AUTHORIZATION);

            // Skip this step if no authorization header has been found.
            if (authHeader == null) {
                ctx.next();
                return;
            }

            // The request carries an authorization header.
            // These headers are expected to be of the form "Basic X" where X is a base64-encoded string that corresponds to either "password" or "username:password".
            // The password is then validated as a JWT token, which should have been obtained previously by the user via a call to CLI_CREDENTIALS_PATH.
            final String[] parts = authHeader.split("\\s+");

            if (parts.length != 2) {
                ctx.next();
                return;
            }
            if (!"Basic".equals(parts[0])) {
                ctx.next();
                return;
            }

            LOGGER.debug("Request carries HTTP Basic authentication. Validating JWT token.");

            final String credentials = new String(Base64.decodeBase64(parts[1]), Charsets.UTF_8);
            final int colonIdx = credentials.indexOf(":");

            final String password;

            if (colonIdx != -1) {
                password = credentials.substring(colonIdx + 1);
            } else {
                password = credentials;
            }

            // Validate the password as a JWT token.
            jwtAuth.validate(password, userId -> {
                if (userId == null) {
                    LOGGER.debug("Got invalid JWT token. Denying.");
                    ctx.response().setStatusCode(403).end();
                } else {
                    LOGGER.debug("Got valid JWT token for principal {}.", userId);
                    ctx.data().put(SessionKeys.USER_ID, userId);
                    ctx.next();
                }
            });
        });

        // Configure routing for all paths.
        router.route(ALL_PATHS).handler(ctx -> {
            // Check whether the user has already been identified.
            // This happens either at the handler for CALLBACK_PATH or at the handler for JWT tokens.
            final String userId = getUserId(ctx);

            // If the user has NOT been identified yet, and the request does not carry an authorization header, redirect the user to the callback.
            if (userId == null) {
                LOGGER.debug("Got no authorization info. Redirecting to {}.", CALLBACK_PATH);
                ctx.response().setStatusCode(302).putHeader(HttpHeaders.LOCATION, CALLBACK_PATH).end();
                return;
            }

            // At this point we've got a valid principal.
            // We should, however, still check whether they are (still) a member of the organization (unless this check is explicitly disabled).
            // This is done mostly to prevent long-lived JWT tokens from being used after a user leaves the organization.

            final Boolean hasAuthorizationHeader = ((Boolean) ctx.data().getOrDefault(HAS_AUTHORIZATION_HEADER, false));

            // If there is an authorization header but membership verification is not required, skip the remaining of this handler.
            if (hasAuthorizationHeader && !JWT_REQUIRES_MEMBERSHIP_VERIFICATION) {
                LOGGER.debug("{} has a valid auth token but is not an organization member. Allowing since membership verification is not required.", userId);
                ctx.next();
                return;
            }

            // Check if the user is still a member of the organization.
            boolean isOrganizationMember = false;

            try {
                LOGGER.debug("Checking organization membership for principal {}.", userId);
                isOrganizationMember = flow.isOrganizationMember(userId);
                LOGGER.debug("Principal is organization member: {}.", isOrganizationMember);
            } catch (final UncheckedIOException ex) {
                // Destroy the user's session in case of an error while validating membership.
                ctx.session().destroy();
                LOGGER.error("Couldn't check membership for {}. Their session has been destroyed.", userId, ex);
            }

            // Make a decision based on whether the user is an organization member.
            // If they aren't, decide based on the presence of the authorization header (indicating either a CLI flow or a UI flow).
            if (isOrganizationMember) {
                // The user is an organization member. Allow the request.
                LOGGER.debug("{} is organization member. Allowing.", userId);
                ctx.next();
            } else if (hasAuthorizationHeader) {
                // The user is not an organization member (or membership couldn't be verified) AND is most probably using a CLI tool. Deny the request.
                LOGGER.debug("{} is not an organization member. Denying.", userId);
                ctx.response().setStatusCode(403).end();
            } else {
                // The user is not an organization member AND is most probably browsing Nexus UI. Redirect to the callback.
                LOGGER.debug("{} does not have an auth token and is not an organization member. Redirecting to {}.", userId, CALLBACK_PATH);
                ctx.response().setStatusCode(302).putHeader(HttpHeaders.LOCATION, CALLBACK_PATH).end();
            }
        });

        // Configure the path from where a JWT token can be obtained.
        router.get(CLI_CREDENTIALS_PATH).produces(MediaType.JSON_UTF_8.toString()).handler(ctx -> {
            final String userId = ctx.session().get(SessionKeys.USER_ID);

            LOGGER.debug("Generating JWT token for principal {}.", userId);

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
