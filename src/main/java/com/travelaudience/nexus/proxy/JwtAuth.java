package com.travelaudience.nexus.proxy;

import io.vertx.core.Vertx;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTOptions;

import java.time.Duration;
import java.util.List;
import java.util.function.Consumer;

import static java.time.temporal.ChronoUnit.DAYS;

/**
 * Provides utility methods for dealing with JWT-based authentication.
 */
public final class JwtAuth {
    private static final String UID_KEY = "uid";

    private final List<String> audience;
    private final JWTAuth jwtAuth;
    private final JWTOptions jwtOptions;

    private JwtAuth(final Vertx vertx,
                    final String keystorePath,
                    final String keystorePass,
                    final List<String> audience) {
        this.jwtAuth = JWTAuth.create(vertx, new JsonObject().put("keyStore", new JsonObject()
                .put("path", keystorePath)
                .put("type", "jceks")
                .put("password", keystorePass)));
        this.jwtOptions = new JWTOptions()
                .setAudience(audience)
                .setAlgorithm("RS256")
                .setExpiresInSeconds(Duration.of(365, DAYS).getSeconds());
        this.audience = audience;
    }

    /**
     * Creates a new instance of {@link JwtAuth}.
     *
     * @param vertx        the base {@link Vertx} instance.
     * @param keystorePath the path to the keystore containing the signing key.
     * @param keystorePass the password to the keystore containing the signing key.
     * @param audience     the intended audience of the generated tokens.
     * @return a new instance of {@link JwtAuth}.
     */
    public static final JwtAuth create(final Vertx vertx,
                                       final String keystorePath,
                                       final String keystorePass,
                                       final List<String> audience) {
        return new JwtAuth(vertx, keystorePath, keystorePass, audience);
    }

    /**
     * Returns a new JWT for the specified user.
     *
     * @param userId the authenticated user.
     * @return a new JWT for the specified user.
     */
    public final String generate(final String userId) {
        return this.jwtAuth.generateToken(new JsonObject().put(UID_KEY, userId), this.jwtOptions);
    }

    /**
     * Validates whether the specified {@code jwtToken} is valid, returning the user's ID if validation is successful or
     * {@null} otherwise.
     *
     * @param jwtToken the JWT token with which the user is authenticating.
     * @param handler  the result handler.
     */
    public final void validate(final String jwtToken,
                               final Consumer<String> handler) {
        final JsonObject authData = new JsonObject()
                .put("jwt", jwtToken)
                .put("options", new JsonObject()
                        .put("audience", new JsonArray(audience)));

        this.jwtAuth.authenticate(authData, res -> {
            if (res.succeeded()) {
                handler.accept(res.result().principal().getString(UID_KEY));
            } else {
                handler.accept(null);
            }
        });
    }
}
