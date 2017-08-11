package com.travelaudience.nexus.proxy;

import static com.google.api.services.cloudresourcemanager.CloudResourceManagerScopes.CLOUD_PLATFORM_READ_ONLY;
import static com.google.api.services.oauth2.Oauth2Scopes.USERINFO_EMAIL;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.store.DataStoreFactory;
import com.google.api.client.util.store.MemoryDataStoreFactory;
import com.google.api.services.cloudresourcemanager.CloudResourceManager;
import com.google.api.services.cloudresourcemanager.model.Organization;
import com.google.common.collect.ImmutableSet;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.List;
import java.util.Set;

/**
 * Wraps {@link GoogleAuthorizationCodeFlow} caching authorization results and providing unchecked methods.
 */
public class CachingGoogleAuthCodeFlow {
    private static final DataStoreFactory DATA_STORE_FACTORY = new MemoryDataStoreFactory();
    private static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();
    private static final JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();
    private static final Set<String> SCOPES = ImmutableSet.of(CLOUD_PLATFORM_READ_ONLY, USERINFO_EMAIL);

    private final LoadingCache<String, Boolean> authCache;
    private final GoogleAuthorizationCodeFlow authFlow;
    private final String organizationId;
    private final String redirectUri;

    private CachingGoogleAuthCodeFlow(final int authCacheTtl,
                                      final String clientId,
                                      final String clientSecret,
                                      final String organizationId,
                                      final String redirectUri) throws IOException {
        this.authCache = Caffeine.newBuilder()
                .maximumSize(4096)
                .expireAfterWrite(authCacheTtl, MILLISECONDS)
                .build(k -> this.isOrganizationMember(k, true));
        this.authFlow = new GoogleAuthorizationCodeFlow.Builder(
                HTTP_TRANSPORT,
                JSON_FACTORY,
                clientId,
                clientSecret,
                SCOPES
        ).setDataStoreFactory(
                DATA_STORE_FACTORY
        ).setAccessType(
                "offline"
        ).setApprovalPrompt(
                "force"
        ).build();
        this.organizationId = organizationId;
        this.redirectUri = redirectUri;
    }

    /**
     * Creates a new instance of {@link CachingGoogleAuthCodeFlow}.
     *
     * @param authCacheTtl   the amount of time (in ms) during which to cache the fact that a user is authorized.
     * @param clientId       the application's client ID.
     * @param clientSecret   the application's client secret.
     * @param organizationId the organization ID.
     * @param redirectUri    the URL which to redirect users to in the end of the authentication flow.
     * @return a new instance of {@link CachingGoogleAuthCodeFlow}.
     */
    public static final CachingGoogleAuthCodeFlow create(final int authCacheTtl,
                                                         final String clientId,
                                                         final String clientSecret,
                                                         final String organizationId,
                                                         final String redirectUri) {
        try {
            return new CachingGoogleAuthCodeFlow(authCacheTtl, clientId, clientSecret, organizationId, redirectUri);
        } catch (final IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    /**
     * Returns the full authorization code request URL (complete with the redirect URL).
     *
     * @return the full authorization code request URL (complete with the redirect URL).
     */
    public final String buildAuthorizationUri() {
        return this.authFlow.newAuthorizationUrl().setRedirectUri(redirectUri).build();
    }

    /**
     * Returns the principal authenticated by {@code token}.
     *
     * @param token an instance of {@link GoogleTokenResponse}.
     * @return the principal authenticated by {@code token}.
     */
    public final String getPrincipal(final GoogleTokenResponse token) {
        try {
            return token.parseIdToken().getPayload().getEmail();
        } catch (final IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    /**
     * Returns whether a given user is a member of the organization.
     *
     * @param userId the user's ID (typically his organization email address).
     * @return whether a given user is a member of the organization.
     */
    public final boolean isOrganizationMember(final String userId) {
        return isOrganizationMember(userId, false);
    }

    private final boolean isOrganizationMember(final String userId,
                                               final boolean forceCheck) {
        if (!forceCheck) {
            return this.authCache.get(userId);
        }

        final Credential credential = this.loadCredential(userId);

        if (credential == null) {
            return false;
        }

        final GoogleCredential googleCredential = new GoogleCredential().setAccessToken(credential.getAccessToken());

        final CloudResourceManager crm = new CloudResourceManager.Builder(
                HTTP_TRANSPORT,
                JSON_FACTORY,
                googleCredential).setApplicationName(this.authFlow.getClientId()).build();

        final List<Organization> organizations;

        try {
            organizations = crm.organizations().list().execute().getOrganizations();
        } catch (final IOException ex) {
            throw new UncheckedIOException(ex);
        }

        return organizations != null
                && organizations.stream().anyMatch(org -> this.organizationId.equals(org.getOrganizationId()));
    }

    /**
     * Loads the credential for the given user ID from the credential store.
     *
     * @param userId the user's ID.
     * @return the credential found in the credential store for the given user ID or {@code null} if none is found.
     */
    public final Credential loadCredential(final String userId) {
        try {
            return this.authFlow.loadCredential(userId);
        } catch (final IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    /**
     * Returns a {@link GoogleTokenResponse} corresponding to an authorization code token request based on the given
     * authorization code.
     *
     * @param authorizationCode the authorization code to use.
     * @return a {@link GoogleTokenResponse} corresponding to an auth code token request based on the given auth code.
     */
    public final GoogleTokenResponse requestToken(final String authorizationCode) {
        try {
            return this.authFlow.newTokenRequest(authorizationCode).setRedirectUri(this.redirectUri).execute();
        } catch (final IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    /**
     * Stores the credential corresponding to the specified {@link GoogleTokenResponse}.
     *
     * @param token an instance of {@link GoogleTokenResponse}.
     * @return the {@link Credential} corresponding to the specified {@link GoogleTokenResponse}.
     */
    public final Credential storeCredential(final GoogleTokenResponse token) {
        try {
            return this.authFlow.createAndStoreCredential(token, this.getPrincipal(token));
        } catch (final IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }
}
