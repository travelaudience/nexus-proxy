package com.travelaudience.nexus.proxy;

import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpClientResponse;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.RoutingContext;

/**
 * A basic class which proxies user requests to a Nexus instance, conveying authentication information.
 *
 * @see <a href="https://books.sonatype.com/nexus-book/reference3/security.html#remote-user-token">Authentication via Remote User Token</a>
 */
public final class NexusHttpProxy {
    private static final CharSequence X_FORWARDED_PROTO_HEADER = HttpHeaders.createOptimized("X-Forwarded-Proto");
    private static final CharSequence X_FORWARDED_FOR = HttpHeaders.createOptimized("X-Forwarded-For");

    private final String host;
    private final HttpClient httpClient;
    private final String nexusRutHeader;
    private final int port;

    private NexusHttpProxy(final Vertx vertx,
                           final String host,
                           final int port,
                           final String nexusRutHeader) {
        this.host = host;
        this.httpClient = vertx.createHttpClient();
        this.nexusRutHeader = nexusRutHeader;
        this.port = port;
    }

    /**
     * Creates a new instance of {@link NexusHttpProxy}.
     *
     * @param vertx          the base {@link Vertx} instance.
     * @param host           the host we will be proxying to.
     * @param port           the port we will be proxying to.
     * @param nexusRutHeader the name of the RUT authentication header as configured in Nexus.
     * @return a new instance of {@link NexusHttpProxy}.
     */
    public static final NexusHttpProxy create(final Vertx vertx,
                                              final String host,
                                              final int port,
                                              final String nexusRutHeader) {
        return new NexusHttpProxy(vertx, host, port, nexusRutHeader);
    }

    /**
     * Proxies the specified HTTP request, enriching its headers with authentication information.
     *
     * @param userId  the ID of the user making the request.
     * @param origReq the original request (i.e., {@link RoutingContext#request()}.
     * @param origRes the original response (i.e., {@link RoutingContext#request()}.
     */
    public void proxyUserRequest(final String userId,
                                 final HttpServerRequest origReq,
                                 final HttpServerResponse origRes) {
        final Handler<HttpClientResponse> proxiedResHandler = proxiedRes -> {
            origRes.setChunked(true);
            origRes.setStatusCode(proxiedRes.statusCode());
            origRes.headers().setAll(proxiedRes.headers());
            proxiedRes.handler(origRes::write);
            proxiedRes.endHandler(v -> origRes.end());
        };

        final HttpClientRequest proxiedReq;
        proxiedReq = httpClient.request(origReq.method(), port, host, origReq.uri(), proxiedResHandler);
        proxiedReq.setChunked(true);
        proxiedReq.headers().add(X_FORWARDED_PROTO_HEADER, origReq.scheme());
        proxiedReq.headers().add(X_FORWARDED_FOR, origReq.remoteAddress().host());
        proxiedReq.headers().addAll(origReq.headers());
        injectRutHeader(proxiedReq, userId);
        origReq.handler(proxiedReq::write);
        origReq.endHandler(v -> proxiedReq.end());
    }

    private final void injectRutHeader(final HttpClientRequest req,
                                       final String userId) {
        if (nexusRutHeader != null && nexusRutHeader.length() > 0 && userId != null && userId.length() > 0) {
            req.headers().add(nexusRutHeader, userId);
        }
    }
}
