package com.travelaudience.nexus.proxy;

import static com.travelaudience.nexus.proxy.ContextKeys.PROXY;
import static com.travelaudience.nexus.proxy.Paths.ALL_PATHS;
import static com.travelaudience.nexus.proxy.Paths.ROOT_PATH;

import com.google.common.primitives.Ints;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.net.PfxOptions;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.VirtualHostHandler;

import java.util.regex.Pattern;

public abstract class BaseNexusProxyVerticle extends AbstractVerticle {
    private static final String ALLOWED_USER_AGENTS_ON_ROOT_REGEX = System.getenv("ALLOWED_USER_AGENTS_ON_ROOT_REGEX");
    private static final Integer BIND_PORT = Ints.tryParse(System.getenv("BIND_PORT"));
    private static final String NEXUS_RUT_HEADER = System.getenv("NEXUS_RUT_HEADER");
    private static final String TLS_CERT_PK12_PATH = System.getenv("TLS_CERT_PK12_PATH");
    private static final String TLS_CERT_PK12_PASS = System.getenv("TLS_CERT_PK12_PASS");
    private static final Boolean TLS_ENABLED = Boolean.parseBoolean(System.getenv("TLS_ENABLED"));
    private static final Integer UPSTREAM_DOCKER_PORT = Ints.tryParse(System.getenv("UPSTREAM_DOCKER_PORT"));
    private static final String UPSTREAM_HOST = System.getenv("UPSTREAM_HOST");
    private static final Integer UPSTREAM_HTTP_PORT = Ints.tryParse(System.getenv("UPSTREAM_HTTP_PORT"));

    protected final String nexusDockerHost = System.getenv("NEXUS_DOCKER_HOST");
    protected final String nexusHttpHost = System.getenv("NEXUS_HTTP_HOST");

    /**
     * The pattern against which to match 'User-Agent' headers.
     */
    private static final Pattern ALLOWED_USER_AGENTS_ON_ROOT_PATTERN = Pattern.compile(
            ALLOWED_USER_AGENTS_ON_ROOT_REGEX,
            Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE
    );

    @Override
    public final void start() throws Exception {
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

        preconfigureRouting(router);

        router.route(ROOT_PATH).handler(ctx -> {
            final String agent = ctx.request().headers().get(HttpHeaders.USER_AGENT);

            if (agent != null && ALLOWED_USER_AGENTS_ON_ROOT_PATTERN.matcher(agent).find()) {
                ctx.response().setStatusCode(200).end();
            } else {
                ctx.next();
            }
        });

        router.route(ALL_PATHS).handler(VirtualHostHandler.create(nexusDockerHost, ctx -> {
            ctx.data().put(PROXY, dockerProxy);
            ctx.next();
        }));

        router.route(ALL_PATHS).handler(VirtualHostHandler.create(nexusHttpHost, ctx -> {
            ctx.data().put(PROXY, httpProxy);
            ctx.next();
        }));

        configureRouting(router);

        router.route(ALL_PATHS).handler(ctx -> {
            ((NexusHttpProxy) ctx.data().get(PROXY)).proxyUserRequest(getUserId(ctx), ctx.request(), ctx.response());
        });

        final PfxOptions pfxOptions = new PfxOptions().setPath(TLS_CERT_PK12_PATH).setPassword(TLS_CERT_PK12_PASS);

        vertx.createHttpServer(
                new HttpServerOptions().setSsl(TLS_ENABLED).setPfxKeyCertOptions(pfxOptions)
        ).requestHandler(
                router::accept
        ).listen(BIND_PORT);
    }

    /**
     * Configures the main routes. This will be called after {@link BaseNexusProxyVerticle#preconfigureRouting(Router)},
     * after user-agent checking on root and after the setup of virtual hosts handlers, but before the actual proxying.
     * @param router the {@link Router} which to configure.
     */
    protected abstract void configureRouting(final Router router);

    /**
     * Returns the currently authenticated user, or {@code null} if no valid authentication info is present.
     * @param ctx the current routing context.
     * @return the currently authenticated user, or {@code null} if no valid authentication info is present.
     */
    protected abstract String getUserId(final RoutingContext ctx);

    /**
     * Configures prerouting routes. This will be called right after the creation of {@code router}.
     * @param router the {@link Router} which to configure.
     */
    protected abstract void preconfigureRouting(final Router router);
}
