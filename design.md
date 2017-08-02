# Integrating Nexus authentication with Google Cloud IAM

**Attention**: all references to previous Nexus setup are linked to:
* https://github.com/travelaudience/docker-nexus
* https://github.com/travelaudience/docker-nexus-backup
* https://github.com/travelaudience/kubernetes-nexus

## Abstract

Sonatype Nexus OSS has no built-in support for SSO. Since GKE and other GCP resources in
use rely on one GCP organization users to authorize access to the same resources,
Cloud IAM is a good authentication backend against which to authenticate. As such, it was
decided that a SSO solution based on Cloud IAM should be developed.

This document focuses on the challenges of developing such as solution and integrating it
with build and deployment tools like Maven, Gradle and Docker. We will start by gathering
the requirements, then dive into identified problems and proposed solutions, and
ultimately conclude on how we may meet these requirements.

## Requirements

1. Block unauthenticated usage of Nexus repositories.
1. No user from outside a GCP organization shall be able to access Nexus or
   otherwise download or upload any artifacts or container images.
1. Members of the GCP organization must be able to authenticate themselves to
   Nexus in an in-browser environment using their GCP account credentials.
1. Members of the GCP organization must be able to authenticate themselves to
   Nexus in a CLI environment — e.g. when using Maven, Gradle or Docker — and download or
   upload artifacts.
1. At no moment in time shall Nexus, Maven, Gradle, Docker or any other tool deal with or
   have knowledge of the developer's raw credentials — which should remain a secret known
   only to the user.
1. Permissions for every member or group of members (role) of the GCP organization
   are configured within Nexus by an administrator and may be different for
   different users.

A couple of important notes must be made here:

* The last requirement deals with authorization rather than with authentication.
* Authorization must be made within Nexus and as such is out of the scope of this report.

## Potential Problems

### Organization Membership

Evaluating whether a user is a member of the GCP organization requires an API
call to the [Cloud Resource Manager API](https://goo.gl/9e3thP), from now on referred to
as CRM API, on behalf of the user. An OAuth2 authentication flow must thus be
established as part of the solution, and the user must grant the following scopes:

```
https://www.googleapis.com/auth/cloud-platform.read-only
https://www.googleapis.com/auth/userinfo.email
```

This means that the user must be presented an OAuth2 consent screen when accessing Nexus,
and only then organization membership can be evaluated. On the other hand there's a quota
of 100 read requests per 400 seconds on the CRM API. As such, it's not
hard to conclude that organization membership cannot be evaluated on every request. In
order to workaround this limitation, responses could be cached. The proposed caching
mechanism could work on a per-user basis and most probably a reasonable TTL would be
involved.

### Authenticating with CLI Tools

Maven, Gradle and Docker authenticate within Nexus in different ways. For instance, Maven
and Gradle use HTTP Basic Auth, but by default do so only when uploading artifacts. This
happens mainly because these tools assume that most downloaded artifacts come from public
repositories (Maven Central, JCenter and friends). When downloading artifacts from
private repositories these tools expect to be presented with an HTTP Basic Auth
challenge. Only then will they authenticate themselves. Hence, in order to meet the
requirements, one may have to configure _preemptive authentication_ so that every request
(`GET`, `HEAD`, and `PUT`) is authenticated. On the other hand, Docker also uses HTTP
Basic Auth but expects Nexus to always present a challenge. Thus, our solution needs to
be able to present Docker with such a challenge on behalf of Nexus in order to prevent
unauthorized access.

## Potential Solutions

### Cloud Identity-Aware Proxy

Google is currently introducing
[Cloud Identity-Aware Proxy](https://cloud.google.com/iap/docs/). This service sits in
front of an HTTPS-enabled GCLB and controlls access to upstream by verifying a user’s
identity and assigned permissions. The in-browser experience provided by Cloud IAP is
simple: an authenticated user with all the necessary permissions to access an application
will be allowed to browse the application, while unauthenticated users or users without
adequate permissions will be shown a big red exclamation mark and the message "You don't
have access".

The [authentication flow](https://cloud.google.com/iap/docs/authentication-howto) for CLI
apps is a bit more complex — the
user must obtain an _access token_ which is valid for one hour (despite being possible to
refresh it an infinite number of times) and use that _access token_ as a bearer token. It
is impossible as far as we know to use Bearer tokens with Maven and Gradle, which renders
Cloud IAP unusable in our scenario.

#### Pros

* Simple to setup and manage.
* Seamless in-browser experience.
* Seamless integration with GKE.

#### Cons

* Forces the use of bearer tokens for the authentication of CLI apps.
  * Maven and Gradle do not support this kind of authentication (although we could
    implement plug-ins for each one of these tools).
  * Even if they did, tokens would have to be refreshed manually on an hourly basis.
* `kube-lego`, the service many Kubernetes/GKE adopters use to configure HTTPS
 for the Nexus public load-balancer, cannot pass through Cloud IAP.
  * TLS certificates cannot be generated and installed without manual intervention.
  * Management of TLS certificates would become painful.

### GCP IAM-Aware Proxy for Nexus

We currently use an Nginx instance as a proxy to Nexus mostly to be able to serve Nexus'
Docker registry while keeping GCE's health checks happy by answering with `200 OK` on the
`GET /` endpoint. Our proposal is to replace Nginx with a custom HTTP proxy, and leverage
on Google's OAuth2 authorization flow and the Nexus RUT authentication realm to establish
and securely convey identity information.

In order to meet the aforementioned requirements and mitigate the potential problems that
we have identified, the proxy's workflow with respect to identity would be the following:

1. Alice opens https://nexus.example.com on her browser and has not active session.
   Alice is redirected towards Google's OAuth2 consent page.
1. After agreeing to the terms of the consent page, Alice is redirected back to the Nexus
   landing page by Google. Behind the scenes the proxy is given an authorization code. If
   Alice does not agree to the terms, either an error message is presented or the
   flow restarts.
1. The proxy exchanges this authorization code by both an _access_ and a _refresh token_.
   The former can be used to make authenticated requests to CRM API on
   behalf of Alice and expires in one hour, while the latter can be used to obtain access
   tokens _ad infinitum_.
1. The proxy stores the refresh token and uses the access token to obtain the list of all
   organizations Alice is a member of. If Alice is a member of the GCP organization, this info
   is cached for a given period of time and a session. If Alice is not a member of the
   GCP organization, access is denied and an error message is presented.
1. After (3) and (4) happen (in background), Alice is presented with the Nexus landing page.
   Alice's identity is now established at the proxy and conveyed to Nexus via the [RUT header](https://books.sonatype.com/nexus-book/reference/rutauth.html).
1. Everytime an HTTP request is made by Alice, the proxy queries the cache for membership
   information. If there's a hit the HTTP request/response cycle proceeds immediately. If
   there's a miss the HTTP request is put on hold while the proxy queries the CRM API for
   membership information. The result is then handled and a decision is made as described
   in (4).

As for CLI tools, the proposed flow is the following:

1. Alice visits https://nexus.example.com/cli/credentials. A JWT carrying identity
   information — namely the Alice's GCP organization email address — is generated and presented
   so that Alice can use in in tools like Maven, Gradle or Docker.
1. Alice instructs CLI tools to always use HTTP Basic Auth when making HTTP requests,
   a technique known to Maven and Gradle users as _preemptive authentication_. Every HTTP
   request made by the tools will now carry an `Authorization` header, containing Alice's
   email address as the username and the generated JWT token as the password.
1. Upon receiving an HTTP request with the `Authorization` header, the proxy will attempt
   to establish identity by validating the JWT. If validation fails, an error response is
   sent and the flow is interrupted If validation succeeds, the abovementioned membership
   cache is queried once again and the flow proceeds as detailed in (4) above.

A few remarks should be made here:

* No one except Google has knowledge of Alice's credentials.
* The generated JWT is in no way related and can in no way be used to call Google's APIs.
  It also doesn't contain any sensitive information, and is signed using RS256 (RSA 2048+
  with SHA-512 signature). It cannot be forged or tampered with in any way without access
  to the private key.
* As we cache membership information, latency is expected to be very low.

Finally, applications authenticating within the proxy using Google service accounts (e.g.
Jenkins) can provide their generated email addresses as the username and their private
key as the password as described in (2) above, since this private key is, to some extent,
analogous to a user's refresh token. Identity can then be established as described above.

#### Pros

* Easily integrates with the planned deployment — the proxy's basically a replacement for
  Nginx and will run as a sidecar container on the same pod as Nexus just as Nginx would.
* We end up with our own in-house implementation of IAP which we can tailor to every need
  shall APIs change or the need to support a new tool arises.
* We have full control about what checks are made on the users. If, for instance, we need
  to change the authentication criteria from Organization membership to something else we
  have the means and knowledge to do so.
* Simple to setup and manage — if it is not simple then we're not making it right.
* Seamless in-browser experience like in Cloud IAP.
* Out-of-the-box support for Maven, Gradle and Docker flows — we are coding against their
  requirements and behaviour.

#### Cons

* We're making our own security here, and it's no secret that _security is hard_. We must
  develop a comprehensive test suite covering as many scenarios as possible, and have the
  utmost concern at protecting the private key used to sign JWTs.

## Conclusion

As mentioned above, Cloud IAP is not compatible with the set of CLI tools used. It's easy
to conclude that it is not usable as a solution to our problem.

On the other hand and despite the _cons_ we have identified (which may even not be _cons_
at all, just things to keep in mind) the proxy solution seems to be a clever one — we are
replacing an external part with a part over which we have total control, and depending on
the chosen technologies a lot of work may already have been done for us.

If we end up going ahead with the in-house proxy we recommend that it is developed in the
Java language using the [Vert.x](http://vertx.io/) framework. We choose Java because
Google's SDKs for Java are very stable, mature and well-tested, and deal with the process
of obtaining, storing and refreshing credentials automatically. Vert.x is advised because
of its performance and ease of development: the proxying of HTTP requests is almost built
into Vert.x, as is JWT generation and validation.
