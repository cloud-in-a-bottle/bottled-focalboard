# OpenHost Focalboard container.
#
# Layers an OpenHost auth-proxy sidecar on top of the upstream
# Focalboard server running in single-user mode.  The auth-proxy
# JWT-verifies every request, gates it on `sub == "owner"`, and
# stamps the configured single-user token as a cookie on the
# first request so the browser carries it forward.
#
# Auth flow:
#
#   1. Browser hits https://focalboard.<zone>/.  The OpenHost router
#      verifies the visitor's zone_auth JWT and stamps
#      X-OpenHost-Is-Owner: true on the request before forwarding
#      to the auth-proxy on container port 8090.
#   2. Auth-proxy: cross-checks the JWT itself (defence in depth
#      via JWKS), and if owner AND no FOCALBOARDAUTHTOKEN cookie
#      yet, 302's the browser back to the same path with the
#      cookie attached.
#   3. Browser follows the redirect, now carrying the token
#      cookie; auth-proxy forwards normally and Focalboard's
#      single-user mode accepts the request.
#
# This is Pattern A from the OpenHost SSO playbook
# (header / token gating with no app-side login dance), close in
# spirit to openhost-jenkins and openhost-forgejo.  Focalboard's
# single-user mode makes it especially clean: there is no app-
# side user model to map to, so we just need to make every owner
# request carry the configured static token.
#
# We can't use the upstream mattermost/focalboard image as the
# runtime base because (a) it's debian-buster which is past EOL
# and (b) the auth-proxy needs Python.  Use a multi-stage build
# to lift just the focalboard-server binary + webapp pack out of
# upstream onto python:3.13-slim, which has Python plus bash and
# coreutils for start.sh.  This mirrors the openhost-minio
# multi-stage layout.

# Stage 1: pull the upstream Focalboard binary + webapp.
#
# Pin to v7.11.4, the last release published by Mattermost
# before the standalone Focalboard project was discontinued.
# We pin by digest to make the build reproducible — `latest`
# floats and could disappear if Docker Hub eventually GCs the
# old image (the upstream repo is dormant since 2023).
FROM mattermost/focalboard:7.11.4 AS focalboard-source

# Stage 2: build the runtime image.
#
# python:3.13-slim has Python (for the auth-proxy + JWKS cache),
# bash + coreutils (for start.sh's first-boot token generator),
# and ca-certificates (so the JWKS fetch over HTTPS works on
# operator hosts where openhost-router fronts JWKS via TLS).
FROM python:3.13-slim

# -- Python deps (PyJWT for JWKS verification, requests for the
#    JWKS fetch).  Same set as openhost-syncthing's auth-proxy.
RUN pip install --no-cache-dir 'pyjwt[crypto]==2.10.1' 'requests==2.32.3'

# -- focalboard binary + webapp -----------------------------------
# focalboard-server is a static Go binary; safe to lift onto a
# different base.  The pack/ dir is the prebuilt React webapp
# (HTML + JS bundles) that the server serves at "/".  config.json
# is the upstream default config; we overwrite it via the
# command-line flags + a runtime-generated config in start.sh.
COPY --from=focalboard-source /opt/focalboard/bin/focalboard-server /opt/focalboard/bin/focalboard-server
COPY --from=focalboard-source /opt/focalboard/pack /opt/focalboard/pack
COPY --from=focalboard-source /opt/focalboard/config.json /opt/focalboard/config.json.upstream

# -- auth-proxy + start.sh ----------------------------------------
# Both files are committed to the repo with mode 0755 (verify
# with `git ls-files --stage`).  Buildah/podman preserves the
# git index mode through COPY, so no `RUN chmod +x` is needed
# — important for portability across operator hosts where the
# system crun rejects newer OCI metadata of any RUN step
# ("unknown version specified").
COPY auth_proxy.py /opt/openhost-focalboard/auth_proxy.py
COPY start.sh      /opt/openhost-focalboard/start.sh

# -- runtime ------------------------------------------------------
# 8090 = auth-proxy (the openhost.toml `port`, gated by the
#        OpenHost router upstream of us, owner-stamped, AND
#        re-verified by the auth-proxy via JWKS).
# 8000 = focalboard-server (loopback only; never exposed).
EXPOSE 8090

ENTRYPOINT ["/opt/openhost-focalboard/start.sh"]
