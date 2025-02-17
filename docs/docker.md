# LaunchDarkly Relay Proxy - Using with Docker

[(Back to README)](../README.md)

Using Docker is not required, but if you prefer using a Docker container we provide a Docker entrypoint to make this as easy as possible.

We provide images based on Alpine Linux and Google's 
["distroless"](https://github.com/GoogleContainerTools/distroless) Debian12 images. 

| Image              | Version                                                                                                                                            | Size                                                                                                                                                          | amd64 | armv7 | arm64v8 | i386 |
|--------------------|----------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|-------|-------|---------|------|
| Distroless         | [![Docker Image Version](https://img.shields.io/docker/v/launchdarkly/ld-relay/latest-static-debian12-nonroot)    ][dockerhub-distroless]          | [![Docker Image Size (tag)](https://img.shields.io/docker/image-size/launchdarkly/ld-relay/latest-static-debian12-nonroot)][dockerhub-distroless]             | ✅     | ✅     | ✅       | ❌    |                                                                                                   |
| Distroless (debug) | [![Docker Image Version](https://img.shields.io/docker/v/launchdarkly/ld-relay/latest-static-debian12-debug-nonroot) ][dockerhub-distroless-debug] | [![Docker Image Size (tag)](https://img.shields.io/docker/image-size/launchdarkly/ld-relay/latest-static-debian12-debug-nonroot)][dockerhub-distroless-debug] | ✅     | ✅     | ✅       | ❌    |
| Alpine             | [![Docker Image Version](https://img.shields.io/docker/v/launchdarkly/ld-relay/latest-alpine)                    ][dockerhub-alpine]               | [![Docker Image Size (tag)](https://img.shields.io/docker/image-size/launchdarkly/ld-relay/latest-alpine)][dockerhub-alpine]                                  | ✅     | ✅     | ✅       | ✅    |

We recommend using the Distroless images, as automated security scanners regularly flag issues in Alpine even though 
the Relay Proxy itself is unaffected. 

Because Relay Proxy is a statically linked Go binary, it can take advantage of the reduced dependencies in the 
Distroless base images.

## Local Development

When developing locally, you can build the `ld-relay` Alpine container with the following command:
```shell
$ docker build -t ld-relay .
```

Please note that this Alpine [Dockerfile](../Dockerfile) is **not** the same one that is published to 
[DockerHub](https://hub.docker.com/r/launchdarkly/ld-relay).

It is a convenience for local development, whereas the Alpine image published to DockerHub is built during our release 
process and is based on [Dockerfile.goreleaser](../Dockerfile.goreleaser).

In Docker, the config file is expected to be found at `/ldr/ld-relay.conf`, unless you are using environment variables 
to configure the Relay Proxy. To learn more, read [Configuration](./configuration.md).

## Local Development Examples

To run a single environment, without Redis:
```shell
$ docker run --name ld-relay -e LD_ENV_test="sdk-test-sdkKey" ld-relay
```

To run multiple environments, without Redis:
```shell
$ docker run --name ld-relay -e LD_ENV_test="sdk-test-sdkKey" -e LD_ENV_prod="sdk-prod-sdkKey" ld-relay
```

To run a single environment, with Redis:
```shell
$ docker run --name redis redis:alpine
$ docker run --name ld-relay --link redis:redis -e USE_REDIS=1 -e LD_ENV_test="sdk-test-sdkKey" ld-relay
```

To run multiple environment, with Redis:
```shell
$ docker run --name redis redis:alpine
$ docker run --name ld-relay --link redis:redis -e USE_REDIS=1 -e LD_ENV_test="sdk-test-sdkKey" -e LD_PREFIX_test="ld:default:test" -e LD_ENV_prod="sdk-prod-sdkKey" -e LD_PREFIX_prod="ld:default:prod" ld-relay
```

## Production Deployment

In production, you may choose between the Distroless or Alpine Linux images. 

Please note that the default Distroless image does not contain a shell. 

### Distroless Variants

Relay's Distroless images are distributed in two variants. The first is intended for regular usage, while the 
second is for debugging and contains a shell.

| Docker image tag suffix           | Based on [Distroless](https://github.com/GoogleContainerTools/distroless) tag.. | Purpose                  |
|-----------------------------------|---------------------------------------------------------------------------------|--------------------------|
| `-static-debian12-nonroot`        | `static-debian12:nonroot`                                                       | Normal usage             |
| `-static-debian12-debug-nonroot-` | `static-debian12:debug-nonroot`                                                 | Contains a busybox shell |

To enter the busybox shell for debugging purposes on a running container (only available in the `-debug-nonroot` 
variant):
```shell
docker exec -it [container name] /busybox/sh
```

[dockerhub-distroless]: https://hub.docker.com/r/launchdarkly/ld-relay/tags?page=&page_size=&ordering=&name=static-debian12-nonroot
[dockerhub-distroless-debug]: https://hub.docker.com/r/launchdarkly/ld-relay/tags?page=&page_size=&ordering=&name=static-debian12-debug-nonroot
[dockerhub-alpine]: https://hub.docker.com/r/launchdarkly/ld-relay/tags?page=&page_size=&ordering=&name=alpine

