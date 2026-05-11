# Changelog

## [2.3.0](https://github.com/radicand/forwardauth-rs/compare/forwardauth-rs-v2.2.0...forwardauth-rs-v2.3.0) (2026-05-11)


### Features

* add jwks-url config override for non-Auth0 OIDC providers ([30be683](https://github.com/radicand/forwardauth-rs/commit/30be683b7f50f71a4790f7a751d1bc0a6fa427eb))


### Bug Fixes

* discover JWKS URI from OIDC discovery document ([45b697a](https://github.com/radicand/forwardauth-rs/commit/45b697abcea35df87d17b0d2a927a6a15d01cdde))
* discover JWKS URI from OIDC discovery document ([4a20b59](https://github.com/radicand/forwardauth-rs/commit/4a20b59d4b6755d9c6da4543087ee3041d47bcf5))

## [2.2.0](https://github.com/radicand/forwardauth-rs/compare/forwardauth-rs-v2.1.1...forwardauth-rs-v2.2.0) (2026-04-15)


### Features

* add Dependabot configuration for Rust dependencies and auto-merge workflow ([875e440](https://github.com/radicand/forwardauth-rs/commit/875e440d2271d6bea9d1164d5e0cd1f63bad6b4e))
* add GitHub Actions workflow for build and test automation ([c64ef8b](https://github.com/radicand/forwardauth-rs/commit/c64ef8b78f600e05e411a6a991e78a05f8ad2e10))
* add release-please workflow for automated versioning and releases ([9c7a4e7](https://github.com/radicand/forwardauth-rs/commit/9c7a4e7604fd83e5b2272b538f55522adad04c1c))
* add weekly repo-maintainer skill, maintenance workflow, and OIDC e2e test suite ([05a32d5](https://github.com/radicand/forwardauth-rs/commit/05a32d556ceb14014219b8bee8b4ed4ec88755fd))
* automate patch releases when Dependabot PRs merge ([5bed0e8](https://github.com/radicand/forwardauth-rs/commit/5bed0e8c5be3a6a20ab1e41a3142cfdd30df37f5))
* efficient multi-platform builds with native ARM runners ([488797c](https://github.com/radicand/forwardauth-rs/commit/488797c12027ee025cee4b034c15626b04f7fa35))
* enhance Dependabot auto-merge workflow to include closed PRs and automate version bumping ([831eaf7](https://github.com/radicand/forwardauth-rs/commit/831eaf78ea54f71da6966bbe82afa77a28db0ac8))
* weekly repo-maintainer automation + OIDC e2e test suite ([8bf1439](https://github.com/radicand/forwardauth-rs/commit/8bf1439c603950404d4606d009d3832b24d0a313))


### Bug Fixes

* add release-please manifest file for version tracking ([ece9bc2](https://github.com/radicand/forwardauth-rs/commit/ece9bc29c2577625b86527cf82f453ace4b833ce))
* add release-please manifest to track version history ([9eaeb35](https://github.com/radicand/forwardauth-rs/commit/9eaeb35000f75849730ed04fa74d1ac281f35029))
* address CodeQL security alerts ([2b83e14](https://github.com/radicand/forwardauth-rs/commit/2b83e1444a9d8d70f1fd16f5b3f6880b0ea2630a))
* address CodeQL security alerts ([7f2f3b3](https://github.com/radicand/forwardauth-rs/commit/7f2f3b37786426df5a3ce4e4d04a6a5ef0fabb88))
* eliminate cache stampedes and harden readiness probe reliability ([3e42c49](https://github.com/radicand/forwardauth-rs/commit/3e42c49cff522ed95e57f7c958bc750e3464a513))
* eliminate JWKS/token cache stampedes and improve probe reliability ([ca3754d](https://github.com/radicand/forwardauth-rs/commit/ca3754d18e9efac1631060f5e1aa1f19d65a8803))
* install jsonwebtoken crypto provider in shared auth0 client initialization ([6f8ca58](https://github.com/radicand/forwardauth-rs/commit/6f8ca58ae766de291822d5e6db3dddc34f447189))
* install jsonwebtoken crypto provider in shared auth0 client initialization ([3de72c5](https://github.com/radicand/forwardauth-rs/commit/3de72c57a1a1b58812e24cdfceae7a8d4b0ab75c))
* make e2e suite functional + harden maintainer skill ([94e1565](https://github.com/radicand/forwardauth-rs/commit/94e1565a07f084be8fbbe32462ab453243f0b796))
* properly handle multi-line tags in manifest merge ([fe14797](https://github.com/radicand/forwardauth-rs/commit/fe147972fe2b3b386b7590741d36e1c4f073da5d))
* release-please workflow permissions, invalid input, and Node 24 warning ([a1b3c9c](https://github.com/radicand/forwardauth-rs/commit/a1b3c9c446c137bdeb815edac4b5ba7825e950bb))
* remove extra workflow ([44a9b23](https://github.com/radicand/forwardauth-rs/commit/44a9b23f23df5a35d1218f10646d456b3fd91467))
* remove extra workflow ([6acf3f4](https://github.com/radicand/forwardauth-rs/commit/6acf3f4ec8dbd80b13b0fb87b9ee7ebbad8c1c52))
* rewrite Traefik health check to avoid shell quoting issues in CI ([d47a6f5](https://github.com/radicand/forwardauth-rs/commit/d47a6f581f33ac592e53246025a52a7f39c1657b))
* sync Helm chart appVersion to 2.1.1 (weekly maintenance 2026-04-11) ([570e1e9](https://github.com/radicand/forwardauth-rs/commit/570e1e988732e311147c840a2fa90424deb89441))
* sync Helm chart appVersion to 2.1.1 and bump chart version to 1.1.1 ([3e17028](https://github.com/radicand/forwardauth-rs/commit/3e17028003714d471ce1e4e5ec5fa7b10b9a6a7a))
* sync Helm chart appVersion with v2.1.0 release ([27aad71](https://github.com/radicand/forwardauth-rs/commit/27aad71905ef513ddabace4ecbb22387189c8242))
* update Helm chart appVersion to 2.1.0 to match latest release ([8582f55](https://github.com/radicand/forwardauth-rs/commit/8582f55823c25b4e94b56e8ee6e38afe6380e61c))
* use docker buildx imagetools for manifest combinations ([4dd3af1](https://github.com/radicand/forwardauth-rs/commit/4dd3af164e4a847a5c804865dd57e516497dd185))
* use GH_PAT token, remove invalid package-name input, enable Node 24 ([2d8ea83](https://github.com/radicand/forwardauth-rs/commit/2d8ea83ec45d8df99ff1d8e664c52eab6dde720f))
* use latest Rust stable in Docker build ([6567dcb](https://github.com/radicand/forwardauth-rs/commit/6567dcb2569c943a28f998ce3f17e11dd0f3c085))

## [2.1.1](https://github.com/radicand/forwardauth-rs/compare/v2.1.0...v2.1.1) (2026-04-07)


### Bug Fixes

* eliminate cache stampedes and harden readiness probe reliability ([3e42c49](https://github.com/radicand/forwardauth-rs/commit/3e42c49cff522ed95e57f7c958bc750e3464a513))
* eliminate JWKS/token cache stampedes and improve probe reliability ([ca3754d](https://github.com/radicand/forwardauth-rs/commit/ca3754d18e9efac1631060f5e1aa1f19d65a8803))
* sync Helm chart appVersion with v2.1.0 release ([27aad71](https://github.com/radicand/forwardauth-rs/commit/27aad71905ef513ddabace4ecbb22387189c8242))
* update Helm chart appVersion to 2.1.0 to match latest release ([8582f55](https://github.com/radicand/forwardauth-rs/commit/8582f55823c25b4e94b56e8ee6e38afe6380e61c))

## [2.1.0](https://github.com/radicand/forwardauth-rs/compare/v2.0.0...v2.1.0) (2026-04-05)


### Features

* add Dependabot configuration for Rust dependencies and auto-merge workflow ([875e440](https://github.com/radicand/forwardauth-rs/commit/875e440d2271d6bea9d1164d5e0cd1f63bad6b4e))
* add GitHub Actions workflow for build and test automation ([c64ef8b](https://github.com/radicand/forwardauth-rs/commit/c64ef8b78f600e05e411a6a991e78a05f8ad2e10))
* add release-please workflow for automated versioning and releases ([9c7a4e7](https://github.com/radicand/forwardauth-rs/commit/9c7a4e7604fd83e5b2272b538f55522adad04c1c))
* add weekly repo-maintainer skill, maintenance workflow, and OIDC e2e test suite ([05a32d5](https://github.com/radicand/forwardauth-rs/commit/05a32d556ceb14014219b8bee8b4ed4ec88755fd))
* automate patch releases when Dependabot PRs merge ([5bed0e8](https://github.com/radicand/forwardauth-rs/commit/5bed0e8c5be3a6a20ab1e41a3142cfdd30df37f5))
* enhance Dependabot auto-merge workflow to include closed PRs and automate version bumping ([831eaf7](https://github.com/radicand/forwardauth-rs/commit/831eaf78ea54f71da6966bbe82afa77a28db0ac8))
* weekly repo-maintainer automation + OIDC e2e test suite ([8bf1439](https://github.com/radicand/forwardauth-rs/commit/8bf1439c603950404d4606d009d3832b24d0a313))


### Bug Fixes

* add release-please manifest file for version tracking ([ece9bc2](https://github.com/radicand/forwardauth-rs/commit/ece9bc29c2577625b86527cf82f453ace4b833ce))
* add release-please manifest to track version history ([9eaeb35](https://github.com/radicand/forwardauth-rs/commit/9eaeb35000f75849730ed04fa74d1ac281f35029))
* address CodeQL security alerts ([2b83e14](https://github.com/radicand/forwardauth-rs/commit/2b83e1444a9d8d70f1fd16f5b3f6880b0ea2630a))
* address CodeQL security alerts ([7f2f3b3](https://github.com/radicand/forwardauth-rs/commit/7f2f3b37786426df5a3ce4e4d04a6a5ef0fabb88))
* install jsonwebtoken crypto provider in shared auth0 client initialization ([6f8ca58](https://github.com/radicand/forwardauth-rs/commit/6f8ca58ae766de291822d5e6db3dddc34f447189))
* install jsonwebtoken crypto provider in shared auth0 client initialization ([3de72c5](https://github.com/radicand/forwardauth-rs/commit/3de72c57a1a1b58812e24cdfceae7a8d4b0ab75c))
* make e2e suite functional + harden maintainer skill ([94e1565](https://github.com/radicand/forwardauth-rs/commit/94e1565a07f084be8fbbe32462ab453243f0b796))
* release-please workflow permissions, invalid input, and Node 24 warning ([a1b3c9c](https://github.com/radicand/forwardauth-rs/commit/a1b3c9c446c137bdeb815edac4b5ba7825e950bb))
* remove extra workflow ([44a9b23](https://github.com/radicand/forwardauth-rs/commit/44a9b23f23df5a35d1218f10646d456b3fd91467))
* remove extra workflow ([6acf3f4](https://github.com/radicand/forwardauth-rs/commit/6acf3f4ec8dbd80b13b0fb87b9ee7ebbad8c1c52))
* rewrite Traefik health check to avoid shell quoting issues in CI ([d47a6f5](https://github.com/radicand/forwardauth-rs/commit/d47a6f581f33ac592e53246025a52a7f39c1657b))
* use GH_PAT token, remove invalid package-name input, enable Node 24 ([2d8ea83](https://github.com/radicand/forwardauth-rs/commit/2d8ea83ec45d8df99ff1d8e664c52eab6dde720f))
