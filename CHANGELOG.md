## [1.0.2](https://github.com/evertrust/stream-mcp/compare/v1.0.1...v1.0.2) (2026-07-02)

### Bug Fixes

* MCP-spec compliance, security hardening, and live-QA verified tool fixes ([#9](https://github.com/evertrust/stream-mcp/issues/9)) ([35e821a](https://github.com/evertrust/stream-mcp/commit/35e821ad9807bc569feabd7dc3af408ddf3f60cf)), closes [PKCS#12](https://github.com/evertrust/PKCS/issues/12)

## [1.0.1](https://github.com/evertrust/stream-mcp/compare/v1.0.0...v1.0.1) (2026-06-18)

### Bug Fixes

* add repository metadata so the npm provenance publish succeeds ([#6](https://github.com/evertrust/stream-mcp/issues/6)) ([ed46a44](https://github.com/evertrust/stream-mcp/commit/ed46a4426d04677800c2d8c405967ba9c41495d4))

## 1.0.0 (2026-06-18)

### Features

* foundation (settings, auth, StreamClient, tool framework, resources) ([dc959f6](https://github.com/evertrust/stream-mcp/commit/dc959f620897b72a63049a3e7d3a684722a0fb11))
* implement all 12 tool domains (151 tools) + wire registry ([e9752fd](https://github.com/evertrust/stream-mcp/commit/e9752fd9fc57584efc69b3886a90a62495b8fd24))
* knowledge resources + search_docs/get_doc + README ([c9678f7](https://github.com/evertrust/stream-mcp/commit/c9678f7aee11cab3d9d6741482df2e540f8844b3))

### Bug Fixes

* address code-review addendum + accept PEM or DER for CRL upload ([aec939a](https://github.com/evertrust/stream-mcp/commit/aec939aa2119b12eebb8a3c5e61906bb295ba1fe))
* complex/maximal-payload live verification (310/317 elements confirmed on QA) ([a74a38a](https://github.com/evertrust/stream-mcp/commit/a74a38a1b5ff09ff1d9ba30eb8b21554399bad75))
* drop nonexistent Stream versions (2.0/2.2) from version warnings ([8f94c52](https://github.com/evertrust/stream-mcp/commit/8f94c52ed78c5438f482c5e76252fdc1604dce3d))
* live-verification bug fixes across all domains + foundation hardening ([c589dfb](https://github.com/evertrust/stream-mcp/commit/c589dfba9fa5be63d910d7c4087f6717bf8789e2))
* **security:** address Codex review findings (SSRF, HSM, revoke/integrity classification) ([869336b](https://github.com/evertrust/stream-mcp/commit/869336b5ff57572b74b7e4fad86b06b90559b614)), closes [PKCS#11](https://github.com/evertrust/PKCS/issues/11)
* update release.yml to target correct branch ([d2a397b](https://github.com/evertrust/stream-mcp/commit/d2a397b3d8275756a279beee88ae5cba65604520))
