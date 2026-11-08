# Security-Patched Build-Time Deepmerge

Upstream: https://github.com/TehShrike/deepmerge, release 4.3.1 (MIT).
The bundled npm `dist/cjs.js` baseline SHA256 is
`2e5160f84a1141bd927264afe4d15766f1e6cf07daef182b37ff53fea121de7d`.
The bundled is-mergeable-object predicate is retained; no runtime dependency
or API change is intended.

GHSA-gcqx-w48m-w2h4 / CVE-2026-93753 is reproducible in the upstream release.
There is no newer published stable upstream version at this review.
Noid replaces the three `destination[key] = value` writes in `mergeObject`
with `Object.defineProperty` data-property writes. This prevents invoking
inherited setters, including `__proto__`, when copying either input.
Enumerable symbols, recursion, array/custom merge options and `.all` remain.

The fork is build-time only, selected by an npm override for
vite-plugin-svelte. Its local version is not proof of advisory remediation:
`node --test vendor/deepmerge/security.test.cjs` tests the actual implementation.
Remove the override when an upstream fixed stable release is available.
