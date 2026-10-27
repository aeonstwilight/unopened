# Third-party notices

unopened itself is MIT licensed (see `LICENSE`).

## Data included in this repository

- `src/unopened/data/tlds.txt` is derived from the ICANN section of the
  [Public Suffix List](https://publicsuffix.org/), licensed under the
  [Mozilla Public License 2.0](https://mozilla.org/MPL/2.0/). The derived list is
  distributed under the same license; its source is the public list linked above.

All other data files under `src/unopened/data/` (allowlist, behavior patterns, brands,
LOLBins, import lists, script keywords) were written for this project and are MIT.

## Libraries

No third-party code is vendored in this repository. Libraries are installed by pip
and keep their own licenses. The Docker image bundles them, including:

| Library | License |
|---|---|
| pefile, signify, oscrypto, LnkParse3, pyzipper | MIT |
| oletools, pypdf, pycryptodomex | BSD |
| flare-capa, flare-floss, vivisect, yara-python | Apache-2.0 |
| py-tlsh | Apache-2.0 or BSD |
| defusedxml | PSF |
| py7zr, pybcj, pyppmd, inflate64, multivolumefile | LGPL-2.1-or-later |
| pycdlib | LGPL-2.1-only |

The LGPL libraries are used unmodified, as separately installed packages; their source
is available from PyPI and their upstream repositories.

capa rules, FLIRT signatures and YARA rules are not included; you supply your own.
