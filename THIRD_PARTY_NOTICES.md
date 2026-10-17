# Third-party software notices and source access

Mayi admits the exact P0 protocol/JOSE/PostgreSQL Go module graph recorded below. MPL-covered components are unmodified; corresponding source archives are linked for recipients. This notice does not assign a license to Mayi's first-party source.

The complete Mozilla Public License 2.0 text is retained at [tools/license-evidence/MPL-2.0.txt](tools/license-evidence/MPL-2.0.txt). For every admitted MPL component, the table below must identify the exact unmodified version and an accessible source archive. That source remains available under MPL 2.0, including its notices and recipients' rights. Modifications to covered files must also be made available under MPL 2.0; an unmodified upstream link is insufficient for modified files.

| Admitted MPL component and version | Source code under MPL 2.0 |
| --- | --- |
| github.com/go-sql-driver/mysql@v1.9.0 | [Source archive](https://proxy.golang.org/github.com/go-sql-driver/mysql/@v/v1.9.0.zip) |
| github.com/hashicorp/consul/api@v1.20.0 | [Source archive](https://proxy.golang.org/github.com/hashicorp/consul/api/@v/v1.20.0.zip) |
| github.com/hashicorp/errwrap@v1.1.0 | [Source archive](https://proxy.golang.org/github.com/hashicorp/errwrap/@v/v1.1.0.zip) |
| github.com/hashicorp/go-cleanhttp@v0.5.2 | [Source archive](https://proxy.golang.org/github.com/hashicorp/go-cleanhttp/@v/v0.5.2.zip) |
| github.com/hashicorp/go-immutable-radix@v1.3.1 | [Source archive](https://proxy.golang.org/github.com/hashicorp/go-immutable-radix/@v/v1.3.1.zip) |
| github.com/hashicorp/go-multierror@v1.1.1 | [Source archive](https://proxy.golang.org/github.com/hashicorp/go-multierror/@v/v1.1.1.zip) |
| github.com/hashicorp/go-retryablehttp@v0.7.7 | [Source archive](https://proxy.golang.org/github.com/hashicorp/go-retryablehttp/@v/v0.7.7.zip) |
| github.com/hashicorp/go-rootcerts@v1.0.2 | [Source archive](https://proxy.golang.org/github.com/hashicorp/go-rootcerts/@v/v1.0.2.zip) |
| github.com/hashicorp/go-uuid@v1.0.3 | [Source archive](https://proxy.golang.org/github.com/hashicorp/go-uuid/@v/v1.0.3.zip) |
| github.com/hashicorp/golang-lru@v0.5.4 | [Source archive](https://proxy.golang.org/github.com/hashicorp/golang-lru/@v/v0.5.4.zip) |
| github.com/hashicorp/hcl@v1.0.0 | [Source archive](https://proxy.golang.org/github.com/hashicorp/hcl/@v/v1.0.0.zip) |
| github.com/hashicorp/serf@v0.10.1 | [Source archive](https://proxy.golang.org/github.com/hashicorp/serf/@v/v0.10.1.zip) |

Distributions must include this notice, the license texts and copyright/NOTICE material for every distributed dependency, and working access to the corresponding MPL source. Copying this document into the repository does not prove that a binary/container distribution includes those materials. Add and test release packaging before distributing binaries. Preserve source availability; use a maintained source mirror if an upstream URL becomes unavailable.

The compiler and reviewed GitHub Actions are recorded in [tools/dependencies.json](tools/dependencies.json). Complete action-bundle license and notice evidence is retained under [tools/license-evidence](tools/license-evidence). Exact module approvals, license evidence hashes and source-access fields are checked by CI. Generated source, forks and copied third-party files require their own review.

See the [dependency policy](docs/dependency-policy.md), [MPL license](https://www.mozilla.org/MPL/2.0/), and [Mozilla's distribution FAQ](https://www.mozilla.org/MPL/2.0/FAQ/#q8-i-want-to-distribute-outside-my-organization-executable-programs-or-libraries-that-i-have-compiled-from-someone-elses-unchanged-mpl-licensed-source-code-either-standalone-or-part-of-a-larger-work-what-do-i-have-to-do).

## All admitted Go modules

Complete license and copyright/NOTICE text is retained in [tools/license-evidence/go-modules.txt](tools/license-evidence/go-modules.txt). Upstream test datasets are not shipped or executed.

| Module and version | Licenses | Source |
| --- | --- | --- |
| cel.dev/expr@v0.25.2 | Apache-2.0 | [Archive](https://proxy.golang.org/cel.dev/expr/@v/v0.25.2.zip) |
| cloud.google.com/go@v0.110.0 | Apache-2.0, BSD-3-Clause | [Archive](https://proxy.golang.org/cloud.google.com/go/@v/v0.110.0.zip) |
| cloud.google.com/go/auth@v0.20.0 | Apache-2.0 | [Archive](https://proxy.golang.org/cloud.google.com/go/auth/@v/v0.20.0.zip) |
| cloud.google.com/go/bigquery@v1.8.0 | Apache-2.0 | [Archive](https://proxy.golang.org/cloud.google.com/go/bigquery/@v/v1.8.0.zip) |
| cloud.google.com/go/compute@v1.19.0 | Apache-2.0 | [Archive](https://proxy.golang.org/cloud.google.com/go/compute/@v/v1.19.0.zip) |
| cloud.google.com/go/compute/metadata@v0.9.0 | Apache-2.0 | [Archive](https://proxy.golang.org/cloud.google.com/go/compute/metadata/@v/v0.9.0.zip) |
| cloud.google.com/go/datastore@v1.1.0 | Apache-2.0 | [Archive](https://proxy.golang.org/cloud.google.com/go/datastore/@v/v1.1.0.zip) |
| cloud.google.com/go/firestore@v1.9.0 | Apache-2.0 | [Archive](https://proxy.golang.org/cloud.google.com/go/firestore/@v/v1.9.0.zip) |
| cloud.google.com/go/longrunning@v0.4.1 | Apache-2.0 | [Archive](https://proxy.golang.org/cloud.google.com/go/longrunning/@v/v0.4.1.zip) |
| cloud.google.com/go/pubsub@v1.3.1 | Apache-2.0 | [Archive](https://proxy.golang.org/cloud.google.com/go/pubsub/@v/v1.3.1.zip) |
| cloud.google.com/go/storage@v1.14.0 | Apache-2.0 | [Archive](https://proxy.golang.org/cloud.google.com/go/storage/@v/v1.14.0.zip) |
| code.dny.dev/ssrf@v0.2.0 | MIT | [Archive](https://proxy.golang.org/code.dny.dev/ssrf/@v/v0.2.0.zip) |
| dario.cat/mergo@v1.0.1 | BSD-3-Clause | [Archive](https://proxy.golang.org/dario.cat/mergo/@v/v1.0.1.zip) |
| dmitri.shuralyov.com/gpu/mtl@v0.0.0-20190408044501-666a987793e9 | BSD-3-Clause | [Archive](https://proxy.golang.org/dmitri.shuralyov.com/gpu/mtl/@v/v0.0.0-20190408044501-666a987793e9.zip) |
| filippo.io/edwards25519@v1.1.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/filippo.io/edwards25519/@v/v1.1.0.zip) |
| github.com/Azure/go-ansiterm@v0.0.0-20250102033503-faa5f7b0171c | MIT | [Archive](https://proxy.golang.org/github.com/!azure/go-ansiterm/@v/v0.0.0-20250102033503-faa5f7b0171c.zip) |
| github.com/BurntSushi/toml@v0.3.1 | MIT | [Archive](https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v0.3.1.zip) |
| github.com/BurntSushi/xgb@v0.0.0-20160522181843-27f122750802 | BSD-3-Clause, WTFPL | [Archive](https://proxy.golang.org/github.com/!burnt!sushi/xgb/@v/v0.0.0-20160522181843-27f122750802.zip) |
| github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp@v1.34.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/!google!cloud!platform/opentelemetry-operations-go/detectors/gcp/@v/v1.34.0.zip) |
| github.com/IBM/sarama@v1.43.1 | MIT | [Archive](https://proxy.golang.org/github.com/!i!b!m/sarama/@v/v1.43.1.zip) |
| github.com/Masterminds/semver/v3@v3.3.1 | MIT | [Archive](https://proxy.golang.org/github.com/!masterminds/semver/v3/@v/v3.3.1.zip) |
| github.com/Microsoft/go-winio@v0.6.2 | MIT | [Archive](https://proxy.golang.org/github.com/!microsoft/go-winio/@v/v0.6.2.zip) |
| github.com/Nvveen/Gotty@v0.0.0-20120604004816-cd527374f1e5 | BSD-2-Clause | [Archive](https://proxy.golang.org/github.com/!nvveen/!gotty/@v/v0.0.0-20120604004816-cd527374f1e5.zip) |
| github.com/apapsch/go-jsonmerge/v2@v2.0.0 | MIT | [Archive](https://proxy.golang.org/github.com/apapsch/go-jsonmerge/v2/@v/v2.0.0.zip) |
| github.com/armon/go-metrics@v0.4.0 | MIT | [Archive](https://proxy.golang.org/github.com/armon/go-metrics/@v/v0.4.0.zip) |
| github.com/asaskevich/govalidator@v0.0.0-20230301143203-a9d515a09cc2 | MIT | [Archive](https://proxy.golang.org/github.com/asaskevich/govalidator/@v/v0.0.0-20230301143203-a9d515a09cc2.zip) |
| github.com/auth0/go-jwt-middleware/v2@v2.3.0 | MIT | [Archive](https://proxy.golang.org/github.com/auth0/go-jwt-middleware/v2/@v/v2.3.0.zip) |
| github.com/avast/retry-go/v4@v4.6.1 | MIT | [Archive](https://proxy.golang.org/github.com/avast/retry-go/v4/@v/v4.6.1.zip) |
| github.com/aymerick/douceur@v0.2.0 | MIT | [Archive](https://proxy.golang.org/github.com/aymerick/douceur/@v/v0.2.0.zip) |
| github.com/beorn7/perks@v1.0.1 | MIT | [Archive](https://proxy.golang.org/github.com/beorn7/perks/@v/v1.0.1.zip) |
| github.com/bmatcuk/doublestar/v2@v2.0.4 | MIT | [Archive](https://proxy.golang.org/github.com/bmatcuk/doublestar/v2/@v/v2.0.4.zip) |
| github.com/bradleyjkemp/cupaloy/v2@v2.8.0 | MIT | [Archive](https://proxy.golang.org/github.com/bradleyjkemp/cupaloy/v2/@v/v2.8.0.zip) |
| github.com/cenkalti/backoff/v4@v4.3.0 | MIT | [Archive](https://proxy.golang.org/github.com/cenkalti/backoff/v4/@v/v4.3.0.zip) |
| github.com/cenkalti/backoff/v5@v5.0.3 | MIT | [Archive](https://proxy.golang.org/github.com/cenkalti/backoff/v5/@v/v5.0.3.zip) |
| github.com/census-instrumentation/opencensus-proto@v0.2.1 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/census-instrumentation/opencensus-proto/@v/v0.2.1.zip) |
| github.com/cespare/xxhash/v2@v2.3.0 | MIT | [Archive](https://proxy.golang.org/github.com/cespare/xxhash/v2/@v/v2.3.0.zip) |
| github.com/chzyer/logex@v1.2.1 | MIT | [Archive](https://proxy.golang.org/github.com/chzyer/logex/@v/v1.2.1.zip) |
| github.com/chzyer/readline@v0.0.0-20180603132655-2972be24d48e | MIT | [Archive](https://proxy.golang.org/github.com/chzyer/readline/@v/v0.0.0-20180603132655-2972be24d48e.zip) |
| github.com/chzyer/test@v0.0.0-20180213035817-a1ea475d72b1 | MIT | [Archive](https://proxy.golang.org/github.com/chzyer/test/@v/v0.0.0-20180213035817-a1ea475d72b1.zip) |
| github.com/client9/misspell@v0.3.4 | MIT | [Archive](https://proxy.golang.org/github.com/client9/misspell/@v/v0.3.4.zip) |
| github.com/cncf/udpa/go@v0.0.0-20201120205902-5459f2c99403 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/cncf/udpa/go/@v/v0.0.0-20201120205902-5459f2c99403.zip) |
| github.com/cncf/xds/go@v0.0.0-20260202195803-dba9d589def2 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/cncf/xds/go/@v/v0.0.0-20260202195803-dba9d589def2.zip) |
| github.com/cockroachdb/cockroach-go/v2@v2.4.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/cockroachdb/cockroach-go/v2/@v/v2.4.0.zip) |
| github.com/containerd/continuity@v0.4.5 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/containerd/continuity/@v/v0.4.5.zip) |
| github.com/coreos/go-semver@v0.3.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/coreos/go-semver/@v/v0.3.0.zip) |
| github.com/coreos/go-systemd/v22@v22.3.2 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/coreos/go-systemd/v22/@v/v22.3.2.zip) |
| github.com/cpuguy83/go-md2man/v2@v2.0.6 | MIT | [Archive](https://proxy.golang.org/github.com/cpuguy83/go-md2man/v2/@v/v2.0.6.zip) |
| github.com/cristalhq/jwt/v4@v4.0.2 | MIT | [Archive](https://proxy.golang.org/github.com/cristalhq/jwt/v4/@v/v4.0.2.zip) |
| github.com/davecgh/go-spew@v1.1.1 | ISC | [Archive](https://proxy.golang.org/github.com/davecgh/go-spew/@v/v1.1.1.zip) |
| github.com/decred/dcrd/dcrec/secp256k1/v4@v4.3.0 | ISC | [Archive](https://proxy.golang.org/github.com/decred/dcrd/dcrec/secp256k1/v4/@v/v4.3.0.zip) |
| github.com/dgraph-io/ristretto@v1.0.0 | Apache-2.0, MIT | [Archive](https://proxy.golang.org/github.com/dgraph-io/ristretto/@v/v1.0.0.zip) |
| github.com/dgraph-io/ristretto/v2@v2.1.0 | Apache-2.0, MIT | [Archive](https://proxy.golang.org/github.com/dgraph-io/ristretto/v2/@v/v2.1.0.zip) |
| github.com/dgryski/go-farm@v0.0.0-20200201041132-a6ae2369ad13 | MIT | [Archive](https://proxy.golang.org/github.com/dgryski/go-farm/@v/v0.0.0-20200201041132-a6ae2369ad13.zip) |
| github.com/distribution/reference@v0.6.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/distribution/reference/@v/v0.6.0.zip) |
| github.com/docker/cli@v28.0.1+incompatible | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/docker/cli/@v/v28.0.1+incompatible.zip) |
| github.com/docker/docker@v28.0.1+incompatible | Apache-2.0, MIT | [Archive](https://proxy.golang.org/github.com/docker/docker/@v/v28.0.1+incompatible.zip) |
| github.com/docker/go-connections@v0.5.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/docker/go-connections/@v/v0.5.0.zip) |
| github.com/docker/go-units@v0.5.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/docker/go-units/@v/v0.5.0.zip) |
| github.com/dustin/go-humanize@v1.0.1 | MIT | [Archive](https://proxy.golang.org/github.com/dustin/go-humanize/@v/v1.0.1.zip) |
| github.com/eapache/go-resiliency@v1.6.0 | MIT | [Archive](https://proxy.golang.org/github.com/eapache/go-resiliency/@v/v1.6.0.zip) |
| github.com/eapache/go-xerial-snappy@v0.0.0-20230731223053-c322873962e3 | MIT | [Archive](https://proxy.golang.org/github.com/eapache/go-xerial-snappy/@v/v0.0.0-20230731223053-c322873962e3.zip) |
| github.com/eapache/queue@v1.1.0 | MIT | [Archive](https://proxy.golang.org/github.com/eapache/queue/@v/v1.1.0.zip) |
| github.com/elazarl/goproxy@v0.0.0-20221015165544-a0805db90819 | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/elazarl/goproxy/@v/v0.0.0-20221015165544-a0805db90819.zip) |
| github.com/envoyproxy/go-control-plane@v0.14.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/envoyproxy/go-control-plane/@v/v0.14.0.zip) |
| github.com/envoyproxy/go-control-plane/envoy@v1.37.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/envoyproxy/go-control-plane/envoy/@v/v1.37.0.zip) |
| github.com/envoyproxy/go-control-plane/ratelimit@v0.1.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/envoyproxy/go-control-plane/ratelimit/@v/v0.1.0.zip) |
| github.com/envoyproxy/protoc-gen-validate@v1.3.3 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/envoyproxy/protoc-gen-validate/@v/v1.3.3.zip) |
| github.com/evanphx/json-patch/v5@v5.9.11 | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/evanphx/json-patch/v5/@v/v5.9.11.zip) |
| github.com/fatih/color@v1.18.0 | MIT | [Archive](https://proxy.golang.org/github.com/fatih/color/@v/v1.18.0.zip) |
| github.com/fatih/structs@v1.1.0 | MIT | [Archive](https://proxy.golang.org/github.com/fatih/structs/@v/v1.1.0.zip) |
| github.com/felixge/fgprof@v0.9.5 | MIT | [Archive](https://proxy.golang.org/github.com/felixge/fgprof/@v/v0.9.5.zip) |
| github.com/felixge/httpsnoop@v1.1.0 | MIT | [Archive](https://proxy.golang.org/github.com/felixge/httpsnoop/@v/v1.1.0.zip) |
| github.com/frankban/quicktest@v1.14.6 | MIT | [Archive](https://proxy.golang.org/github.com/frankban/quicktest/@v/v1.14.6.zip) |
| github.com/fsnotify/fsnotify@v1.8.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/fsnotify/fsnotify/@v/v1.8.0.zip) |
| github.com/ghodss/yaml@v1.0.0 | BSD-3-Clause, MIT | [Archive](https://proxy.golang.org/github.com/ghodss/yaml/@v/v1.0.0.zip) |
| github.com/go-gl/glfw@v0.0.0-20190409004039-e6da0acd62b1 | BSD-3-Clause, Zlib | [Archive](https://proxy.golang.org/github.com/go-gl/glfw/@v/v0.0.0-20190409004039-e6da0acd62b1.zip) |
| github.com/go-gl/glfw/v3.3/glfw@v0.0.0-20200222043503-6f7a984d4dc4 | BSD-3-Clause, Zlib | [Archive](https://proxy.golang.org/github.com/go-gl/glfw/v3.3/glfw/@v/v0.0.0-20200222043503-6f7a984d4dc4.zip) |
| github.com/go-jose/go-jose/v3@v3.0.5 | Apache-2.0, BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/go-jose/go-jose/v3/@v/v3.0.5.zip) |
| github.com/go-jose/go-jose/v4@v4.1.6 | Apache-2.0, BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/go-jose/go-jose/v4/@v/v4.1.6.zip) |
| github.com/go-logr/logr@v1.4.4 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/go-logr/logr/@v/v1.4.4.zip) |
| github.com/go-logr/stdr@v1.2.2 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/go-logr/stdr/@v/v1.2.2.zip) |
| github.com/go-openapi/analysis@v0.25.5 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/go-openapi/analysis/@v/v0.25.5.zip) |
| github.com/go-openapi/errors@v0.22.8 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/go-openapi/errors/@v/v0.22.8.zip) |
| github.com/go-openapi/jsonpointer@v1.0.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/go-openapi/jsonpointer/@v/v1.0.0.zip) |
| github.com/go-openapi/jsonreference@v1.0.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/go-openapi/jsonreference/@v/v1.0.0.zip) |
| github.com/go-openapi/loads@v0.25.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/go-openapi/loads/@v/v0.25.0.zip) |
| github.com/go-openapi/runtime@v0.33.0 | Apache-2.0, MIT | [Archive](https://proxy.golang.org/github.com/go-openapi/runtime/@v/v0.33.0.zip) |
| github.com/go-openapi/runtime/server-middleware@v0.30.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/go-openapi/runtime/server-middleware/@v/v0.30.0.zip) |
| github.com/go-openapi/spec@v0.22.9 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/go-openapi/spec/@v/v0.22.9.zip) |
| github.com/go-openapi/strfmt@v0.27.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/go-openapi/strfmt/@v/v0.27.0.zip) |
| github.com/go-openapi/swag@v0.28.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/go-openapi/swag/@v/v0.28.0.zip) |
| github.com/go-openapi/swag/cmdutils@v0.28.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/go-openapi/swag/cmdutils/@v/v0.28.0.zip) |
| github.com/go-openapi/swag/conv@v0.28.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/go-openapi/swag/conv/@v/v0.28.0.zip) |
| github.com/go-openapi/swag/fileutils@v0.28.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/go-openapi/swag/fileutils/@v/v0.28.0.zip) |
| github.com/go-openapi/swag/jsonutils@v0.28.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/go-openapi/swag/jsonutils/@v/v0.28.0.zip) |
| github.com/go-openapi/swag/loading@v0.28.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/go-openapi/swag/loading/@v/v0.28.0.zip) |
| github.com/go-openapi/swag/mangling@v0.28.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/go-openapi/swag/mangling/@v/v0.28.0.zip) |
| github.com/go-openapi/swag/netutils@v0.28.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/go-openapi/swag/netutils/@v/v0.28.0.zip) |
| github.com/go-openapi/swag/pools@v0.28.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/go-openapi/swag/pools/@v/v0.28.0.zip) |
| github.com/go-openapi/swag/stringutils@v0.28.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/go-openapi/swag/stringutils/@v/v0.28.0.zip) |
| github.com/go-openapi/swag/typeutils@v0.28.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/go-openapi/swag/typeutils/@v/v0.28.0.zip) |
| github.com/go-openapi/swag/yamlutils@v0.28.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/go-openapi/swag/yamlutils/@v/v0.28.0.zip) |
| github.com/go-openapi/validate@v0.26.1 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/go-openapi/validate/@v/v0.26.1.zip) |
| github.com/go-sql-driver/mysql@v1.9.0 | MPL-2.0 | [Archive](https://proxy.golang.org/github.com/go-sql-driver/mysql/@v/v1.9.0.zip) |
| github.com/go-task/slim-sprig@v0.0.0-20230315185526-52ccab3ef572 | MIT | [Archive](https://proxy.golang.org/github.com/go-task/slim-sprig/@v/v0.0.0-20230315185526-52ccab3ef572.zip) |
| github.com/go-viper/mapstructure/v2@v2.5.0 | MIT | [Archive](https://proxy.golang.org/github.com/go-viper/mapstructure/v2/@v/v2.5.0.zip) |
| github.com/gobuffalo/attrs@v1.0.3 | MIT | [Archive](https://proxy.golang.org/github.com/gobuffalo/attrs/@v/v1.0.3.zip) |
| github.com/gobuffalo/envy@v1.10.2 | MIT | [Archive](https://proxy.golang.org/github.com/gobuffalo/envy/@v/v1.10.2.zip) |
| github.com/gobuffalo/fizz@v1.14.4 | MIT | [Archive](https://proxy.golang.org/github.com/gobuffalo/fizz/@v/v1.14.4.zip) |
| github.com/gobuffalo/flect@v1.0.3 | MIT | [Archive](https://proxy.golang.org/github.com/gobuffalo/flect/@v/v1.0.3.zip) |
| github.com/gobuffalo/genny/v2@v2.1.0 | MIT | [Archive](https://proxy.golang.org/github.com/gobuffalo/genny/v2/@v/v2.1.0.zip) |
| github.com/gobuffalo/github_flavored_markdown@v1.1.4 | BSD-2-Clause, MIT | [Archive](https://proxy.golang.org/github.com/gobuffalo/github_flavored_markdown/@v/v1.1.4.zip) |
| github.com/gobuffalo/helpers@v0.6.7 | MIT | [Archive](https://proxy.golang.org/github.com/gobuffalo/helpers/@v/v0.6.7.zip) |
| github.com/gobuffalo/httptest@v1.5.2 | BSD-3-Clause, MIT | [Archive](https://proxy.golang.org/github.com/gobuffalo/httptest/@v/v1.5.2.zip) |
| github.com/gobuffalo/logger@v1.0.7 | MIT | [Archive](https://proxy.golang.org/github.com/gobuffalo/logger/@v/v1.0.7.zip) |
| github.com/gobuffalo/nulls@v0.4.2 | MIT | [Archive](https://proxy.golang.org/github.com/gobuffalo/nulls/@v/v0.4.2.zip) |
| github.com/gobuffalo/packd@v1.0.2 | MIT | [Archive](https://proxy.golang.org/github.com/gobuffalo/packd/@v/v1.0.2.zip) |
| github.com/gobuffalo/plush/v4@v4.1.22 | MIT | [Archive](https://proxy.golang.org/github.com/gobuffalo/plush/v4/@v/v4.1.22.zip) |
| github.com/gobuffalo/pop/v6@v6.1.1 | MIT | [Archive](https://proxy.golang.org/github.com/gobuffalo/pop/v6/@v/v6.1.1.zip) |
| github.com/gobuffalo/tags/v3@v3.1.4 | MIT | [Archive](https://proxy.golang.org/github.com/gobuffalo/tags/v3/@v/v3.1.4.zip) |
| github.com/gobuffalo/validate/v3@v3.3.3 | MIT | [Archive](https://proxy.golang.org/github.com/gobuffalo/validate/v3/@v/v3.3.3.zip) |
| github.com/gobwas/glob@v0.2.3 | MIT | [Archive](https://proxy.golang.org/github.com/gobwas/glob/@v/v0.2.3.zip) |
| github.com/goccy/go-json@v0.10.5 | MIT | [Archive](https://proxy.golang.org/github.com/goccy/go-json/@v/v0.10.5.zip) |
| github.com/goccy/go-yaml@v1.16.0 | MIT | [Archive](https://proxy.golang.org/github.com/goccy/go-yaml/@v/v1.16.0.zip) |
| github.com/gofrs/flock@v0.12.1 | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/gofrs/flock/@v/v0.12.1.zip) |
| github.com/gofrs/uuid@v4.4.0+incompatible | MIT | [Archive](https://proxy.golang.org/github.com/gofrs/uuid/@v/v4.4.0+incompatible.zip) |
| github.com/gogo/protobuf@v1.3.2 | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/gogo/protobuf/@v/v1.3.2.zip) |
| github.com/golang-jwt/jwt/v5@v5.2.2 | MIT | [Archive](https://proxy.golang.org/github.com/golang-jwt/jwt/v5/@v/v5.2.2.zip) |
| github.com/golang/glog@v1.2.5 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/golang/glog/@v/v1.2.5.zip) |
| github.com/golang/groupcache@v0.0.0-20210331224755-41bb18bfe9da | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/golang/groupcache/@v/v0.0.0-20210331224755-41bb18bfe9da.zip) |
| github.com/golang/mock@v1.6.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/golang/mock/@v/v1.6.0.zip) |
| github.com/golang/protobuf@v1.5.4 | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/golang/protobuf/@v/v1.5.4.zip) |
| github.com/golang/snappy@v0.0.4 | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/golang/snappy/@v/v0.0.4.zip) |
| github.com/google/btree@v1.0.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/google/btree/@v/v1.0.0.zip) |
| github.com/google/go-cmp@v0.7.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/google/go-cmp/@v/v0.7.0.zip) |
| github.com/google/go-jsonnet@v0.20.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/google/go-jsonnet/@v/v0.20.0.zip) |
| github.com/google/martian@v2.1.0+incompatible | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/google/martian/@v/v2.1.0+incompatible.zip) |
| github.com/google/martian/v3@v3.1.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/google/martian/v3/@v/v3.1.0.zip) |
| github.com/google/pprof@v0.0.0-20250315033105-103756e64e1d | Apache-2.0, BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/google/pprof/@v/v0.0.0-20250315033105-103756e64e1d.zip) |
| github.com/google/renameio@v0.1.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/google/renameio/@v/v0.1.0.zip) |
| github.com/google/s2a-go@v0.1.9 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/google/s2a-go/@v/v0.1.9.zip) |
| github.com/google/shlex@v0.0.0-20191202100458-e7afc7fbc510 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/google/shlex/@v/v0.0.0-20191202100458-e7afc7fbc510.zip) |
| github.com/google/uuid@v1.6.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/google/uuid/@v/v1.6.0.zip) |
| github.com/googleapis/enterprise-certificate-proxy@v0.3.15 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/googleapis/enterprise-certificate-proxy/@v/v0.3.15.zip) |
| github.com/googleapis/gax-go/v2@v2.22.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/googleapis/gax-go/v2/@v/v2.22.0.zip) |
| github.com/googleapis/google-cloud-go-testing@v0.0.0-20200911160855-bcd43fbb19e8 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/googleapis/google-cloud-go-testing/@v/v0.0.0-20200911160855-bcd43fbb19e8.zip) |
| github.com/gorilla/css@v1.0.1 | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/gorilla/css/@v/v1.0.1.zip) |
| github.com/gorilla/mux@v1.8.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/gorilla/mux/@v/v1.8.0.zip) |
| github.com/gorilla/websocket@v1.5.3 | BSD-2-Clause | [Archive](https://proxy.golang.org/github.com/gorilla/websocket/@v/v1.5.3.zip) |
| github.com/grpc-ecosystem/go-grpc-prometheus@v1.2.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/grpc-ecosystem/go-grpc-prometheus/@v/v1.2.0.zip) |
| github.com/grpc-ecosystem/grpc-gateway/v2@v2.30.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/grpc-ecosystem/grpc-gateway/v2/@v/v2.30.0.zip) |
| github.com/hashicorp/consul/api@v1.20.0 | MPL-2.0 | [Archive](https://proxy.golang.org/github.com/hashicorp/consul/api/@v/v1.20.0.zip) |
| github.com/hashicorp/errwrap@v1.1.0 | MPL-2.0 | [Archive](https://proxy.golang.org/github.com/hashicorp/errwrap/@v/v1.1.0.zip) |
| github.com/hashicorp/go-cleanhttp@v0.5.2 | MPL-2.0 | [Archive](https://proxy.golang.org/github.com/hashicorp/go-cleanhttp/@v/v0.5.2.zip) |
| github.com/hashicorp/go-hclog@v1.6.3 | MIT | [Archive](https://proxy.golang.org/github.com/hashicorp/go-hclog/@v/v1.6.3.zip) |
| github.com/hashicorp/go-immutable-radix@v1.3.1 | MPL-2.0 | [Archive](https://proxy.golang.org/github.com/hashicorp/go-immutable-radix/@v/v1.3.1.zip) |
| github.com/hashicorp/go-multierror@v1.1.1 | MPL-2.0 | [Archive](https://proxy.golang.org/github.com/hashicorp/go-multierror/@v/v1.1.1.zip) |
| github.com/hashicorp/go-retryablehttp@v0.7.7 | MPL-2.0 | [Archive](https://proxy.golang.org/github.com/hashicorp/go-retryablehttp/@v/v0.7.7.zip) |
| github.com/hashicorp/go-rootcerts@v1.0.2 | MPL-2.0 | [Archive](https://proxy.golang.org/github.com/hashicorp/go-rootcerts/@v/v1.0.2.zip) |
| github.com/hashicorp/go-uuid@v1.0.3 | MPL-2.0 | [Archive](https://proxy.golang.org/github.com/hashicorp/go-uuid/@v/v1.0.3.zip) |
| github.com/hashicorp/golang-lru@v0.5.4 | MPL-2.0 | [Archive](https://proxy.golang.org/github.com/hashicorp/golang-lru/@v/v0.5.4.zip) |
| github.com/hashicorp/hcl@v1.0.0 | MPL-2.0 | [Archive](https://proxy.golang.org/github.com/hashicorp/hcl/@v/v1.0.0.zip) |
| github.com/hashicorp/serf@v0.10.1 | MPL-2.0 | [Archive](https://proxy.golang.org/github.com/hashicorp/serf/@v/v0.10.1.zip) |
| github.com/ianlancetaylor/demangle@v0.0.0-20200824232613-28f6c0f3b639 | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/ianlancetaylor/demangle/@v/v0.0.0-20200824232613-28f6c0f3b639.zip) |
| github.com/inconshreveable/mousetrap@v1.1.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/inconshreveable/mousetrap/@v/v1.1.0.zip) |
| github.com/inhies/go-bytesize@v0.0.0-20220417184213-4913239db9cf | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/inhies/go-bytesize/@v/v0.0.0-20220417184213-4913239db9cf.zip) |
| github.com/jackc/chunkreader/v2@v2.0.1 | MIT | [Archive](https://proxy.golang.org/github.com/jackc/chunkreader/v2/@v/v2.0.1.zip) |
| github.com/jackc/pgconn@v1.14.3 | MIT | [Archive](https://proxy.golang.org/github.com/jackc/pgconn/@v/v1.14.3.zip) |
| github.com/jackc/pgio@v1.0.0 | MIT | [Archive](https://proxy.golang.org/github.com/jackc/pgio/@v/v1.0.0.zip) |
| github.com/jackc/pgpassfile@v1.0.0 | MIT | [Archive](https://proxy.golang.org/github.com/jackc/pgpassfile/@v/v1.0.0.zip) |
| github.com/jackc/pgproto3/v2@v2.3.3 | MIT | [Archive](https://proxy.golang.org/github.com/jackc/pgproto3/v2/@v/v2.3.3.zip) |
| github.com/jackc/pgservicefile@v0.0.0-20240606120523-5a60cdf6a761 | MIT | [Archive](https://proxy.golang.org/github.com/jackc/pgservicefile/@v/v0.0.0-20240606120523-5a60cdf6a761.zip) |
| github.com/jackc/pgtype@v1.14.4 | MIT | [Archive](https://proxy.golang.org/github.com/jackc/pgtype/@v/v1.14.4.zip) |
| github.com/jackc/pgx/v4@v4.18.3 | MIT | [Archive](https://proxy.golang.org/github.com/jackc/pgx/v4/@v/v4.18.3.zip) |
| github.com/jackc/pgx/v5@v5.11.0 | MIT | [Archive](https://proxy.golang.org/github.com/jackc/pgx/v5/@v/v5.11.0.zip) |
| github.com/jackc/puddle/v2@v2.2.2 | MIT | [Archive](https://proxy.golang.org/github.com/jackc/puddle/v2/@v/v2.2.2.zip) |
| github.com/jandelgado/gcov2lcov@v1.1.1 | MIT | [Archive](https://proxy.golang.org/github.com/jandelgado/gcov2lcov/@v/v1.1.1.zip) |
| github.com/jcmturner/aescts/v2@v2.0.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/jcmturner/aescts/v2/@v/v2.0.0.zip) |
| github.com/jcmturner/dnsutils/v2@v2.0.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/jcmturner/dnsutils/v2/@v/v2.0.0.zip) |
| github.com/jcmturner/gofork@v1.7.6 | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/jcmturner/gofork/@v/v1.7.6.zip) |
| github.com/jcmturner/gokrb5/v8@v8.4.4 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/jcmturner/gokrb5/v8/@v/v8.4.4.zip) |
| github.com/jcmturner/rpc/v2@v2.0.3 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/jcmturner/rpc/v2/@v/v2.0.3.zip) |
| github.com/jmoiron/sqlx@v1.4.0 | MIT | [Archive](https://proxy.golang.org/github.com/jmoiron/sqlx/@v/v1.4.0.zip) |
| github.com/joho/godotenv@v1.5.1 | MIT | [Archive](https://proxy.golang.org/github.com/joho/godotenv/@v/v1.5.1.zip) |
| github.com/josharian/intern@v1.0.0 | MIT | [Archive](https://proxy.golang.org/github.com/josharian/intern/@v/v1.0.0.zip) |
| github.com/json-iterator/go@v1.1.12 | MIT | [Archive](https://proxy.golang.org/github.com/json-iterator/go/@v/v1.1.12.zip) |
| github.com/jstemmer/go-junit-report@v0.9.1 | MIT | [Archive](https://proxy.golang.org/github.com/jstemmer/go-junit-report/@v/v0.9.1.zip) |
| github.com/julienschmidt/httprouter@v1.3.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/julienschmidt/httprouter/@v/v1.3.0.zip) |
| github.com/kballard/go-shellquote@v0.0.0-20180428030007-95032a82bc51 | MIT | [Archive](https://proxy.golang.org/github.com/kballard/go-shellquote/@v/v0.0.0-20180428030007-95032a82bc51.zip) |
| github.com/kisielk/errcheck@v1.5.0 | MIT | [Archive](https://proxy.golang.org/github.com/kisielk/errcheck/@v/v1.5.0.zip) |
| github.com/kisielk/gotool@v1.0.0 | MIT | [Archive](https://proxy.golang.org/github.com/kisielk/gotool/@v/v1.0.0.zip) |
| github.com/klauspost/compress@v1.17.11 | Apache-2.0, BSD-3-Clause, MIT | [Archive](https://proxy.golang.org/github.com/klauspost/compress/@v/v1.17.11.zip) |
| github.com/knadh/koanf/maps@v0.1.1 | MIT | [Archive](https://proxy.golang.org/github.com/knadh/koanf/maps/@v/v0.1.1.zip) |
| github.com/knadh/koanf/parsers/json@v0.1.0 | MIT | [Archive](https://proxy.golang.org/github.com/knadh/koanf/parsers/json/@v/v0.1.0.zip) |
| github.com/knadh/koanf/parsers/toml@v0.1.0 | MIT | [Archive](https://proxy.golang.org/github.com/knadh/koanf/parsers/toml/@v/v0.1.0.zip) |
| github.com/knadh/koanf/parsers/yaml@v0.1.0 | MIT | [Archive](https://proxy.golang.org/github.com/knadh/koanf/parsers/yaml/@v/v0.1.0.zip) |
| github.com/knadh/koanf/providers/posflag@v0.1.0 | MIT | [Archive](https://proxy.golang.org/github.com/knadh/koanf/providers/posflag/@v/v0.1.0.zip) |
| github.com/knadh/koanf/providers/rawbytes@v0.1.0 | MIT | [Archive](https://proxy.golang.org/github.com/knadh/koanf/providers/rawbytes/@v/v0.1.0.zip) |
| github.com/knadh/koanf/v2@v2.1.2 | MIT | [Archive](https://proxy.golang.org/github.com/knadh/koanf/v2/@v/v2.1.2.zip) |
| github.com/kr/fs@v0.1.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/kr/fs/@v/v0.1.0.zip) |
| github.com/kr/pretty@v0.3.1 | MIT | [Archive](https://proxy.golang.org/github.com/kr/pretty/@v/v0.3.1.zip) |
| github.com/kr/pty@v1.1.1 | MIT | [Archive](https://proxy.golang.org/github.com/kr/pty/@v/v1.1.1.zip) |
| github.com/kr/text@v0.2.0 | MIT | [Archive](https://proxy.golang.org/github.com/kr/text/@v/v0.2.0.zip) |
| github.com/laher/mergefs@v0.1.1 | MIT | [Archive](https://proxy.golang.org/github.com/laher/mergefs/@v/v0.1.1.zip) |
| github.com/lestrrat-go/backoff/v2@v2.0.8 | MIT | [Archive](https://proxy.golang.org/github.com/lestrrat-go/backoff/v2/@v/v2.0.8.zip) |
| github.com/lestrrat-go/blackmagic@v1.0.2 | MIT | [Archive](https://proxy.golang.org/github.com/lestrrat-go/blackmagic/@v/v1.0.2.zip) |
| github.com/lestrrat-go/httpcc@v1.0.1 | MIT | [Archive](https://proxy.golang.org/github.com/lestrrat-go/httpcc/@v/v1.0.1.zip) |
| github.com/lestrrat-go/iter@v1.0.2 | MIT | [Archive](https://proxy.golang.org/github.com/lestrrat-go/iter/@v/v1.0.2.zip) |
| github.com/lestrrat-go/jwx@v1.2.30 | MIT | [Archive](https://proxy.golang.org/github.com/lestrrat-go/jwx/@v/v1.2.30.zip) |
| github.com/lestrrat-go/option@v1.0.1 | MIT | [Archive](https://proxy.golang.org/github.com/lestrrat-go/option/@v/v1.0.1.zip) |
| github.com/lib/pq@v1.10.9 | MIT | [Archive](https://proxy.golang.org/github.com/lib/pq/@v/v1.10.9.zip) |
| github.com/luna-duclos/instrumentedsql@v1.1.3 | MIT | [Archive](https://proxy.golang.org/github.com/luna-duclos/instrumentedsql/@v/v1.1.3.zip) |
| github.com/magiconair/properties@v1.8.7 | BSD-2-Clause | [Archive](https://proxy.golang.org/github.com/magiconair/properties/@v/v1.8.7.zip) |
| github.com/mailru/easyjson@v0.9.0 | MIT | [Archive](https://proxy.golang.org/github.com/mailru/easyjson/@v/v0.9.0.zip) |
| github.com/mattn/go-colorable@v0.1.14 | MIT | [Archive](https://proxy.golang.org/github.com/mattn/go-colorable/@v/v0.1.14.zip) |
| github.com/mattn/go-isatty@v0.0.20 | MIT | [Archive](https://proxy.golang.org/github.com/mattn/go-isatty/@v/v0.0.20.zip) |
| github.com/mattn/go-sqlite3@v1.14.24 | MIT | [Archive](https://proxy.golang.org/github.com/mattn/go-sqlite3/@v/v1.14.24.zip) |
| github.com/mattn/goveralls@v0.0.12 | MIT | [Archive](https://proxy.golang.org/github.com/mattn/goveralls/@v/v0.0.12.zip) |
| github.com/microcosm-cc/bluemonday@v1.0.27 | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/microcosm-cc/bluemonday/@v/v1.0.27.zip) |
| github.com/mitchellh/copystructure@v1.2.0 | MIT | [Archive](https://proxy.golang.org/github.com/mitchellh/copystructure/@v/v1.2.0.zip) |
| github.com/mitchellh/go-homedir@v1.1.0 | MIT | [Archive](https://proxy.golang.org/github.com/mitchellh/go-homedir/@v/v1.1.0.zip) |
| github.com/mitchellh/mapstructure@v1.5.0 | MIT | [Archive](https://proxy.golang.org/github.com/mitchellh/mapstructure/@v/v1.5.0.zip) |
| github.com/mitchellh/reflectwalk@v1.0.2 | MIT | [Archive](https://proxy.golang.org/github.com/mitchellh/reflectwalk/@v/v1.0.2.zip) |
| github.com/moby/docker-image-spec@v1.3.1 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/moby/docker-image-spec/@v/v1.3.1.zip) |
| github.com/moby/sys/user@v0.3.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/moby/sys/user/@v/v0.3.0.zip) |
| github.com/moby/term@v0.5.2 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/moby/term/@v/v0.5.2.zip) |
| github.com/modern-go/concurrent@v0.0.0-20180306012644-bacd9c7ef1dd | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/modern-go/concurrent/@v/v0.0.0-20180306012644-bacd9c7ef1dd.zip) |
| github.com/modern-go/reflect2@v1.0.2 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/modern-go/reflect2/@v/v1.0.2.zip) |
| github.com/mohae/deepcopy@v0.0.0-20170929034955-c48cc78d4826 | MIT | [Archive](https://proxy.golang.org/github.com/mohae/deepcopy/@v/v0.0.0-20170929034955-c48cc78d4826.zip) |
| github.com/morikuni/aec@v1.0.0 | MIT | [Archive](https://proxy.golang.org/github.com/morikuni/aec/@v/v1.0.0.zip) |
| github.com/moul/http2curl@v0.0.0-20170919181001-9ac6cf4d929b | MIT | [Archive](https://proxy.golang.org/github.com/moul/http2curl/@v/v0.0.0-20170919181001-9ac6cf4d929b.zip) |
| github.com/munnerz/goautoneg@v0.0.0-20191010083416-a7dc8b61c822 | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/munnerz/goautoneg/@v/v0.0.0-20191010083416-a7dc8b61c822.zip) |
| github.com/nyaruka/phonenumbers@v1.5.0 | MIT | [Archive](https://proxy.golang.org/github.com/nyaruka/phonenumbers/@v/v1.5.0.zip) |
| github.com/oapi-codegen/runtime@v1.6.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/oapi-codegen/runtime/@v/v1.6.0.zip) |
| github.com/oklog/ulid@v1.3.1 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/oklog/ulid/@v/v1.3.1.zip) |
| github.com/oklog/ulid/v2@v2.1.1 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/oklog/ulid/v2/@v/v2.1.1.zip) |
| github.com/oleiade/reflections@v1.0.1 | MIT | [Archive](https://proxy.golang.org/github.com/oleiade/reflections/@v/v1.0.1.zip) |
| github.com/onsi/ginkgo/v2@v2.11.0 | MIT | [Archive](https://proxy.golang.org/github.com/onsi/ginkgo/v2/@v/v2.11.0.zip) |
| github.com/onsi/gomega@v1.27.10 | MIT | [Archive](https://proxy.golang.org/github.com/onsi/gomega/@v/v1.27.10.zip) |
| github.com/opencontainers/go-digest@v1.0.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/opencontainers/go-digest/@v/v1.0.0.zip) |
| github.com/opencontainers/image-spec@v1.1.1 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/opencontainers/image-spec/@v/v1.1.1.zip) |
| github.com/opencontainers/runc@v1.2.5 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/opencontainers/runc/@v/v1.2.5.zip) |
| github.com/openzipkin/zipkin-go@v0.4.3 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/openzipkin/zipkin-go/@v/v0.4.3.zip) |
| github.com/ory/analytics-go/v5@v5.0.1 | MIT | [Archive](https://proxy.golang.org/github.com/ory/analytics-go/v5/@v/v5.0.1.zip) |
| github.com/ory/dockertest/v3@v3.11.0 | Apache-2.0, BSD-2-Clause | [Archive](https://proxy.golang.org/github.com/ory/dockertest/v3/@v/v3.11.0.zip) |
| github.com/ory/fosite@v0.49.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/ory/fosite/@v/v0.49.0.zip) |
| github.com/ory/go-acc@v0.2.9-0.20230103102148-6b1c9a70dbbe | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/ory/go-acc/@v/v0.2.9-0.20230103102148-6b1c9a70dbbe.zip) |
| github.com/ory/go-convenience@v0.1.0 | MIT | [Archive](https://proxy.golang.org/github.com/ory/go-convenience/@v/v0.1.0.zip) |
| github.com/ory/herodot@v0.10.3-0.20250318104651-3179543efba8 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/ory/herodot/@v/v0.10.3-0.20250318104651-3179543efba8.zip) |
| github.com/ory/jsonschema/v3@v3.0.9-0.20250317235931-280c5fc7bf0e | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/ory/jsonschema/v3/@v/v3.0.9-0.20250317235931-280c5fc7bf0e.zip) |
| github.com/ory/pop/v6@v6.3.0 | MIT | [Archive](https://proxy.golang.org/github.com/ory/pop/v6/@v/v6.3.0.zip) |
| github.com/ory/x@v0.0.729 | Apache-2.0, MIT | [Archive](https://proxy.golang.org/github.com/ory/x/@v/v0.0.729.zip) |
| github.com/parnurzeal/gorequest@v0.2.15 | MIT | [Archive](https://proxy.golang.org/github.com/parnurzeal/gorequest/@v/v0.2.15.zip) |
| github.com/pelletier/go-toml@v1.9.5 | Apache-2.0, MIT | [Archive](https://proxy.golang.org/github.com/pelletier/go-toml/@v/v1.9.5.zip) |
| github.com/pelletier/go-toml/v2@v2.0.9 | MIT | [Archive](https://proxy.golang.org/github.com/pelletier/go-toml/v2/@v/v2.0.9.zip) |
| github.com/peterhellberg/link@v1.2.0 | MIT | [Archive](https://proxy.golang.org/github.com/peterhellberg/link/@v/v1.2.0.zip) |
| github.com/pierrec/lz4/v4@v4.1.21 | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/pierrec/lz4/v4/@v/v4.1.21.zip) |
| github.com/pkg/errors@v0.9.1 | BSD-2-Clause | [Archive](https://proxy.golang.org/github.com/pkg/errors/@v/v0.9.1.zip) |
| github.com/pkg/profile@v1.7.0 | BSD-2-Clause | [Archive](https://proxy.golang.org/github.com/pkg/profile/@v/v1.7.0.zip) |
| github.com/pkg/sftp@v1.13.1 | BSD-2-Clause | [Archive](https://proxy.golang.org/github.com/pkg/sftp/@v/v1.13.1.zip) |
| github.com/planetscale/vtprotobuf@v0.6.1-0.20240319094008-0393e58bdf10 | BSD-3-Clause, MIT | [Archive](https://proxy.golang.org/github.com/planetscale/vtprotobuf/@v/v0.6.1-0.20240319094008-0393e58bdf10.zip) |
| github.com/pmezard/go-difflib@v1.0.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/pmezard/go-difflib/@v/v1.0.0.zip) |
| github.com/prometheus/client_golang@v1.21.1 | Apache-2.0, BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/prometheus/client_golang/@v/v1.21.1.zip) |
| github.com/prometheus/client_model@v0.6.1 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/prometheus/client_model/@v/v0.6.1.zip) |
| github.com/prometheus/common@v0.63.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/prometheus/common/@v/v0.63.0.zip) |
| github.com/prometheus/procfs@v0.15.1 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/prometheus/procfs/@v/v0.15.1.zip) |
| github.com/rabbitmq/amqp091-go@v1.9.0 | BSD-2-Clause | [Archive](https://proxy.golang.org/github.com/rabbitmq/amqp091-go/@v/v1.9.0.zip) |
| github.com/rakutentech/jwk-go@v1.2.0 | MIT | [Archive](https://proxy.golang.org/github.com/rakutentech/jwk-go/@v/v1.2.0.zip) |
| github.com/rcrowley/go-metrics@v0.0.0-20201227073835-cf1acfcdf475 | BSD-2-Clause | [Archive](https://proxy.golang.org/github.com/rcrowley/go-metrics/@v/v0.0.0-20201227073835-cf1acfcdf475.zip) |
| github.com/rogpeppe/fastuuid@v1.2.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/rogpeppe/fastuuid/@v/v1.2.0.zip) |
| github.com/rogpeppe/go-internal@v1.14.1 | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/rogpeppe/go-internal/@v/v1.14.1.zip) |
| github.com/rs/cors@v1.11.1 | MIT | [Archive](https://proxy.golang.org/github.com/rs/cors/@v/v1.11.1.zip) |
| github.com/russross/blackfriday/v2@v2.1.0 | BSD-2-Clause | [Archive](https://proxy.golang.org/github.com/russross/blackfriday/v2/@v/v2.1.0.zip) |
| github.com/sagikazarmark/crypt@v0.10.0 | MIT | [Archive](https://proxy.golang.org/github.com/sagikazarmark/crypt/@v/v0.10.0.zip) |
| github.com/seatgeek/logrus-gelf-formatter@v0.0.0-20210414080842-5b05eb8ff761 | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/seatgeek/logrus-gelf-formatter/@v/v0.0.0-20210414080842-5b05eb8ff761.zip) |
| github.com/segmentio/backo-go@v1.1.0 | MIT | [Archive](https://proxy.golang.org/github.com/segmentio/backo-go/@v/v1.1.0.zip) |
| github.com/sergi/go-diff@v1.3.1 | MIT | [Archive](https://proxy.golang.org/github.com/sergi/go-diff/@v/v1.3.1.zip) |
| github.com/sirupsen/logrus@v1.9.3 | MIT | [Archive](https://proxy.golang.org/github.com/sirupsen/logrus/@v/v1.9.3.zip) |
| github.com/smartystreets/goconvey@v1.6.4 | Apache-2.0, MIT | [Archive](https://proxy.golang.org/github.com/smartystreets/goconvey/@v/v1.6.4.zip) |
| github.com/sourcegraph/annotate@v0.0.0-20160123013949-f4cad6c6324d | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/sourcegraph/annotate/@v/v0.0.0-20160123013949-f4cad6c6324d.zip) |
| github.com/sourcegraph/syntaxhighlight@v0.0.0-20170531221838-bd320f5d308e | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/sourcegraph/syntaxhighlight/@v/v0.0.0-20170531221838-bd320f5d308e.zip) |
| github.com/spf13/afero@v1.9.5 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/spf13/afero/@v/v1.9.5.zip) |
| github.com/spf13/cast@v1.7.1 | MIT | [Archive](https://proxy.golang.org/github.com/spf13/cast/@v/v1.7.1.zip) |
| github.com/spf13/cobra@v1.9.1 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/spf13/cobra/@v/v1.9.1.zip) |
| github.com/spf13/jwalterweatherman@v1.1.0 | MIT | [Archive](https://proxy.golang.org/github.com/spf13/jwalterweatherman/@v/v1.1.0.zip) |
| github.com/spf13/pflag@v1.0.6 | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/spf13/pflag/@v/v1.0.6.zip) |
| github.com/spf13/viper@v1.16.0 | MIT | [Archive](https://proxy.golang.org/github.com/spf13/viper/@v/v1.16.0.zip) |
| github.com/spiffe/go-spiffe/v2@v2.8.1 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/spiffe/go-spiffe/v2/@v/v2.8.1.zip) |
| github.com/ssoready/hyrumtoken@v1.0.0 | MIT | [Archive](https://proxy.golang.org/github.com/ssoready/hyrumtoken/@v/v1.0.0.zip) |
| github.com/stretchr/objx@v0.5.3 | MIT | [Archive](https://proxy.golang.org/github.com/stretchr/objx/@v/v0.5.3.zip) |
| github.com/stretchr/testify@v1.12.1 | BSD-3-Clause, ISC, MIT | [Archive](https://proxy.golang.org/github.com/stretchr/testify/@v/v1.12.1.zip) |
| github.com/subosito/gotenv@v1.4.2 | MIT | [Archive](https://proxy.golang.org/github.com/subosito/gotenv/@v/v1.4.2.zip) |
| github.com/tidwall/gjson@v1.18.0 | MIT | [Archive](https://proxy.golang.org/github.com/tidwall/gjson/@v/v1.18.0.zip) |
| github.com/tidwall/match@v1.1.1 | MIT | [Archive](https://proxy.golang.org/github.com/tidwall/match/@v/v1.1.1.zip) |
| github.com/tidwall/pretty@v1.2.1 | MIT | [Archive](https://proxy.golang.org/github.com/tidwall/pretty/@v/v1.2.1.zip) |
| github.com/tidwall/sjson@v1.2.5 | MIT | [Archive](https://proxy.golang.org/github.com/tidwall/sjson/@v/v1.2.5.zip) |
| github.com/urfave/negroni@v1.0.0 | MIT | [Archive](https://proxy.golang.org/github.com/urfave/negroni/@v/v1.0.0.zip) |
| github.com/xeipuuv/gojsonpointer@v0.0.0-20190905194746-02993c407bfb | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/xeipuuv/gojsonpointer/@v/v0.0.0-20190905194746-02993c407bfb.zip) |
| github.com/xeipuuv/gojsonreference@v0.0.0-20180127040603-bd5ef7bd5415 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/xeipuuv/gojsonreference/@v/v0.0.0-20180127040603-bd5ef7bd5415.zip) |
| github.com/xeipuuv/gojsonschema@v1.2.0 | Apache-2.0 | [Archive](https://proxy.golang.org/github.com/xeipuuv/gojsonschema/@v/v1.2.0.zip) |
| github.com/xtgo/uuid@v0.0.0-20140804021211-a0b114877d4c | BSD-3-Clause | [Archive](https://proxy.golang.org/github.com/xtgo/uuid/@v/v0.0.0-20140804021211-a0b114877d4c.zip) |
| github.com/yuin/goldmark@v1.4.13 | MIT | [Archive](https://proxy.golang.org/github.com/yuin/goldmark/@v/v1.4.13.zip) |
| go.etcd.io/etcd/api/v3@v3.5.9 | Apache-2.0 | [Archive](https://proxy.golang.org/go.etcd.io/etcd/api/v3/@v/v3.5.9.zip) |
| go.etcd.io/etcd/client/pkg/v3@v3.5.9 | Apache-2.0 | [Archive](https://proxy.golang.org/go.etcd.io/etcd/client/pkg/v3/@v/v3.5.9.zip) |
| go.etcd.io/etcd/client/v2@v2.305.7 | Apache-2.0 | [Archive](https://proxy.golang.org/go.etcd.io/etcd/client/v2/@v/v2.305.7.zip) |
| go.etcd.io/etcd/client/v3@v3.5.9 | Apache-2.0 | [Archive](https://proxy.golang.org/go.etcd.io/etcd/client/v3/@v/v3.5.9.zip) |
| go.mongodb.org/mongo-driver@v1.17.3 | Apache-2.0 | [Archive](https://proxy.golang.org/go.mongodb.org/mongo-driver/@v/v1.17.3.zip) |
| go.opencensus.io@v0.24.0 | Apache-2.0 | [Archive](https://proxy.golang.org/go.opencensus.io/@v/v0.24.0.zip) |
| go.opentelemetry.io/auto/sdk@v1.2.1 | Apache-2.0 | [Archive](https://proxy.golang.org/go.opentelemetry.io/auto/sdk/@v/v1.2.1.zip) |
| go.opentelemetry.io/contrib/detectors/gcp@v1.44.0 | Apache-2.0, BSD-3-Clause | [Archive](https://proxy.golang.org/go.opentelemetry.io/contrib/detectors/gcp/@v/v1.44.0.zip) |
| go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc@v0.70.0 | Apache-2.0, BSD-3-Clause | [Archive](https://proxy.golang.org/go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc/@v/v0.70.0.zip) |
| go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace@v0.60.0 | Apache-2.0 | [Archive](https://proxy.golang.org/go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace/@v/v0.60.0.zip) |
| go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp@v0.70.0 | Apache-2.0, BSD-3-Clause | [Archive](https://proxy.golang.org/go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp/@v/v0.70.0.zip) |
| go.opentelemetry.io/contrib/propagators/b3@v1.35.0 | Apache-2.0 | [Archive](https://proxy.golang.org/go.opentelemetry.io/contrib/propagators/b3/@v/v1.35.0.zip) |
| go.opentelemetry.io/contrib/propagators/jaeger@v1.35.0 | Apache-2.0 | [Archive](https://proxy.golang.org/go.opentelemetry.io/contrib/propagators/jaeger/@v/v1.35.0.zip) |
| go.opentelemetry.io/contrib/samplers/jaegerremote@v0.29.0 | Apache-2.0 | [Archive](https://proxy.golang.org/go.opentelemetry.io/contrib/samplers/jaegerremote/@v/v0.29.0.zip) |
| go.opentelemetry.io/otel@v1.47.0 | Apache-2.0, BSD-3-Clause | [Archive](https://proxy.golang.org/go.opentelemetry.io/otel/@v/v1.47.0.zip) |
| go.opentelemetry.io/otel/exporters/jaeger@v1.17.0 | Apache-2.0, BSD-2-Clause | [Archive](https://proxy.golang.org/go.opentelemetry.io/otel/exporters/jaeger/@v/v1.17.0.zip) |
| go.opentelemetry.io/otel/exporters/otlp/otlptrace@v1.47.0 | Apache-2.0, BSD-3-Clause | [Archive](https://proxy.golang.org/go.opentelemetry.io/otel/exporters/otlp/otlptrace/@v/v1.47.0.zip) |
| go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp@v1.47.0 | Apache-2.0, BSD-3-Clause | [Archive](https://proxy.golang.org/go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp/@v/v1.47.0.zip) |
| go.opentelemetry.io/otel/exporters/stdout/stdouttrace@v1.45.0 | Apache-2.0, BSD-3-Clause | [Archive](https://proxy.golang.org/go.opentelemetry.io/otel/exporters/stdout/stdouttrace/@v/v1.45.0.zip) |
| go.opentelemetry.io/otel/exporters/zipkin@v1.47.0 | Apache-2.0, BSD-3-Clause | [Archive](https://proxy.golang.org/go.opentelemetry.io/otel/exporters/zipkin/@v/v1.47.0.zip) |
| go.opentelemetry.io/otel/log@v1.47.0 | Apache-2.0, BSD-3-Clause | [Archive](https://proxy.golang.org/go.opentelemetry.io/otel/log/@v/v1.47.0.zip) |
| go.opentelemetry.io/otel/metric@v1.47.0 | Apache-2.0, BSD-3-Clause | [Archive](https://proxy.golang.org/go.opentelemetry.io/otel/metric/@v/v1.47.0.zip) |
| go.opentelemetry.io/otel/sdk@v1.47.0 | Apache-2.0, BSD-3-Clause | [Archive](https://proxy.golang.org/go.opentelemetry.io/otel/sdk/@v/v1.47.0.zip) |
| go.opentelemetry.io/otel/sdk/metric@v1.47.0 | Apache-2.0, BSD-3-Clause | [Archive](https://proxy.golang.org/go.opentelemetry.io/otel/sdk/metric/@v/v1.47.0.zip) |
| go.opentelemetry.io/otel/trace@v1.47.0 | Apache-2.0, BSD-3-Clause | [Archive](https://proxy.golang.org/go.opentelemetry.io/otel/trace/@v/v1.47.0.zip) |
| go.opentelemetry.io/proto/otlp@v1.11.0 | Apache-2.0 | [Archive](https://proxy.golang.org/go.opentelemetry.io/proto/otlp/@v/v1.11.0.zip) |
| go.uber.org/atomic@v1.9.0 | MIT | [Archive](https://proxy.golang.org/go.uber.org/atomic/@v/v1.9.0.zip) |
| go.uber.org/goleak@v1.3.0 | MIT | [Archive](https://proxy.golang.org/go.uber.org/goleak/@v/v1.3.0.zip) |
| go.uber.org/mock@v0.5.0 | Apache-2.0 | [Archive](https://proxy.golang.org/go.uber.org/mock/@v/v0.5.0.zip) |
| go.uber.org/multierr@v1.8.0 | MIT | [Archive](https://proxy.golang.org/go.uber.org/multierr/@v/v1.8.0.zip) |
| go.uber.org/zap@v1.21.0 | MIT | [Archive](https://proxy.golang.org/go.uber.org/zap/@v/v1.21.0.zip) |
| go.yaml.in/yaml/v3@v3.0.5 | Apache-2.0, MIT | [Archive](https://proxy.golang.org/go.yaml.in/yaml/v3/@v/v3.0.5.zip) |
| golang.org/x/crypto@v0.58.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/golang.org/x/crypto/@v/v0.58.0.zip) |
| golang.org/x/exp@v0.0.0-20250305212735-054e65f0b394 | BSD-3-Clause | [Archive](https://proxy.golang.org/golang.org/x/exp/@v/v0.0.0-20250305212735-054e65f0b394.zip) |
| golang.org/x/image@v0.0.0-20190802002840-cff245a6509b | BSD-3-Clause | [Archive](https://proxy.golang.org/golang.org/x/image/@v/v0.0.0-20190802002840-cff245a6509b.zip) |
| golang.org/x/lint@v0.0.0-20201208152925-83fdc39ff7b5 | BSD-3-Clause | [Archive](https://proxy.golang.org/golang.org/x/lint/@v/v0.0.0-20201208152925-83fdc39ff7b5.zip) |
| golang.org/x/mobile@v0.0.0-20190719004257-d2bd2a29d028 | BSD-3-Clause | [Archive](https://proxy.golang.org/golang.org/x/mobile/@v/v0.0.0-20190719004257-d2bd2a29d028.zip) |
| golang.org/x/mod@v0.42.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/golang.org/x/mod/@v/v0.42.0.zip) |
| golang.org/x/net@v0.61.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/golang.org/x/net/@v/v0.61.0.zip) |
| golang.org/x/oauth2@v0.37.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/golang.org/x/oauth2/@v/v0.37.0.zip) |
| golang.org/x/sync@v0.24.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/golang.org/x/sync/@v/v0.24.0.zip) |
| golang.org/x/sys@v0.49.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/golang.org/x/sys/@v/v0.49.0.zip) |
| golang.org/x/telemetry@v0.0.0-20260924152758-ed294f943157 | BSD-3-Clause | [Archive](https://proxy.golang.org/golang.org/x/telemetry/@v/v0.0.0-20260924152758-ed294f943157.zip) |
| golang.org/x/term@v0.47.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/golang.org/x/term/@v/v0.47.0.zip) |
| golang.org/x/text@v0.43.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/golang.org/x/text/@v/v0.43.0.zip) |
| golang.org/x/time@v0.4.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/golang.org/x/time/@v/v0.4.0.zip) |
| golang.org/x/tools@v0.51.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/golang.org/x/tools/@v/v0.51.0.zip) |
| golang.org/x/xerrors@v0.0.0-20220907171357-04be3eba64a2 | BSD-3-Clause | [Archive](https://proxy.golang.org/golang.org/x/xerrors/@v/v0.0.0-20220907171357-04be3eba64a2.zip) |
| gonum.org/v1/gonum@v0.17.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/gonum.org/v1/gonum/@v/v0.17.0.zip) |
| google.golang.org/api@v0.278.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/google.golang.org/api/@v/v0.278.0.zip) |
| google.golang.org/appengine@v1.6.8 | Apache-2.0 | [Archive](https://proxy.golang.org/google.golang.org/appengine/@v/v1.6.8.zip) |
| google.golang.org/genproto@v0.0.0-20231106174013-bbf56f31fb17 | Apache-2.0 | [Archive](https://proxy.golang.org/google.golang.org/genproto/@v/v0.0.0-20231106174013-bbf56f31fb17.zip) |
| google.golang.org/genproto/googleapis/api@v0.0.0-20260928230214-8a89bd6388cc | Apache-2.0 | [Archive](https://proxy.golang.org/google.golang.org/genproto/googleapis/api/@v/v0.0.0-20260928230214-8a89bd6388cc.zip) |
| google.golang.org/genproto/googleapis/rpc@v0.0.0-20260928230214-8a89bd6388cc | Apache-2.0 | [Archive](https://proxy.golang.org/google.golang.org/genproto/googleapis/rpc/@v/v0.0.0-20260928230214-8a89bd6388cc.zip) |
| google.golang.org/grpc@v1.84.0 | Apache-2.0 | [Archive](https://proxy.golang.org/google.golang.org/grpc/@v/v1.84.0.zip) |
| google.golang.org/protobuf@v1.36.12 | BSD-3-Clause | [Archive](https://proxy.golang.org/google.golang.org/protobuf/@v/v1.36.12.zip) |
| gopkg.in/check.v1@v1.0.0-20201130134442-10cb98267c6c | BSD-2-Clause | [Archive](https://proxy.golang.org/gopkg.in/check.v1/@v/v1.0.0-20201130134442-10cb98267c6c.zip) |
| gopkg.in/errgo.v2@v2.1.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/gopkg.in/errgo.v2/@v/v2.1.0.zip) |
| gopkg.in/ini.v1@v1.67.0 | Apache-2.0 | [Archive](https://proxy.golang.org/gopkg.in/ini.v1/@v/v1.67.0.zip) |
| gopkg.in/yaml.v2@v2.4.0 | Apache-2.0, MIT | [Archive](https://proxy.golang.org/gopkg.in/yaml.v2/@v/v2.4.0.zip) |
| gopkg.in/yaml.v3@v3.0.1 | Apache-2.0, MIT | [Archive](https://proxy.golang.org/gopkg.in/yaml.v3/@v/v3.0.1.zip) |
| honnef.co/go/tools@v0.0.1-2020.1.4 | Apache-2.0, BSD-2-Clause, BSD-3-Clause, MIT | [Archive](https://proxy.golang.org/honnef.co/go/tools/@v/v0.0.1-2020.1.4.zip) |
| rsc.io/binaryregexp@v0.2.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/rsc.io/binaryregexp/@v/v0.2.0.zip) |
| rsc.io/quote/v3@v3.1.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/rsc.io/quote/v3/@v/v3.1.0.zip) |
| rsc.io/sampler@v1.3.0 | BSD-3-Clause | [Archive](https://proxy.golang.org/rsc.io/sampler/@v/v1.3.0.zip) |
| sigs.k8s.io/yaml@v1.4.0 | Apache-2.0, BSD-3-Clause, MIT | [Archive](https://proxy.golang.org/sigs.k8s.io/yaml/@v/v1.4.0.zip) |

## P0 local services

PostgreSQL 17.11 is built from the [exact official source](https://ftp.postgresql.org/pub/source/v17.11/postgresql-17.11.tar.bz2). Its PostgreSQL, TCL, Spencer-94 and FSFUL notices are retained in [postgresql.txt](tools/license-evidence/postgresql.txt).

OpenBao v2.7.1 is unmodified MPL-2.0 source at commit `a5db72cef75c24b920ade02065b18dd8eb666bac`: [corresponding source archive](https://api.github.com/repos/openbao/openbao/tarball/a5db72cef75c24b920ade02065b18dd8eb666bac). Recipients can obtain every linked component's exact source from [the component inventory](docs/p0/openbao-components.json). Full retained license and NOTICE material is in [openbao-components.txt](tools/license-evidence/openbao-components.txt), including CC0-1.0 and Unicode-DFS-2016. The build excludes UI assets. The reedsolomon release omits its license file; retained MIT text comes from an upstream commit with byte-identical program sources, as recorded in [the equivalence evidence](docs/p0/reedsolomon-source-equivalence.json).

The allowed Unlicense is unused in the selected Fosite graph. Zlib and WTFPL notices are retained for GLFW and XGB upstream test-graph modules; their packages are never compiled, executed or distributed by Mayi. An inventory entry is not a statement that its package is linked into the server.

PostgreSQL's generated configure script uses [FSFUL](https://spdx.org/licenses/FSFUL.html), explicitly approved with retained notice. The generated Bison parser and config.guess/config.sub use their additional permissions permitting PostgreSQL distribution terms; those headers are retained. The bundled X11 install-sh helper is not executed or redistributed by Mayi; the harness explicitly selects platform mkdir/install instead.
