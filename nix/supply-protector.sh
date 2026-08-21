#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

graph=${1:?exported closure graph is required}
output=${2:?output directory is required}
: "${ROOT_PATH:?}" "${CHANNEL:?}" "${VERSION:?}" "${SOURCE_REV:?}"
: "${SOURCE_TIMESTAMP:?}" "${CACHE_URL:?}" "${CACHE_PUBLIC_KEY:?}"
: "${SPDX_SCHEMA:?}" "${CYCLONEDX_SCHEMA:?}" "${CYCLONEDX_JSF_SCHEMA:?}"

temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
nodes_ndjson=$temporary/nodes.ndjson
edges_ndjson=$temporary/edges.ndjson
: >"$nodes_ndjson"
: >"$edges_ndjson"
root_seen=false

store_identity() {
  local store_path=$1
  local basename=${store_path#/nix/store/}
  STORE_HASH=${basename%%-*}
  STORE_NAME=${basename#*-}
  [[ $store_path == /nix/store/* && $STORE_HASH =~ ^[0-9a-z]{32}$ && -n $STORE_NAME ]]
}

while IFS= read -r store_path; do
  [[ -n $store_path ]] || {
    printf 'Unexpected empty store path in exported closure graph\n' >&2
    exit 1
  }
  IFS= read -r separator
  [[ -z $separator ]]
  IFS= read -r reference_count
  [[ $reference_count =~ ^[0-9]+$ ]]

  store_identity "$store_path"
  store_hash=$STORE_HASH
  store_name=$STORE_NAME
  is_root=false
  if [[ $store_path == "$ROOT_PATH" ]]; then
    is_root=true
    root_seen=true
    store_name=xen-orchestra-ce
  fi
  jq -cn \
    --arg path "$store_path" \
    --arg storeHash "$store_hash" \
    --arg name "$store_name" \
    --arg spdxId "SPDXRef-$store_hash" \
    --arg bomRef "nix:$store_hash" \
    --argjson isRoot "$is_root" \
    '{path:$path,storeHash:$storeHash,name:$name,spdxId:$spdxId,bomRef:$bomRef,isRoot:$isRoot}' \
    >>"$nodes_ndjson"

  for ((index = 0; index < reference_count; index++)); do
    IFS= read -r reference
    store_identity "$reference"
    [[ $reference == "$store_path" ]] && continue
    jq -cn \
      --arg from "$store_path" \
      --arg to "$reference" \
      --arg fromSpdx "SPDXRef-$store_hash" \
      --arg toSpdx "SPDXRef-$STORE_HASH" \
      --arg fromBomRef "nix:$store_hash" \
      --arg toBomRef "nix:$STORE_HASH" \
      '{from:$from,to:$to,fromSpdx:$fromSpdx,toSpdx:$toSpdx,fromBomRef:$fromBomRef,toBomRef:$toBomRef}' \
      >>"$edges_ndjson"
  done
done <"$graph"

[[ $root_seen == true ]]
jq -s 'sort_by(.path)' "$nodes_ndjson" >"$temporary/nodes.json"
jq -s 'sort_by(.from, .to) | unique_by(.from, .to)' "$edges_ndjson" >"$temporary/edges.json"
created=$(date --utc --date="@$SOURCE_TIMESTAMP" +%Y-%m-%dT%H:%M:%SZ)
root_hash=${ROOT_PATH#/nix/store/}
root_hash=${root_hash%%-*}

mkdir -p "$output"
cp "$graph" "$output/closure.graph"

jq -S -n \
  --slurpfile nodes "$temporary/nodes.json" \
  --slurpfile edges "$temporary/edges.json" \
  --arg channel "$CHANNEL" \
  --arg created "$created" \
  --arg root "$ROOT_PATH" \
  --arg rootSpdx "SPDXRef-$root_hash" \
  --arg sourceRev "$SOURCE_REV" \
  --arg version "$VERSION" '
  {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: ("xo-nixpkg-" + $channel + "-" + $version),
    documentNamespace: ("https://github.com/declarative-dale/xo-nixpkg/supply/" + $sourceRev + "/" + $channel + "/" + $rootSpdx),
    creationInfo: {
      created: $created,
      creators: ["Tool: xo-nixpkg-supply-protector"]
    },
    packages: [
      $nodes[0][] |
      {
        name: .name,
        SPDXID: .spdxId,
        downloadLocation: "NOASSERTION",
        filesAnalyzed: false,
        licenseConcluded: "NOASSERTION",
        licenseDeclared: "NOASSERTION",
        copyrightText: "NOASSERTION",
        externalRefs: [{
          referenceCategory: "OTHER",
          referenceType: "nix-store-path",
          referenceLocator: .path
        }]
      } + if .isRoot then {versionInfo: $version, primaryPackagePurpose: "APPLICATION"} else {} end
    ],
    relationships: (
      [{spdxElementId: "SPDXRef-DOCUMENT", relationshipType: "DESCRIBES", relatedSpdxElement: $rootSpdx}] +
      [$edges[0][] | {spdxElementId: .fromSpdx, relationshipType: "DEPENDS_ON", relatedSpdxElement: .toSpdx}]
    )
  }' >"$output/xen-orchestra.spdx.json"

jq -S -n \
  --slurpfile nodes "$temporary/nodes.json" \
  --slurpfile edges "$temporary/edges.json" \
  --arg channel "$CHANNEL" \
  --arg created "$created" \
  --arg rootBomRef "nix:$root_hash" \
  --arg sourceRev "$SOURCE_REV" \
  --arg version "$VERSION" '
  def component:
    {
      type: (if .isRoot then "application" else "library" end),
      name: .name,
      "bom-ref": .bomRef,
      properties: [
        {name: "nix:storePath", value: .path},
        {name: "nix:storeHash", value: .storeHash}
      ]
    } + if .isRoot then {version: $version} else {} end;
  {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    metadata: {
      timestamp: $created,
      tools: {components: [{type: "application", name: "xo-nixpkg-supply-protector"}]},
      component: (($nodes[0][] | select(.bomRef == $rootBomRef)) | component)
    },
    components: [$nodes[0][] | component],
    dependencies: [
      $nodes[0][] as $node |
      {
        ref: $node.bomRef,
        dependsOn: ([$edges[0][] | select(.fromBomRef == $node.bomRef) | .toBomRef] | unique)
      }
    ],
    properties: [
      {name: "xo-nixpkg:channel", value: $channel},
      {name: "xo-nixpkg:sourceRevision", value: $sourceRev}
    ]
  }' >"$output/xen-orchestra.cdx.json"

(
  cd "$output"
  sha256sum closure.graph xen-orchestra.spdx.json xen-orchestra.cdx.json >SHA256SUMS
  sha256sum --check --strict SHA256SUMS
)

path_count=$(jq 'length' "$temporary/nodes.json")
relationship_count=$(jq 'length' "$temporary/edges.json")
graph_sha256=$(sha256sum "$output/closure.graph" | cut -d' ' -f1)
spdx_sha256=$(sha256sum "$output/xen-orchestra.spdx.json" | cut -d' ' -f1)
cdx_sha256=$(sha256sum "$output/xen-orchestra.cdx.json" | cut -d' ' -f1)
jq -S -n \
  --arg cachePublicKey "$CACHE_PUBLIC_KEY" \
  --arg cacheUrl "$CACHE_URL" \
  --arg cdxSha256 "$cdx_sha256" \
  --arg channel "$CHANNEL" \
  --arg created "$created" \
  --arg graphSha256 "$graph_sha256" \
  --arg sourceRev "$SOURCE_REV" \
  --arg spdxSha256 "$spdx_sha256" \
  --arg storeHash "$root_hash" \
  --arg storePath "$ROOT_PATH" \
  --arg version "$VERSION" \
  --argjson pathCount "$path_count" \
  --argjson relationshipCount "$relationship_count" '
  {
    schemaVersion: 1,
    predicateType: "https://github.com/declarative-dale/xo-nixpkg/supply-protector/v1",
    subject: {
      name: "xen-orchestra-ce",
      channel: $channel,
      version: $version,
      sourceRevision: $sourceRev,
      storePath: $storePath,
      storeHash: $storeHash
    },
    closure: {
      pathCount: $pathCount,
      relationshipCount: $relationshipCount,
      graph: {path: "closure.graph", sha256: $graphSha256}
    },
    documents: {
      spdx: {path: "xen-orchestra.spdx.json", sha256: $spdxSha256},
      cyclonedx: {path: "xen-orchestra.cdx.json", sha256: $cdxSha256}
    },
    distribution: {
      substituter: $cacheUrl,
      trustedPublicKey: $cachePublicKey
    },
    generatedAt: $created
  }' >"$output/assertion.json"

jq -e --arg root "$ROOT_PATH" --arg version "$VERSION" '
  .spdxVersion == "SPDX-2.3" and
  any(.packages[];
    .versionInfo == $version and
    any(.externalRefs[]; .referenceLocator == $root))
' "$output/xen-orchestra.spdx.json" >/dev/null
jq -e --arg root "$ROOT_PATH" '
  .bomFormat == "CycloneDX" and
  .specVersion == "1.5" and
  ([.metadata.component.properties[] |
    select(.name == "nix:storePath") |
    .value] == [$root])
' "$output/xen-orchestra.cdx.json" >/dev/null
jq -e --arg root "$ROOT_PATH" '
  .schemaVersion == 1 and
  .subject.storePath == $root and
  .closure.pathCount > 0 and
  .closure.relationshipCount > 0
' "$output/assertion.json" >/dev/null

mkdir "$temporary/schemas"
ln -s "$CYCLONEDX_SCHEMA" "$temporary/schemas/bom-1.5.schema.json"
ln -s "$CYCLONEDX_JSF_SCHEMA" "$temporary/schemas/jsf-0.82.schema.json"
check-jsonschema --schemafile "$SPDX_SCHEMA" "$output/xen-orchestra.spdx.json"
check-jsonschema \
  --schemafile "$temporary/schemas/bom-1.5.schema.json" \
  "$output/xen-orchestra.cdx.json"
