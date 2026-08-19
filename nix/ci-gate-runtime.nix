let
  valueOr =
    name: fallback:
    let
      value = builtins.getEnv name;
    in
    if value == "" then fallback else value;
  sourceRoot = valueOr "XO_NIXPKG_SOURCE_ROOT" (builtins.getEnv "PWD");
  flakeRef = valueOr "XO_NIXPKG_FLAKE_REF" "git+file://${sourceRoot}";
  flake = builtins.getFlake flakeRef;
  workflow = builtins.fromJSON (builtins.getEnv "PREPARED_CI_WORKFLOW");
  result = flake.lib.evaluateCiWorkflowGate {
    inherit workflow;
    jobResults = builtins.fromJSON (builtins.getEnv "CI_JOB_RESULTS");
  };
  requiredNames = map (job: job.name) result.requiredJobResults;
in
if result.passed then
  "CI workflow ${result.workflow} passed required jobs: ${builtins.concatStringsSep ", " requiredNames}\n"
else
  throw "CI workflow ${result.workflow} failed: prepare=${result.preparation.result}; required jobs: ${result.summary}"
