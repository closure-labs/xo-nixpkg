{
  ciWorkflowLib,
  pkgs,
}:

let
  system = "x86_64-linux";
  sourceAttribute = "lib.ciWorkflows.${system}";
  protectedMain = {
    event = "push";
    ref = "refs/heads/main";
  };
  definition = ciWorkflowLib.mkCiWorkflow {
    name = "fixture-ci";
    jobs = {
      validate = {
        gate = true;
        plan = "lib.ciPlans.${system}.validation";
      };
      publish = {
        gate = true;
        plan = "lib.ciPlans.${system}.publish";
        when = protectedMain;
      };
    };
    release.when = protectedMain;
  };
  prepare =
    event:
    ciWorkflowLib.prepareCiWorkflow {
      workflow = definition;
      inherit system sourceAttribute event;
    };
  pullRequest = prepare {
    name = "pull_request";
    ref = "refs/pull/14/merge";
  };
  main = prepare {
    name = "push";
    ref = "refs/heads/main";
  };
  local = prepare {
    name = "local";
    ref = "local";
  };
  gate = workflow: jobResults: ciWorkflowLib.evaluateCiWorkflowGate { inherit workflow jobResults; };
  expectFailure = value: !(builtins.tryEval (builtins.deepSeq value value)).success;
  malformed = definition // {
    unexpected = true;
  };
  failedPreparation = gate pullRequest {
    prepare.result = "failure";
    validate.result = "success";
  };
  missingJob = gate main {
    prepare.result = "success";
    validate.result = "success";
  };
  skippedJob = gate main {
    prepare.result = "success";
    validate.result = "success";
    publish.result = "skipped";
  };
  failedJob = gate main {
    prepare.result = "success";
    validate.result = "failure";
    publish.result = "success";
  };
  successfulGate = gate main {
    prepare.result = "success";
    validate.result = "success";
    publish.result = "success";
  };
in
assert pullRequest.jobs.validate.enabled;
assert !pullRequest.jobs.publish.enabled;
assert !pullRequest.release.enabled;
assert pullRequest.gate.requiredJobs == [ "validate" ];
assert main.jobs.validate.enabled;
assert main.jobs.publish.enabled;
assert main.release.enabled;
assert
  main.gate.requiredJobs == [
    "publish"
    "validate"
  ];
assert local.jobs.validate.enabled;
assert !local.jobs.publish.enabled;
assert local.gate.requiredJobs == [ "validate" ];
assert expectFailure (
  ciWorkflowLib.prepareCiWorkflow {
    workflow = malformed;
    inherit system sourceAttribute;
    event = {
      name = "local";
      ref = "local";
    };
  }
);
assert !failedPreparation.passed;
assert failedPreparation.preparation.result == "failure";
assert !missingJob.passed;
assert (builtins.head missingJob.requiredJobResults).result == "missing";
assert !skippedJob.passed;
assert (builtins.head skippedJob.requiredJobResults).result == "skipped";
assert !failedJob.passed;
assert failedJob.summary == "publish=success, validate=failure";
assert successfulGate.passed;
assert successfulGate.decision == "pass";
pkgs.runCommandLocal "xo-nixpkg-ci-workflow-contract" { } ''
  touch "$out"
''
