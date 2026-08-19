{ lib }:

let
  validName =
    value: builtins.isString value && builtins.match "[A-Za-z0-9][A-Za-z0-9._-]*" value != null;
  validAttribute =
    value:
    builtins.isString value
    && builtins.match "[A-Za-z0-9][A-Za-z0-9._+-]*" value != null
    && !(lib.hasInfix ".." value);
  validEvent =
    value: builtins.isString value && builtins.match "[A-Za-z0-9][A-Za-z0-9_-]*" value != null;
  validRef =
    value:
    builtins.isString value
    && builtins.match "refs/[A-Za-z0-9._/-]+" value != null
    && !(lib.hasInfix ".." value);
  validObservedRef =
    value:
    builtins.isString value
    && builtins.match "[A-Za-z0-9][A-Za-z0-9._/-]*" value != null
    && !(lib.hasInfix ".." value);
  exactKeys = expected: value: builtins.attrNames value == expected;
  normalizeCondition =
    condition:
    assert lib.assertMsg (builtins.isAttrs condition) "CI workflow conditions must be attribute sets";
    assert lib.assertMsg (exactKeys [
      "event"
      "ref"
    ] condition) "CI workflow conditions require only event and ref";
    assert lib.assertMsg (validEvent condition.event) "CI workflow condition event is malformed";
    assert lib.assertMsg (validRef condition.ref) "CI workflow condition ref is malformed";
    {
      inherit (condition) event ref;
    };
  normalizeJob =
    job:
    assert lib.assertMsg (builtins.isAttrs job) "CI workflow jobs must be attribute sets";
    assert lib.assertMsg (
      exactKeys [
        "gate"
        "plan"
      ] job
      || exactKeys [
        "gate"
        "plan"
        "when"
      ] job
    ) "CI workflow jobs require only gate, plan, and optional when";
    assert lib.assertMsg (builtins.isBool job.gate) "CI workflow job gate must be boolean";
    assert lib.assertMsg (validAttribute job.plan) "CI workflow job plan is malformed";
    {
      inherit (job) gate plan;
    }
    // lib.optionalAttrs (job ? when) { when = normalizeCondition job.when; };
  normalizeWorkflow =
    workflow:
    assert lib.assertMsg (builtins.isAttrs workflow) "CI workflows must be attribute sets";
    assert lib.assertMsg (exactKeys [
      "jobs"
      "name"
      "release"
      "schemaVersion"
    ] workflow) "CI workflows require only schemaVersion, name, jobs, and release";
    assert lib.assertMsg (workflow.schemaVersion == 1) "CI workflow schemaVersion must be 1";
    assert lib.assertMsg (validName workflow.name) "CI workflow name is malformed";
    assert lib.assertMsg (
      builtins.isAttrs workflow.jobs && workflow.jobs != { }
    ) "CI workflow requires jobs";
    assert lib.assertMsg (lib.all validName (
      builtins.attrNames workflow.jobs
    )) "CI workflow job name is malformed";
    assert lib.assertMsg (
      builtins.isAttrs workflow.release && exactKeys [ "when" ] workflow.release
    ) "CI workflow release requires only a when condition";
    let
      jobs = lib.mapAttrs (_: normalizeJob) workflow.jobs;
    in
    assert lib.assertMsg (lib.any (job: job.gate && !(job ? when)) (
      builtins.attrValues jobs
    )) "CI workflow requires an unconditional gated job";
    {
      schemaVersion = 1;
      inherit (workflow) name;
      inherit jobs;
      release.when = normalizeCondition workflow.release.when;
    };
  normalizeEvent =
    event:
    assert lib.assertMsg (builtins.isAttrs event) "CI workflow events must be attribute sets";
    assert lib.assertMsg (exactKeys [
      "name"
      "ref"
    ] event) "CI workflow events require only name and ref";
    assert lib.assertMsg (validEvent event.name) "CI workflow event name is malformed";
    assert lib.assertMsg (validObservedRef event.ref) "CI workflow event ref is malformed";
    {
      inherit (event) name ref;
    };
  conditionEnabled = event: condition: condition.event == event.name && condition.ref == event.ref;
  prepare =
    {
      workflow,
      system,
      sourceAttribute,
      event,
    }:
    let
      definition = normalizeWorkflow workflow;
      normalizedEvent = normalizeEvent event;
      jobs = lib.mapAttrs (
        _: job:
        job
        // {
          enabled = !(job ? when) || conditionEnabled normalizedEvent job.when;
        }
      ) definition.jobs;
      requiredJobs = builtins.attrNames (lib.filterAttrs (_: job: job.enabled && job.gate) jobs);
    in
    assert lib.assertMsg (validName system) "CI workflow system is malformed";
    assert lib.assertMsg (validAttribute sourceAttribute) "CI workflow source attribute is malformed";
    assert lib.assertMsg (requiredJobs != [ ]) "Prepared CI workflow requires at least one gated job";
    {
      schemaVersion = 1;
      inherit (definition) name;
      inherit system jobs;
      source.attribute = sourceAttribute;
      event = normalizedEvent;
      release = definition.release // {
        enabled = conditionEnabled normalizedEvent definition.release.when;
      };
      gate = { inherit requiredJobs; };
    };
  normalizePreparedWorkflow =
    workflow:
    assert lib.assertMsg (builtins.isAttrs workflow) "Prepared CI workflows must be attribute sets";
    assert lib.assertMsg (exactKeys [
      "event"
      "gate"
      "jobs"
      "name"
      "release"
      "schemaVersion"
      "source"
      "system"
    ] workflow) "Prepared CI workflow schema is malformed";
    assert lib.assertMsg (
      builtins.isAttrs workflow.source && exactKeys [ "attribute" ] workflow.source
    ) "Prepared CI workflow source is malformed";
    assert lib.assertMsg (
      builtins.isAttrs workflow.gate && exactKeys [ "requiredJobs" ] workflow.gate
    ) "Prepared CI workflow gate is malformed";
    assert lib.assertMsg (builtins.isList workflow.gate.requiredJobs)
      "Prepared CI workflow requiredJobs must be a list";
    assert lib.assertMsg (
      builtins.isAttrs workflow.release
      && exactKeys [
        "enabled"
        "when"
      ] workflow.release
    ) "Prepared CI workflow release is malformed";
    assert lib.assertMsg (builtins.isBool workflow.release.enabled)
      "Prepared CI workflow release enabled must be boolean";
    let
      definition = {
        inherit (workflow) schemaVersion name;
        jobs = lib.mapAttrs (
          _: job:
          assert lib.assertMsg (
            builtins.isAttrs job && job ? enabled && builtins.isBool job.enabled
          ) "Prepared CI workflow job enabled must be boolean";
          builtins.removeAttrs job [ "enabled" ]
        ) workflow.jobs;
        release.when = workflow.release.when;
      };
      expected = prepare {
        workflow = definition;
        inherit (workflow) system;
        sourceAttribute = workflow.source.attribute;
        event = workflow.event;
      };
    in
    assert lib.assertMsg (
      workflow == expected
    ) "Prepared CI workflow does not match its definition and event";
    expected;
  resultFor =
    jobResults: name:
    if
      builtins.hasAttr name jobResults
      && builtins.isAttrs jobResults.${name}
      && jobResults.${name} ? result
      && builtins.isString jobResults.${name}.result
    then
      jobResults.${name}.result
    else
      "missing";
in
{
  ciWorkflowSchemaVersion = 1;

  mkCiWorkflow =
    {
      name,
      jobs,
      release,
    }:
    normalizeWorkflow {
      schemaVersion = 1;
      inherit name jobs release;
    };

  prepareCiWorkflow = prepare;

  evaluateCiWorkflowGate =
    {
      workflow,
      jobResults,
    }:
    let
      prepared = normalizePreparedWorkflow workflow;
      _jobResultsType =
        assert lib.assertMsg (builtins.isAttrs jobResults)
          "CI workflow job results must be an attribute set";
        true;
      preparationResult = resultFor jobResults "prepare";
      requiredJobResults = map (
        name:
        let
          result = resultFor jobResults name;
        in
        {
          inherit name result;
          passed = result == "success";
        }
      ) prepared.gate.requiredJobs;
      passed = preparationResult == "success" && lib.all (job: job.passed) requiredJobResults;
    in
    assert _jobResultsType;
    {
      schemaVersion = 1;
      workflow = prepared.name;
      inherit passed requiredJobResults;
      decision = if passed then "pass" else "fail";
      preparation = {
        result = preparationResult;
        passed = preparationResult == "success";
      };
      summary = lib.concatStringsSep ", " (map (job: "${job.name}=${job.result}") requiredJobResults);
    };
}
