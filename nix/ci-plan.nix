{ lib }:

let
  validName =
    value: builtins.isString value && builtins.match "[A-Za-z0-9][A-Za-z0-9._-]*" value != null;
  validAttribute =
    value:
    builtins.isString value
    && builtins.match "[A-Za-z0-9][A-Za-z0-9._+-]*" value != null
    && !(lib.hasInfix ".." value);
  normalizeTarget =
    target:
    if builtins.isString target then
      {
        name = lib.last (lib.splitString "." target);
        attribute = target;
      }
    else
      assert lib.assertMsg (builtins.isAttrs target)
        "CI plan targets must be attribute strings or { name, attribute } sets";
      assert lib.assertMsg (
        target ? name && target ? attribute
      ) "CI plan target sets require name and attribute";
      assert lib.assertMsg (
        builtins.attrNames target == [
          "attribute"
          "name"
        ]
      ) "CI plan target sets may contain only name and attribute";
      {
        inherit (target) name attribute;
      };
in
{
  ciPlanSchemaVersion = 1;

  mkFlakeAttributePlan =
    {
      name,
      targets,
    }:
    let
      normalizedTargets = map normalizeTarget targets;
      names = map (target: target.name) normalizedTargets;
      attributes = map (target: target.attribute) normalizedTargets;
    in
    assert lib.assertMsg (validName name) "CI plan name is malformed";
    assert lib.assertMsg (normalizedTargets != [ ]) "CI plans require at least one target";
    assert lib.assertMsg (lib.all (
      target: validName target.name
    ) normalizedTargets) "CI plan target name is malformed";
    assert lib.assertMsg (lib.all (
      target: validAttribute target.attribute
    ) normalizedTargets) "CI plan target attribute is malformed";
    assert lib.assertMsg (
      lib.length names == lib.length (lib.unique names)
    ) "CI plan target names must be unique";
    assert lib.assertMsg (
      lib.length attributes == lib.length (lib.unique attributes)
    ) "CI plan target attributes must be unique";
    {
      schemaVersion = 1;
      inherit name;
      targets = normalizedTargets;
    };
}
