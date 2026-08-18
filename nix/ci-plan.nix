{ lib }:

let
  validName =
    value: builtins.isString value && builtins.match "[A-Za-z0-9][A-Za-z0-9._-]*" value != null;
  validAttribute =
    value:
    builtins.isString value
    && builtins.match "[A-Za-z0-9][A-Za-z0-9._+-]*" value != null
    && !(lib.hasInfix ".." value);
  validLink =
    value:
    builtins.isString value
    && value != ""
    && builtins.substring 0 1 value != "/"
    && builtins.match "[A-Za-z0-9._+-][A-Za-z0-9._+/-]*" value != null
    && !(lib.hasInfix ".." value);
  normalizeTarget =
    target:
    assert lib.assertMsg (builtins.isAttrs target)
      "CI plan targets must be { name, attribute, link? } sets";
    assert lib.assertMsg (
      target ? name && target ? attribute
    ) "CI plan targets require name and attribute";
    assert lib.assertMsg (lib.all (
      key:
      builtins.elem key [
        "attribute"
        "link"
        "name"
      ]
    ) (builtins.attrNames target)) "CI plan targets may contain only name, attribute, and link";
    assert lib.assertMsg (!(target ? link) || validLink target.link) "CI plan target link is malformed";
    {
      inherit (target) name attribute;
    }
    // lib.optionalAttrs (target ? link) { inherit (target) link; };
in
{
  ciPlanSchemaVersion = 2;

  mkCiPlan =
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
      schemaVersion = 2;
      inherit name;
      targets = normalizedTargets;
    };
}
