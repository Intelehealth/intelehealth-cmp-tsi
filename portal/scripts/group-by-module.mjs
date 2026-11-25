// Arrange an OpenAPI document's sidebar by BRD module.
//
// The generator (python_port/dpdpcms_py/openapi_gen.py) lists the modules in
// `x-modules`, in the BRD's order, and names each operation's module in
// `x-module`. The sidebar has two levels: the module, then the service split
// by API category (admin, client, public, bootstrap), because the same
// function name can exist in more than one category.
export const EXTENSIONS_TITLE = "Extensions (not in the BRD)";

const HTTP_METHODS = ["get", "post"];

export function groupByModule(spec) {
  const modules = new Map(spec["x-modules"].map((module) => [module.name, module]));
  const tagsByModule = new Map();
  for (const [path, item] of Object.entries(spec.paths)) {
    const category = path.split("/")[3];
    for (const method of HTTP_METHODS) {
      const operation = item[method];
      if (!operation) continue;
      const owner = operation["x-module"];
      if (!modules.has(owner)) {
        throw new Error(`${path}: module "${owner}" is not listed in x-modules`);
      }
      const tag = `${operation.tags[0]} / ${category}`;
      operation.tags = [tag];
      if (!tagsByModule.has(owner)) tagsByModule.set(owner, new Set());
      tagsByModule.get(owner).add(tag);
    }
  }

  const groups = [];
  const extensionTags = [];
  const descriptions = new Map();
  for (const module of modules.values()) {
    const tags = [...(tagsByModule.get(module.name) ?? [])].sort();
    if (!tags.length) continue;
    if (module.kind === "extension") {
      extensionTags.push(...tags);
      for (const tag of tags) descriptions.set(tag, module.title);
    } else {
      groups.push({ name: module.title, tags });
    }
  }
  if (extensionTags.length) groups.push({ name: EXTENSIONS_TITLE, tags: extensionTags.sort() });

  spec["x-tagGroups"] = groups;
  spec.tags = groups.flatMap((group) =>
    group.tags.map((name) => (descriptions.has(name) ? { name, description: descriptions.get(name) } : { name })),
  );
  return spec;
}
