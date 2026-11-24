// Prepare the two generated OpenAPI documents (../docs/api/*.json) for the portal.
//
// The spec files are the source of truth and are not edited. This writes
// portal copies under .specs/ with only presentation changes:
//   - a placeholder server, so code samples show a full URL;
//   - in the internal document, tags grouped by API category (admin, client,
//     public, bootstrap), because the same function name can exist in more
//     than one category.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const source = join(here, "..", "..", "docs", "api");
const target = join(here, "..", ".specs");
mkdirSync(target, { recursive: true });

const SERVERS = [
  {
    url: "https://{host}",
    description: "Your CMS deployment",
    variables: { host: { default: "cms.example.org", description: "Host name of the CMS" } },
  },
];
const CATEGORY_TITLES = {
  client: "Client API",
  public: "Public API (no credential)",
  admin: "Admin API",
  bootstrap: "Bootstrap",
};
const HTTP_METHODS = ["get", "post"];

function load(name) {
  return JSON.parse(readFileSync(join(source, name), "utf8"));
}

function save(name, spec) {
  writeFileSync(join(target, name), JSON.stringify(spec, null, 2) + "\n");
}

function groupByCategory(spec) {
  const groups = new Map();
  for (const [path, item] of Object.entries(spec.paths)) {
    const category = path.split("/")[3];
    for (const method of HTTP_METHODS) {
      const operation = item[method];
      if (!operation) continue;
      // A read has a GET and a POST page; tell them apart in the sidebar.
      if (method === "get") operation.summary = `${operation.summary} (GET)`;
      const tag = `${category} / ${operation.tags[0]}`;
      operation.tags = [tag];
      if (!groups.has(category)) groups.set(category, new Set());
      groups.get(category).add(tag);
    }
  }
  const order = Object.keys(CATEGORY_TITLES).filter((category) => groups.has(category));
  spec.tags = order.flatMap((category) => [...groups.get(category)].sort().map((name) => ({ name })));
  spec["x-tagGroups"] = order.map((category) => ({
    name: CATEGORY_TITLES[category],
    tags: [...groups.get(category)].sort(),
  }));
  return spec;
}

const integrator = load("openapi-public.json");
integrator.servers = SERVERS;
save("integrator.json", groupByCategory(integrator));

const internal = load("openapi-internal.json");
internal.servers = SERVERS;
save("internal.json", groupByCategory(internal));

console.log(
  `prepared ${Object.keys(integrator.paths).length} integrator and ${Object.keys(internal.paths).length} internal paths`,
);
