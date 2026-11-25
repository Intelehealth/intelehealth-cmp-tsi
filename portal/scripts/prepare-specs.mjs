// Prepare the two generated OpenAPI documents (../docs/api/*.json) for the portal.
//
// The spec files are the source of truth and are not edited. This writes
// portal copies under .specs/ with only presentation changes:
//   - a placeholder server, so code samples show a full URL;
//   - tags grouped by BRD module, then by service and API category (see
//     group-by-module.mjs).
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { groupByModule } from "./group-by-module.mjs";

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

function load(name) {
  return JSON.parse(readFileSync(join(source, name), "utf8"));
}

function save(name, spec) {
  writeFileSync(join(target, name), JSON.stringify(spec, null, 2) + "\n");
}

const integrator = load("openapi-public.json");
integrator.servers = SERVERS;
save("integrator.json", groupByModule(integrator));

const internal = load("openapi-internal.json");
internal.servers = SERVERS;
save("internal.json", groupByModule(internal));

console.log(
  `prepared ${Object.keys(integrator.paths).length} integrator and ${Object.keys(internal.paths).length} internal paths`,
);
