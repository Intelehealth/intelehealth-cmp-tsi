import assert from "node:assert/strict";
import { test } from "node:test";

import { EXTENSIONS_TITLE, groupByModule } from "./group-by-module.mjs";

function operation(service, module) {
  return { tags: [service], "x-module": module, summary: "f" };
}

function sample() {
  return {
    "x-modules": [
      { name: "consent_lifecycle", title: "Consent Management Lifecycle", kind: "module", services: ["consent", "policy"] },
      { name: "grievance", title: "Grievance Redressal Mechanism", kind: "module", services: ["grievance"] },
      { name: "breach", title: "Personal data breach handling", kind: "extension", services: ["breach"] },
      { name: "ropa", title: "Record of processing activities", kind: "extension", services: ["ropa"] },
    ],
    paths: {
      "/api/v1/admin/ropa/export_ropa": { post: operation("ropa", "ropa") },
      "/api/v1/admin/grievance/list_grievances": { post: operation("grievance", "grievance") },
      "/api/v1/client/consent/record_consent": { post: operation("consent", "consent_lifecycle") },
      "/api/v1/admin/policy/get_policy": { get: operation("policy", "consent_lifecycle"), post: operation("policy", "consent_lifecycle") },
      "/api/v1/admin/consent/record_consent": { post: operation("consent", "consent_lifecycle") },
      "/api/v1/admin/breach/report_breach": { post: operation("breach", "breach") },
    },
  };
}

test("the sidebar groups are the BRD modules, in the BRD's order", () => {
  const groups = groupByModule(sample())["x-tagGroups"];
  assert.deepEqual(
    groups.map((group) => group.name),
    ["Consent Management Lifecycle", "Grievance Redressal Mechanism", EXTENSIONS_TITLE],
  );
});

test("a module lists its services, each split by API category", () => {
  const [consent] = groupByModule(sample())["x-tagGroups"];
  assert.deepEqual(consent.tags, ["consent / admin", "consent / client", "policy / admin"]);
});

test("the same function in two categories lands under two tags", () => {
  const spec = groupByModule(sample());
  assert.deepEqual(spec.paths["/api/v1/admin/consent/record_consent"].post.tags, ["consent / admin"]);
  assert.deepEqual(spec.paths["/api/v1/client/consent/record_consent"].post.tags, ["consent / client"]);
});

test("GET and POST of one function share a tag", () => {
  const item = groupByModule(sample()).paths["/api/v1/admin/policy/get_policy"];
  assert.deepEqual(item.get.tags, ["policy / admin"]);
  assert.deepEqual(item.post.tags, ["policy / admin"]);
});

test("extensions share one last group and say what each is for", () => {
  const spec = groupByModule(sample());
  const last = spec["x-tagGroups"].at(-1);
  assert.deepEqual(last.tags, ["breach / admin", "ropa / admin"]);
  const described = Object.fromEntries(spec.tags.map((tag) => [tag.name, tag.description]));
  assert.equal(described["ropa / admin"], "Record of processing activities");
  assert.equal(described["consent / admin"], undefined);
});

test("every tag is declared once, in sidebar order", () => {
  const spec = groupByModule(sample());
  assert.deepEqual(
    spec.tags.map((tag) => tag.name),
    spec["x-tagGroups"].flatMap((group) => group.tags),
  );
});

test("an operation whose module the document does not list stops the build", () => {
  const spec = sample();
  spec.paths["/api/v1/admin/consent/record_consent"].post["x-module"] = "nowhere";
  assert.throws(() => groupByModule(spec), /nowhere/);
});
