import Link from "@docusaurus/Link";
import Layout from "@theme/Layout";
import type { ReactNode } from "react";

import styles from "./index.module.css";

const SAMPLE = `curl -X POST https://cms.example.org/api/v1/client/consent/validate_consent \\
  -H 'Content-Type: application/json' \\
  -H 'X-API-Key: <key>' -H 'X-API-Secret: <secret>' \\
  -d '{
    "user_id": "<principal identifier>",
    "required_purpose_id": "marketing"
  }'`;

const PATHS = [
  {
    tag: "Fiduciary backend",
    title: "Record and check consent",
    text: "Fetch the active policy, record each purpose decision, and validate consent before you process personal data.",
    to: "/consent-flow",
  },
  {
    tag: "Principal app",
    title: "Rights requests",
    text: "Let a data principal see their history, ask for erasure or correction, and nominate someone to act for them.",
    to: "/rights",
  },
  {
    tag: "Principal app",
    title: "Grievances",
    text: "Submit a complaint, follow it by reference number, attach evidence and rate the outcome.",
    to: "/grievances",
  },
];

const CONCEPTS = [
  { title: "Authentication", text: "API key and secret, or a principal token from a one-time code.", to: "/authentication" },
  { title: "Tenancy and identity", text: "Which fields the server takes from your credential.", to: "/tenancy" },
  { title: "Errors", text: "One error body, and what each status means.", to: "/errors" },
];

const REFERENCE = [
  {
    title: "Integrator API",
    count: "40 operations",
    text: "Everything under /api/v1/client/ and /api/v1/public/. For fiduciary applications and principal-facing apps.",
    to: "/integrator-api/tsi-dpdp-cms-api",
  },
  {
    title: "Internal API",
    count: "189 operations",
    text: "Every function, including the admin console API, with the role permission each one needs.",
    to: "/internal-api/tsi-dpdp-cms-api-internal",
  },
];

export default function Home(): ReactNode {
  return (
    <Layout
      title="Developer Portal"
      description="Guides and API reference for the TSI DPDP Consent Management System."
    >
      <header className={styles.hero}>
        <div className={styles.heroInner}>
          <div>
            <span className={styles.eyebrow}>Digital Personal Data Protection Act</span>
            <h1 className={styles.title}>Build consent into your product</h1>
            <p className={styles.lead}>
              The TSI DPDP Consent Management System records, validates and withdraws consent for a data
              fiduciary, and handles every right a data principal holds: access, correction, erasure,
              nomination and grievance.
            </p>
            <div className={styles.actions}>
              <Link className={styles.primary} to="/get-started">
                Get started
              </Link>
              <Link className={styles.secondary} to="/integrator-api/tsi-dpdp-cms-api">
                API reference
              </Link>
            </div>
          </div>
          <div className={styles.sample}>
            <div className={styles.sampleBar}>
              <span />
              <span />
              <span />
              <em>validate_consent</em>
            </div>
            <pre>
              <code>{SAMPLE}</code>
            </pre>
          </div>
        </div>
      </header>

      <main className={styles.main}>
        <section>
          <h2 className={styles.heading}>Choose your path</h2>
          <div className={styles.grid3}>
            {PATHS.map((item) => (
              <Link key={item.title} className={styles.card} to={item.to}>
                <span className={styles.tag}>{item.tag}</span>
                <h3>{item.title}</h3>
                <p>{item.text}</p>
                <span className={styles.more}>Read the guide →</span>
              </Link>
            ))}
          </div>
        </section>

        <section>
          <h2 className={styles.heading}>API reference</h2>
          <p className={styles.sub}>
            Generated from the server's own validation schemas and permission tables, so it matches the
            running code.
          </p>
          <div className={styles.grid2}>
            {REFERENCE.map((item) => (
              <Link key={item.title} className={`${styles.card} ${styles.cardLarge}`} to={item.to}>
                <span className={styles.tag}>{item.count}</span>
                <h3>{item.title}</h3>
                <p>{item.text}</p>
                <span className={styles.more}>Browse the reference →</span>
              </Link>
            ))}
          </div>
        </section>

        <section>
          <h2 className={styles.heading}>Core concepts</h2>
          <div className={styles.grid3}>
            {CONCEPTS.map((item) => (
              <Link key={item.title} className={`${styles.card} ${styles.cardPlain}`} to={item.to}>
                <h3>{item.title}</h3>
                <p>{item.text}</p>
              </Link>
            ))}
          </div>
        </section>
      </main>
    </Layout>
  );
}
