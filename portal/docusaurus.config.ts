import type * as Preset from "@docusaurus/preset-classic";
import type { Config } from "@docusaurus/types";
import type * as OpenApiPlugin from "docusaurus-plugin-openapi-docs";
import { themes as prismThemes } from "prism-react-renderer";

const REPO = "https://github.com/Intelehealth/intelehealth-cmp-tsi";

const config: Config = {
  // The OpenAPI plugin and theme (5.x) are built for the Rspack/SWC toolchain.
  future: {
    faster: true,
    // CSS cascade layers are left off: with them, page-level CSS modules lose
    // to the base theme's rules and the landing page styling does not apply.
    v4: {
      removeLegacyPostBuildHeadAttribute: true,
      useCssCascadeLayers: false,
      siteStorageNamespacing: true,
      fasterByDefault: true,
      mdx1CompatDisabledByDefault: true,
    },
  },
  title: "TSI DPDP CMS Developer Portal",
  tagline: "Consent management API for the Digital Personal Data Protection Act",
  url: "https://intelehealth.github.io",
  baseUrl: "/intelehealth-cmp-tsi/",
  organizationName: "Intelehealth",
  projectName: "intelehealth-cmp-tsi",
  trailingSlash: false,
  onBrokenLinks: "throw",
  markdown: { hooks: { onBrokenMarkdownLinks: "throw" } },
  i18n: { defaultLocale: "en", locales: ["en"] },

  presets: [
    [
      "classic",
      {
        docs: {
          routeBasePath: "/",
          sidebarPath: "./sidebars.ts",
          docItemComponent: "@theme/ApiItem",
        },
        blog: false,
        theme: { customCss: "./src/css/custom.css" },
      } satisfies Preset.Options,
    ],
  ],

  plugins: [
    [
      "docusaurus-plugin-openapi-docs",
      {
        id: "api",
        docsPluginId: "classic",
        config: {
          integrator: {
            specPath: ".specs/integrator.json",
            outputDir: "docs/integrator-api",
            sidebarOptions: { groupPathsBy: "tagGroup" },
          } satisfies OpenApiPlugin.Options,
          internal: {
            specPath: ".specs/internal.json",
            outputDir: "docs/internal-api",
            sidebarOptions: { groupPathsBy: "tagGroup" },
          } satisfies OpenApiPlugin.Options,
        },
      },
    ],
  ],
  themes: ["docusaurus-theme-openapi-docs"],

  themeConfig: {
    colorMode: { defaultMode: "light", respectPrefersColorScheme: true },
    navbar: {
      title: "TSI DPDP CMS",
      items: [
        { type: "docSidebar", sidebarId: "guides", label: "Docs", position: "left" },
        { type: "docSidebar", sidebarId: "integratorApi", label: "Integrator API", position: "left" },
        { type: "docSidebar", sidebarId: "internalApi", label: "Internal API", position: "left" },
        { href: `${REPO}/blob/main/CHANGELOG.md`, label: "What's new", position: "left" },
        { href: REPO, label: "GitHub", position: "right" },
      ],
    },
    footer: {
      style: "dark",
      links: [
        {
          title: "Docs",
          items: [
            { label: "Get started", to: "/get-started" },
            { label: "Authentication", to: "/authentication" },
            { label: "Errors", to: "/errors" },
          ],
        },
        {
          title: "API reference",
          items: [
            { label: "Integrator API", to: "/integrator-api/tsi-dpdp-cms-api" },
            { label: "Internal API", to: "/internal-api/tsi-dpdp-cms-api-internal" },
            { label: "OpenAPI files", href: `${REPO}/tree/main/docs/api` },
          ],
        },
        {
          title: "Project",
          items: [
            { label: "Source", href: REPO },
            { label: "Security policy", href: `${REPO}/blob/main/SECURITY.md` },
            { label: "Changelog", href: `${REPO}/blob/main/CHANGELOG.md` },
          ],
        },
      ],
    },
    prism: {
      theme: prismThemes.oneLight,
      darkTheme: prismThemes.nightOwl,
      additionalLanguages: ["bash", "json", "python"],
    },
    languageTabs: [
      { highlight: "bash", language: "curl", logoClass: "curl" },
      { highlight: "python", language: "python", logoClass: "python" },
      { highlight: "javascript", language: "nodejs", logoClass: "nodejs" },
      { highlight: "java", language: "java", logoClass: "java" },
    ],
    api: { schemaExpansion: { enabled: true, default: 1, max: 4 } },
  } satisfies Preset.ThemeConfig,
};

export default config;
