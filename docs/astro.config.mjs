import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import rehypeMermaid from "rehype-mermaid";

export default defineConfig({
  output: "static",
  outDir: "./dist",
  site: "https://docs.pwnkit.com",
  markdown: {
    // Render ```mermaid code blocks as SVG at build time
    syntaxHighlight: { type: "shiki", excludeLangs: ["mermaid"] },
    rehypePlugins: [
      [rehypeMermaid, { strategy: "img-svg", dark: true }],
    ],
  },
  integrations: [
    starlight({
      title: "pwnkit",
      description:
        "Documentation for pwnkit — fully autonomous agentic pentesting framework.",
      logo: {
        src: "./src/assets/pwnkit-icon.gif",
        alt: "pwnkit",
      },
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/PwnKit-Labs/pwnkit",
        },
        {
          icon: "external",
          label: "Website",
          href: "https://pwnkit.com",
        },
      ],
      defaultLocale: "root",
      expressiveCode: {
        themes: ["dracula"],
      },
      sidebar: [
        {
          label: "Getting Started",
          slug: "getting-started",
        },
        {
          label: "Commands",
          slug: "commands",
        },
        {
          label: "Features",
          slug: "features",
        },
        {
          label: "Configuration",
          slug: "configuration",
        },
        {
          label: "Recipes",
          slug: "recipes",
        },
        {
          label: "Finding Triage",
          slug: "triage",
        },
        {
          label: "Architecture",
          slug: "architecture",
        },
        {
          label: "Core Concepts",
          items: [
            { label: "Agent Loop", slug: "agent-loop" },
            { label: "Blind Verification", slug: "blind-verification" },
            { label: "Adversarial Evals", slug: "adversarial-evals" },
            { label: "White-Box Mode", slug: "white-box-mode" },
            { label: "Budget Management", slug: "budget-management" },
          ],
        },
        {
          label: "Benchmark",
          items: [
            { label: "Overview", slug: "benchmark" },
            { label: "Methodology", slug: "methodology" },
          ],
        },
        {
          label: "Roadmap",
          slug: "roadmap",
        },
        {
          label: "Research",
          items: [
            { label: "Overview", slug: "research" },
            { label: "2026-04-11 Triage Ablation Results", slug: "research/2026-04-11-ablation" },
            { label: "Dynamic Routing Design", slug: "research/dynamic-routing-design" },
            { label: "Triage Dataset", slug: "research/triage-dataset" },
            { label: "Feature Extractor", slug: "research/feature-extractor" },
            { label: "Shell-First Rationale", slug: "research/shell-first" },
            { label: "Model Comparison", slug: "research/model-comparison" },
            { label: "XBOW Analysis", slug: "research/xbow-analysis" },
            { label: "Competitive Landscape", slug: "research/competitive-landscape" },
            { label: "Agent Techniques", slug: "research/agent-techniques" },
            { label: "Finding Triage ML", slug: "research/finding-triage-ml" },
            { label: "FP Reduction Moat", slug: "research/fp-reduction-moat" },
            { label: "XBEN-099 Investigation", slug: "research/xben-099-investigation" },
            { label: "Unsolved Eight Investigation", slug: "research/unsolved-eight-investigation" },
          ],
        },
        {
          label: "Cloud",
          slug: "cloud",
        },
        {
          label: "API Keys",
          slug: "api-keys",
        },
      ],
      customCss: ["./src/styles/custom.css"],
    }),
  ],
});
