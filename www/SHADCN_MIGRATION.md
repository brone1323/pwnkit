# shadcn/ui Migration Plan — pwnkit www

This document tracks the rollout of [shadcn/ui](https://ui.shadcn.com/) into
`www/`. The site is Astro 6 + Tailwind v4 + React 19, dark-mode-only, themed
with the pwnkit crimson/night palette. We use the **`radix-luma`** style with
the **`radix`** base — the same configuration as `packages/dashboard`, which
gives us the Vercel/Radix aesthetic.

The migration is staged: install + theming + plan landed first; the actual
homepage rewrite happens in a follow-up after the structural refactor of
`index.astro` is merged.

## What was installed

- Initialized via `npx shadcn@latest init -y -b radix --css-variables -p luma`
- Components added: `button`, `card`, `badge`, `table`, `separator`, `tooltip`,
  `tabs` (in `src/components/ui/`)
- New deps: `class-variance-authority`, `clsx`, `tailwind-merge`,
  `tw-animate-css`, `radix-ui`, `lucide-react`, `@fontsource-variable/inter`,
  `shadcn`
- New files: `src/lib/utils.ts`, `components.json`
- `tsconfig.json` gained `baseUrl: "."` + `paths: { "@/*": ["./src/*"] }`
- `src/styles/global.css` extended with the shadcn `@theme inline` block,
  `:root` token map, and a passthrough `.dark` block

## components.json

```jsonc
{
  "$schema": "https://ui.shadcn.com/schema.json",
  "style": "radix-luma",          // matches packages/dashboard
  "rsc": false,
  "tsx": true,
  "tailwind": {
    "config": "",
    "css": "src/styles/global.css",
    "baseColor": "neutral",
    "cssVariables": true,
    "prefix": ""
  },
  "iconLibrary": "lucide",
  "aliases": {
    "components": "@/components",
    "utils":      "@/lib/utils",
    "ui":         "@/components/ui",
    "lib":        "@/lib",
    "hooks":      "@/hooks"
  }
}
```

## Color token mapping

shadcn components consume semantic CSS variables (`--background`, `--primary`,
`--card`, ...). We override these in `:root` so every shadcn component picks up
pwnkit's crimson/night palette automatically — no per-component restyling
required.

| shadcn token             | pwnkit value                          | Notes                              |
| ------------------------ | ------------------------------------- | ---------------------------------- |
| `--background`           | `#0a0a0a` (`--color-night`)           | Page background                    |
| `--foreground`           | `#ffffff`                             | Default text                       |
| `--card`                 | `#141414` (`--color-night-light`)     | Card / popover surface             |
| `--card-foreground`      | `#ffffff`                             |                                    |
| `--popover`              | `#141414`                             |                                    |
| `--popover-foreground`   | `#ffffff`                             |                                    |
| `--primary`              | `#DC2626` (`--color-crimson`)         | Brand. Used by `<Button>` default. |
| `--primary-foreground`   | `#ffffff`                             |                                    |
| `--secondary`            | `#1e1e1e` (`--color-night-lighter`)   | Subtle surface                     |
| `--secondary-foreground` | `#ffffff`                             |                                    |
| `--muted`                | `#1e1e1e`                             | Disabled / placeholder bg          |
| `--muted-foreground`     | `#a3a3a3` (`--color-smoke`)           | Secondary text                     |
| `--accent`               | `#1e1e1e`                             | Hover surface                      |
| `--accent-foreground`    | `#ffffff`                             |                                    |
| `--destructive`          | `#EF4444` (`--color-crimson-light`)   | Errors                             |
| `--border`               | `rgba(255,255,255,0.10)`              | GitHub-dark style hairlines        |
| `--input`                | `rgba(255,255,255,0.15)`              |                                    |
| `--ring`                 | `#DC2626`                             | Focus ring = crimson               |
| `--chart-1..5`           | crimson + grey ramp                   | For any future charts              |
| `--radius`               | `0.625rem`                            | shadcn default                     |

The existing pwnkit Tailwind tokens (`bg-night`, `bg-night-light`, `bg-crimson`,
`text-smoke`, etc.) are untouched in `@theme {}` and continue to work side by
side with the new semantic shadcn classes (`bg-background`, `bg-card`,
`bg-primary`, `text-muted-foreground`, ...). Existing pages keep rendering;
new code can use either set, but **prefer the semantic tokens for any
shadcn-based component** so dark/light parity stays consistent if we ever add
a light mode.

## Migration: Before / After

The structural refactor agent is currently splitting `index.astro` into
section components. **Do not edit `index.astro` or its new section components
yet.** The snippets below are templates for the follow-up PR.

### 1. Hero CTAs

Today the hero uses inline `<a>` styled with utility classes. Replace with
`<Button asChild>` so we keep the link semantics but inherit shadcn's hover,
focus-ring, and size system.

Before:

```astro
<a
  href="#install"
  class="inline-flex items-center gap-2 px-6 py-3 bg-crimson hover:bg-crimson-light text-white font-medium rounded-md transition-colors"
>
  Get started
</a>
```

After:

```tsx
import { Button } from "@/components/ui/button"

<Button asChild size="lg">
  <a href="#install">Get started</a>
</Button>

<Button asChild size="lg" variant="outline">
  <a href="https://github.com/peaktwilight/pwnkit">Star on GitHub</a>
</Button>
```

`variant="default"` already maps to `bg-primary` = crimson, and the focus ring
inherits `--ring` = crimson. No custom classes needed.

### 2. Feature cards / Trinity cards

Before:

```astro
<div class="rounded-lg border border-white/10 bg-night-light p-6">
  <h3 class="text-xl font-semibold text-white">Discover</h3>
  <p class="mt-2 text-smoke">Crawl the target ...</p>
</div>
```

After:

```tsx
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from "@/components/ui/card"

<Card>
  <CardHeader>
    <CardTitle>Discover</CardTitle>
    <CardDescription>Crawl the target attack surface end-to-end.</CardDescription>
  </CardHeader>
  <CardContent>
    {/* body copy, bullets, mini diagram */}
  </CardContent>
  <CardFooter>
    <Button asChild variant="ghost" size="sm">
      <a href="/docs/discover">Learn more →</a>
    </Button>
  </CardFooter>
</Card>
```

`<Card>` already uses `bg-card` (= `--color-night-light`) and
`border-border` (= white/10), so it matches the current panels for free.

### 3. Benchmark comparison table

Before: a hand-rolled `<table>` with `<th class="text-left text-smoke ...">`.

After:

```tsx
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell, TableCaption } from "@/components/ui/table"
import { Tooltip, TooltipTrigger, TooltipContent, TooltipProvider } from "@/components/ui/tooltip"

<TooltipProvider>
  <Table>
    <TableCaption>XBOW benchmark — 87.5% pwnkit vs competitors</TableCaption>
    <TableHeader>
      <TableRow>
        <TableHead>Agent</TableHead>
        <TableHead className="text-right">Score</TableHead>
        <TableHead className="text-right">Cost / chal.</TableHead>
        <TableHead>Notes</TableHead>
      </TableRow>
    </TableHeader>
    <TableBody>
      <TableRow>
        <TableCell className="font-medium">pwnkit</TableCell>
        <TableCell className="text-right">87.5%</TableCell>
        <TableCell className="text-right">$0.42</TableCell>
        <TableCell>
          <Tooltip>
            <TooltipTrigger>Shell-first</TooltipTrigger>
            <TooltipContent>10-turn IDOR vs 20+ for structured tools</TooltipContent>
          </Tooltip>
        </TableCell>
      </TableRow>
      {/* ... */}
    </TableBody>
  </Table>
</TooltipProvider>
```

`<TooltipProvider>` should be hoisted to the page root (or `Layout.astro`)
once we have more than one tooltip — see "Outstanding wiring" below.

### 4. Status pills

Before:

```astro
<span class="inline-flex items-center rounded-full border border-crimson/40 bg-crimson/10 px-2 py-0.5 text-xs text-crimson">
  87.5%
</span>
```

After:

```tsx
import { Badge } from "@/components/ui/badge"

<Badge variant="default">87.5%</Badge>          {/* solid crimson */}
<Badge variant="outline">XBOW verified</Badge>  {/* hairline outline */}
<Badge variant="secondary">v0.5</Badge>         {/* night-lighter chip */}
```

If we want a "soft crimson" variant (crimson text on translucent crimson bg),
add it to `badgeVariants` in `src/components/ui/badge.tsx`:

```tsx
crimson:
  "bg-primary/10 text-primary border-primary/40 [a]:hover:bg-primary/20",
```

### 5. Section dividers

Before: `<div class="h-px bg-white/10" />`

After:

```tsx
import { Separator } from "@/components/ui/separator"

<Separator className="my-16" />
<Separator orientation="vertical" className="h-6" />
```

### 6. Tabs (e.g. "Web / API / npm / Source" target switcher)

```tsx
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs"

<Tabs defaultValue="web">
  <TabsList>
    <TabsTrigger value="web">Web app</TabsTrigger>
    <TabsTrigger value="api">API</TabsTrigger>
    <TabsTrigger value="npm">npm package</TabsTrigger>
    <TabsTrigger value="src">Source code</TabsTrigger>
  </TabsList>
  <TabsContent value="web">{/* ... */}</TabsContent>
  {/* ... */}
</Tabs>
```

### 7. `npx pwnkit` command display

shadcn does not ship a `code` primitive in the radix base, so for the install
block we keep the existing `<pre><code>` markup but wrap the copy button as a
`<Button variant="ghost" size="icon">` using `lucide-react`'s `Copy` /
`Check` icons. Example:

```tsx
import { Button } from "@/components/ui/button"
import { Copy, Check } from "lucide-react"
import { useState } from "react"

function CopyCommand({ cmd }: { cmd: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <div className="flex items-center justify-between rounded-md border bg-card px-4 py-3 font-mono text-sm">
      <code>{cmd}</code>
      <Button
        variant="ghost"
        size="icon"
        onClick={() => {
          navigator.clipboard.writeText(cmd)
          setCopied(true)
          setTimeout(() => setCopied(false), 1500)
        }}
        aria-label="Copy command"
      >
        {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
      </Button>
    </div>
  )
}
```

## Outstanding wiring (do in the migration PR, not now)

1. **`TooltipProvider` in `Layout.astro`.** Currently no tooltip is rendered,
   so we don't need it yet. When the benchmark table lands, add:
   ```astro
   ---
   import { TooltipProvider } from "@/components/ui/tooltip"
   ---
   <TooltipProvider client:load>
     <slot />
   </TooltipProvider>
   ```
   Note that `TooltipProvider` is a React component, so it must be rendered
   inside an island (`client:load`) or live inside an existing React tree.
2. **Add a `crimson` badge variant** if any section needs the soft-crimson
   pill style we use today.
3. **Audit `bg-night-light` → `bg-card`** sweep once shadcn cards are in
   place, so the two surfaces stay in sync if `--color-night-light` ever
   changes.
4. **Replace bespoke focus rings** (`focus:ring-crimson`) with the shadcn
   default — they now map to the same color via `--ring`.
5. **Decide on `Inter Variable`.** shadcn init pulled in
   `@fontsource-variable/inter` and global.css imports it. The site currently
   sets `font-family: 'Outfit'` inline on `<body>` in `Layout.astro`. Either
   switch to Inter (matches dashboard), or remove the unused font import.

## Verification

- `npm run build` in `www/` — 14 pages built, no TypeScript errors.
- `ls www/src/components/ui/` — 7 components present.
- No existing pwnkit tokens were removed; all current pages render unchanged.

## Why `radix-luma` + `radix` base?

- `packages/dashboard` already uses this combination; sharing it means brand
  consistency between marketing and product.
- The `radix` base is built directly on Radix Primitives (the same primitives
  Vercel uses for their dashboard), giving the cleaner, slightly more opinionated
  Vercel aesthetic vs. the older `base` style.
- `luma` preset = generous radius, soft borders, subtle hover states — matches
  the GitHub-dark refresh we already adopted in the rest of the site.
