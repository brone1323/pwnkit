import type { Evidence, PocStep } from "@pwnkit/shared";

function looksLikeHttpRequest(text: string): boolean {
  return /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+/i.test(text.trim());
}

function parseHttpRequestLine(text: string): { method: string; url: string } | null {
  const firstLine = text.split("\n")[0]?.trim() ?? "";
  const m = firstLine.match(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)/i);
  if (!m) return null;
  return { method: m[1].toUpperCase(), url: m[2] };
}

export function derivePocStepsFromEvidence(evidence: Evidence): PocStep[] {
  const steps: PocStep[] = [];
  const request = evidence.request?.trim() ?? "";
  const response = evidence.response?.trim() ?? "";
  const analysis = evidence.analysis?.trim() ?? "";

  if (request) {
    if (looksLikeHttpRequest(request)) {
      const parsed = parseHttpRequestLine(request);
      if (parsed) {
        steps.push({
          id: "exploit-1",
          kind: "exploit",
          summary: "Trigger vulnerable endpoint",
          action: { type: "http", method: parsed.method, url: parsed.url },
        });
      } else {
        steps.push({
          id: "exploit-1",
          kind: "exploit",
          summary: "Run exploit request",
          action: { type: "note", text: request },
        });
      }
    } else {
      steps.push({
        id: "exploit-1",
        kind: "exploit",
        summary: "Execute exploit command",
        action: { type: "shell", cmd: request },
      });
    }
  }

  if (response) {
    steps.push({
      id: "verify-1",
      kind: "verify",
      summary: "Observe vulnerable response",
      action: { type: "note", text: response },
      expect: { type: "body-contains", text: response.slice(0, 64) },
    });
  }

  if (analysis) {
    steps.push({
      id: "analysis-1",
      kind: "prerequisite",
      summary: "Analyst context",
      action: { type: "note", text: analysis },
    });
  }

  return steps;
}
