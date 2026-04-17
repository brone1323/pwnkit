import React, { useState } from "react";
import { render, Box, Text, useInput, useApp } from "ink";
import { printBanner } from "./banner.js";
import { BORDER, INFO, MUTED, PRIMARY, RAIL, SECONDARY, TEXT } from "./theme.js";

interface MenuOption {
  label: string;
  value: string;
  hint: string;
}

const options: MenuOption[] = [
  { value: "scan", label: "Scan a target", hint: "Web, API, or MCP target" },
  { value: "audit", label: "Audit a package", hint: "Registry package triage" },
  { value: "review", label: "Review a codebase", hint: "Source review and agent analysis" },
  { value: "tui", label: "Open terminal mission control", hint: "Runs, findings, workers, queue" },
  { value: "dashboard", label: "Open local mission control", hint: "Browser dashboard" },
  { value: "doctor", label: "Check runtimes and setup", hint: "Verify CLI and model access" },
  { value: "replay", label: "Replay the last scan", hint: "Animated terminal playback" },
  { value: "history", label: "View past results", hint: "Recent reports and artifacts" },
];

type Phase = "menu" | "input";

function Shortcut({ children }: { children: React.ReactNode }): React.ReactElement {
  return <Text color={MUTED}>{children}</Text>;
}

function PromptRail({
  title,
  meta,
  children,
}: {
  title: string;
  meta?: string;
  children: React.ReactNode;
}): React.ReactElement {
  return (
    <Box>
      <Text color={PRIMARY}>{RAIL}</Text>
      <Box flexDirection="column" marginLeft={1}>
        <Box justifyContent="space-between">
          <Text color={TEXT} bold>{title}</Text>
          {meta ? <Text color={MUTED}>{meta}</Text> : null}
        </Box>
        {children}
      </Box>
    </Box>
  );
}

function Menu({ onSelect }: { onSelect: (action: string, target?: string) => void }): React.ReactElement {
  const { exit } = useApp();
  const [phase, setPhase] = useState<Phase>("menu");
  const [selected, setSelected] = useState(0);
  const [action, setAction] = useState("");
  const [inputValue, setInputValue] = useState("");
  const [placeholder, setPlaceholder] = useState("");
  const [inputLabel, setInputLabel] = useState("");

  useInput((input, key) => {
    if (key.escape || (key.ctrl && input === "c")) {
      exit();
      return;
    }

    if (phase === "menu") {
      if (key.upArrow) setSelected((s) => Math.max(0, s - 1));
      if (key.downArrow) setSelected((s) => Math.min(options.length - 1, s + 1));
      if (key.return) {
        const opt = options[selected].value;
        if (opt === "history" || opt === "doctor" || opt === "replay" || opt === "dashboard" || opt === "tui") {
          onSelect(opt);
          return;
        }
        setAction(opt);
        setPhase("input");
        if (opt === "scan") {
          setInputLabel("Target URL");
          setPlaceholder("https://api.example.com/v1");
        } else if (opt === "audit") {
          setInputLabel("Package name");
          setPlaceholder("express or requests");
        } else if (opt === "review") {
          setInputLabel("Repo path or URL");
          setPlaceholder("./my-project");
        }
      }
    } else if (phase === "input") {
      if (key.return) {
        if (inputValue.trim()) {
          onSelect(action, inputValue.trim());
        }
        return;
      }
      if (key.backspace || key.delete) {
        setInputValue((v) => v.slice(0, -1));
        return;
      }
      if (input && !key.ctrl && !key.meta) {
        setInputValue((v) => v + input);
      }
    }
  });

  return (
    <Box flexDirection="column" paddingLeft={2} paddingRight={2}>
      {phase === "menu" && (
        <Box flexDirection="column" gap={1}>
          <PromptRail title="Launcher" meta="command palette">
            <Text color={MUTED}>Select the next workflow. The launcher stays quiet; the scan shell carries the detail.</Text>
          </PromptRail>
          <PromptRail title="Actions" meta={`${selected + 1}/${options.length}`}>
            <Box flexDirection="column" marginTop={1}>
              {options.map((opt, i) => {
                const isSelected = i === selected;
                return (
                  <Box key={opt.value} marginBottom={1}>
                    <Text color={isSelected ? PRIMARY : BORDER}>{isSelected ? RAIL : "│"}</Text>
                    <Box flexDirection="column" marginLeft={1}>
                      <Text color={isSelected ? TEXT : "#C8C8C8"} bold={isSelected}>
                        {opt.label}
                      </Text>
                      <Text color={isSelected ? SECONDARY : MUTED}>{opt.hint}</Text>
                    </Box>
                  </Box>
                );
              })}
            </Box>
          </PromptRail>
          <Box marginLeft={2} gap={2}>
            <Shortcut>↑↓ move</Shortcut>
            <Shortcut>enter open</Shortcut>
            <Shortcut>esc quit</Shortcut>
          </Box>
        </Box>
      )}

      {phase === "input" && (
        <Box flexDirection="column" gap={1}>
          <PromptRail title={action} meta="target input">
            <Text color={MUTED}>{inputLabel}</Text>
            <Box marginTop={1}>
              <Text color={PRIMARY}>{RAIL}</Text>
              <Box marginLeft={1}>
                <Text color={inputValue ? TEXT : MUTED} bold={Boolean(inputValue)}>
                  {inputValue || placeholder}
                </Text>
                <Text color={INFO}>█</Text>
              </Box>
            </Box>
          </PromptRail>
          <Box marginLeft={2} gap={2}>
            <Shortcut>enter launch</Shortcut>
            <Shortcut>esc cancel</Shortcut>
          </Box>
        </Box>
      )}
    </Box>
  );
}

export function showInkMenu(): Promise<{ action: string; target?: string }> {
  // Print shared banner before Ink takes over
  printBanner();

  return new Promise((resolve) => {
    const instance = render(
      <Menu onSelect={(action, target) => {
        instance.unmount();
        resolve({ action, target });
      }} />
    );
  });
}
