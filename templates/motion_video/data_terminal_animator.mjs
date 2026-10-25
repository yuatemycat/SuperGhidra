#!/usr/bin/env node
/**
 * data_terminal_animator.mjs
 * 
 * Generic data-driven terminal and code animator for HyperFrames & GSAP video compositions.
 * 
 * Capabilities:
 * - Generates ready-to-render HTML/GSAP compositions from real CLI output or structured JSON.
 * - Per-character typewriter animation with realistic cadence and prompt coloring.
 * - Stdout burst revealing (lines appear whole or staggered, exactly matching real terminal streams).
 * - Animated marker swipes (gradient backgroundSize fill) for key statistics, numbers, or alerts.
 * - Syntax highlighting for keywords, memory traces (load:/store:), comments, and status tokens.
 * - Enforces GSAP transform-only motion rules (no integer pixel snapping on left/top).
 * - Enforces font longhand properties and ligature disabling for monospaced code stability.
 * 
 * Usage:
 *   node data_terminal_animator.mjs --input output.txt --output s-proof.html [options]
 *   node data_terminal_animator.mjs --config terminal_scene.json --output s-terminal.html
 */

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";

/**
 * Escapes raw strings for safe HTML rendering.
 */
export function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/**
 * Wraps individual characters into span elements for GSAP typewriter staggered opacity tweens.
 */
export function wrapChars(str, className = "c") {
  return [...str]
    .map((ch) => `<span class="${className}">${escapeHtml(ch)}</span>`)
    .join("");
}

/**
 * Default theme and layout configuration.
 */
export const DEFAULT_CONFIG = {
  compositionId: "terminal",
  width: 1080,
  height: 1920,
  terminal: {
    x: 70,
    y: 200,
    width: 940,
    height: 1100,
    borderRadius: 18,
    title: "Terminal",
    backgroundColor: "#16171C",
    headerColor: "#23252D",
    textColor: "#E6E6E6",
    promptColor: "#5FD38D",
    keywordColor: "#7DC4E4",
    commentColor: "#6B7280",
    markerColor: "#B8F433",
    markerTextColor: "#0A0A0A",
    fontSizePx: 34,
    lineHeight: 1.4,
    fontFamily: "'JetBrains Mono', monospace"
  },
  animation: {
    startSecond: 1.0,
    typeCharDuration: 0.001,
    typeCharStagger: 0.018,
    stdoutLineDelay: 0.12,
    markerDuration: 0.4
  },
  highlights: [],
  blocks: []
};

/**
 * Generates an animated terminal composition HTML string.
 * 
 * @param {object} options Configuration object matching DEFAULT_CONFIG
 * @returns {string} Fully self-contained HTML template with GSAP timeline
 */
export function generateTerminalComposition(options) {
  const cfg = {
    ...DEFAULT_CONFIG,
    ...options,
    terminal: { ...DEFAULT_CONFIG.terminal, ...(options.terminal || {}) },
    animation: { ...DEFAULT_CONFIG.animation, ...(options.animation || {}) }
  };

  const term = cfg.terminal;
  const anim = cfg.animation;
  const blocks = cfg.blocks || [];

  // Generate HTML for command blocks and outputs
  let bodyHtml = "";
  let timelineCode = "";
  let currentTime = anim.startSecond;

  timelineCode += `    // Terminal entrance (transform-only, no pixel snap)\n`;
  timelineCode += `    tl.fromTo("#term-win", \n`;
  timelineCode += `      { opacity: 0, y: 40, scale: 0.96, filter: "blur(8px)" },\n`;
  timelineCode += `      { opacity: 1, y: 0, scale: 1, filter: "blur(0px)", duration: 0.45, ease: "expo.out" },\n`;
  timelineCode += `      ${(currentTime - 0.5 > 0 ? (currentTime - 0.5).toFixed(2) : 0)});\n\n`;

  let hlIndex = 0;
  const allHighlights = [...(cfg.highlights || [])];

  blocks.forEach((block, bIdx) => {
    const cmdId = `cmd_${bIdx}`;
    const promptStr = block.prompt || "$ ";
    const commandText = block.command || "";

    // 1. Command Line HTML
    bodyHtml += `        <div class="ln cmd" id="${cmdId}">`;
    bodyHtml += `${wrapChars(promptStr, "c p")}`;
    bodyHtml += `${wrapChars(commandText, "c")}`;
    bodyHtml += `</div>\n`;

    // 2. Command Typing Timeline
    const cmdDuration = commandText.length * anim.typeCharStagger;
    timelineCode += `    // Block ${bIdx + 1}: Type "${commandText.slice(0, 30)}..."\n`;
    timelineCode += `    tl.fromTo("#${cmdId} .c", \n`;
    timelineCode += `      { opacity: 0 }, \n`;
    timelineCode += `      { opacity: 1, duration: ${anim.typeCharDuration}, stagger: ${anim.typeCharStagger}, ease: "none" }, \n`;
    timelineCode += `      ${currentTime.toFixed(3)});\n`;
    currentTime += cmdDuration + 0.15; // pause after typing before output appears

    // 3. Stdout Lines HTML & Timeline
    if (block.output && block.output.length > 0) {
      const outGroupId = `out_${bIdx}`;
      bodyHtml += `        <div class="out-group" id="${outGroupId}">\n`;

      block.output.forEach((rawLine, lIdx) => {
        let lineHtml = escapeHtml(rawLine);

        // Apply syntax coloring (e.g. keywords load: / store: or custom rules)
        lineHtml = lineHtml.replace(/(load:|store:|read:|write:)/g, '<span class="k">$1</span>');

        // Apply marker highlights
        allHighlights.forEach((hlTarget) => {
          if (lineHtml.includes(hlTarget.pattern)) {
            const hlId = `hl_${hlIndex++}`;
            const replacement = `<span class="hl" id="${hlId}">${escapeHtml(hlTarget.pattern)}</span>`;
            lineHtml = lineHtml.replaceAll(hlTarget.pattern, replacement);

            // Add highlight swipe animation
            const hlDelay = hlTarget.delay || 0.2;
            const hlStart = currentTime + hlDelay;
            timelineCode += `    // Marker highlight "${hlTarget.pattern}"\n`;
            timelineCode += `    tl.to("#${hlId}", {\n`;
            timelineCode += `      backgroundSize: "100% 100%",\n`;
            timelineCode += `      color: "${term.markerTextColor}",\n`;
            timelineCode += `      duration: ${hlTarget.duration || anim.markerDuration},\n`;
            timelineCode += `      ease: "power2.inOut"\n`;
            timelineCode += `    }, ${hlStart.toFixed(3)});\n`;
          }
        });

        const lineId = `ln_${bIdx}_${lIdx}`;
        bodyHtml += `          <div class="ln out" id="${lineId}">${lineHtml}</div>\n`;
      });

      bodyHtml += `        </div>\n`;

      // Timeline for stdout: reveal lines
      const outStagger = block.staggerOutput !== undefined ? block.staggerOutput : anim.stdoutLineDelay;
      timelineCode += `    // Block ${bIdx + 1}: Stdout display\n`;
      timelineCode += `    tl.to("#${outGroupId} .out", {\n`;
      timelineCode += `      opacity: 1,\n`;
      timelineCode += `      duration: 0.08,\n`;
      timelineCode += `      stagger: ${outStagger},\n`;
      timelineCode += `      ease: "none"\n`;
      timelineCode += `    }, ${currentTime.toFixed(3)});\n\n`;

      currentTime += (block.output.length * outStagger) + 0.3;
    }

    // Optional Comment Line
    if (block.comment) {
      const cmId = `cm_${bIdx}`;
      bodyHtml += `        <div class="ln cm" id="${cmId}">${wrapChars(block.comment, "c")}</div>\n`;
      const cmDuration = block.comment.length * (anim.typeCharStagger * 1.2);
      timelineCode += `    // Block ${bIdx + 1}: Comment "${block.comment}"\n`;
      timelineCode += `    tl.fromTo("#${cmId} .c", \n`;
      timelineCode += `      { opacity: 0 }, \n`;
      timelineCode += `      { opacity: 1, duration: ${anim.typeCharDuration}, stagger: ${(anim.typeCharStagger * 1.2).toFixed(3)}, ease: "none" }, \n`;
      timelineCode += `      ${currentTime.toFixed(3)});\n\n`;
      currentTime += cmDuration + 0.4;
    }

    if (bIdx < blocks.length - 1) {
      bodyHtml += `        <div class="gap"></div>\n`;
      currentTime += 0.2;
    }
  });

  const totalDuration = (currentTime + 1.0).toFixed(2);

  return `<template>
  <style>
    #root {
      position: absolute;
      inset: 0;
      overflow: hidden;
      width: ${cfg.width}px;
      height: ${cfg.height}px;
    }

    #term-win {
      position: absolute;
      left: ${term.x}px;
      top: ${term.y}px;
      width: ${term.width}px;
      height: ${term.height}px;
      border-radius: ${term.borderRadius}px;
      background-color: ${term.backgroundColor};
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.4);
      overflow: hidden;
      transform: translate3d(0, 0, 0);
    }

    #term-bar {
      position: absolute;
      left: 0;
      top: 0;
      width: 100%;
      height: 64px;
      background-color: ${term.headerColor};
      display: flex;
      align-items: center;
    }

    .term-dots {
      position: absolute;
      left: 24px;
      display: flex;
      gap: 10px;
    }

    .term-dot {
      width: 18px;
      height: 18px;
      border-radius: 9px;
    }

    .dot-close { background-color: #FF5F57; }
    .dot-min   { background-color: #FEBC2E; }
    .dot-max   { background-color: #28C840; }

    .term-title {
      width: 100%;
      text-align: center;
      color: #8B8F98;
      font-family: 'Inter', sans-serif;
      font-weight: 500;
      font-size: 28px;
      line-height: 1;
      pointer-events: none;
    }

    #term-body {
      position: absolute;
      left: 32px;
      top: 96px;
      width: calc(100% - 64px);
      height: calc(100% - 128px);
      color: ${term.textColor};
      font-family: ${term.fontFamily};
      font-weight: 500;
      font-size: ${term.fontSizePx}px;
      line-height: ${term.lineHeight};
      font-variant-ligatures: none;
      font-feature-settings: "liga" 0, "calt" 0;
      overflow: hidden;
    }

    #term-body .ln {
      min-height: ${term.lineHeight}em;
      white-space: pre-wrap;
      word-break: break-all;
    }

    #term-body .c {
      opacity: 0;
    }

    #term-body .p {
      color: ${term.promptColor};
      font-weight: 700;
    }

    #term-body .out {
      opacity: 0;
    }

    #term-body .k {
      color: ${term.keywordColor};
    }

    #term-body .cm {
      color: ${term.commentColor};
      font-style: italic;
    }

    #term-body .gap {
      height: ${term.lineHeight}em;
    }

    #term-body .hl {
      display: inline-block;
      padding: 0 4px;
      border-radius: 4px;
      background: linear-gradient(${term.markerColor}, ${term.markerColor}) no-repeat left center;
      background-size: 0% 100%;
      color: inherit;
    }
  </style>

  <div id="root" data-composition-id="${cfg.compositionId}" data-width="${cfg.width}" data-height="${cfg.height}">
    <div id="term-win" data-hold="true">
      <div id="term-bar">
        <div class="term-dots">
          <span class="term-dot dot-close"></span>
          <span class="term-dot dot-min"></span>
          <span class="term-dot dot-max"></span>
        </div>
        <div class="term-title">${escapeHtml(term.title)}</div>
      </div>
      <div id="term-body">
${bodyHtml}      </div>
    </div>
  </div>

  <script>
    window.__timelines = window.__timelines || {};
    const tl = gsap.timeline({ paused: true });

${timelineCode}
    window.__timelines["${cfg.compositionId}"] = tl;
  </script>
</template>
`;
}

/**
 * Parses raw text output (such as assets/real_output.txt) into structured blocks.
 */
export function parseRawOutputText(rawText) {
  const clean = rawText.replace(/\r/g, "");
  const rawBlocks = clean.split("\n\n").map((b) => b.trim().split("\n")).filter((b) => b.length > 0);

  const blocks = [];
  for (const lines of rawBlocks) {
    if (lines.length === 0) continue;
    const firstLine = lines[0];
    let command = firstLine;
    let prompt = "$ ";
    if (firstLine.startsWith("$ ")) {
      command = firstLine.slice(2);
      prompt = "$ ";
    } else if (firstLine.startsWith("> ")) {
      command = firstLine.slice(2);
      prompt = "> ";
    }

    const output = lines.slice(1);
    blocks.push({
      prompt,
      command,
      output
    });
  }
  return blocks;
}

// CLI Execution
if (import.meta.url === `file:///${process.argv[1].replace(/\\/g, "/")}`) {
  const args = process.argv.slice(2);
  let inputFile = null;
  let configFile = null;
  let outputFile = null;
  let title = "Terminal - Real Output";
  let highlights = [];

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--input" || arg === "-i") {
      inputFile = args[++i];
    } else if (arg === "--config" || arg === "-c") {
      configFile = args[++i];
    } else if (arg === "--output" || arg === "-o") {
      outputFile = args[++i];
    } else if (arg === "--title" || arg === "-t") {
      title = args[++i];
    } else if (arg === "--hl") {
      const patterns = args[++i].split(",");
      highlights = patterns.map((p) => ({ pattern: p.trim() }));
    }
  }

  if (!outputFile) {
    console.log("Usage: node data_terminal_animator.mjs --input <raw_output.txt> --output <comp.html> [--title <str>] [--hl <str,str>]");
    console.log("       node data_terminal_animator.mjs --config <config.json> --output <comp.html>");
    process.exit(1);
  }

  let config = { ...DEFAULT_CONFIG };

  if (configFile) {
    const rawCfg = JSON.parse(readFileSync(configFile, "utf8"));
    config = { ...config, ...rawCfg };
  } else if (inputFile) {
    const rawText = readFileSync(inputFile, "utf8");
    const blocks = parseRawOutputText(rawText);
    config.blocks = blocks;
    config.terminal.title = title;
    if (highlights.length > 0) {
      config.highlights = highlights;
    }
  } else {
    console.error("Error: Either --input or --config must be provided.");
    process.exit(1);
  }

  const generatedHtml = generateTerminalComposition(config);
  writeFileSync(outputFile, generatedHtml, "utf8");
  console.log(`✓ Generated terminal composition at ${outputFile} (${generatedHtml.length} bytes)`);
}
