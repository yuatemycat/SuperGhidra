#!/usr/bin/env node
/**
 * font_longhand_sanitizer.mjs
 * 
 * Production-ready utility to rewrite shorthand CSS `font:` declarations into explicit longhand
 * properties (`font-family`, `font-size`, `font-weight`, `font-style`, `line-height`).
 * 
 * Why:
 * Headless Chrome (as used in HyperFrames, Puppeteer, Playwright, and Chromium render pipelines)
 * frequently drops custom webfonts (e.g. 'Archivo Black', 'JetBrains Mono', 'Inter') or fails to
 * match font-face descriptors when `font:` shorthand is used, causing silent fallback to Times New
 * Roman or Arial. Expanding shorthand to longhand guarantees deterministic font rendering across
 * headless capture passes.
 * 
 * Usage:
 *   node font_longhand_sanitizer.mjs [options] [files/directories...]
 * 
 * Examples:
 *   node font_longhand_sanitizer.mjs --dir ./compositions
 *   node font_longhand_sanitizer.mjs --check ./compositions
 *   node font_longhand_sanitizer.mjs --dry-run index.html
 */

import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { resolve, extname, join, relative } from "node:path";
import process from "node:process";

const DEFAULT_EXTS = new Set([".html", ".css", ".mjs", ".js", ".svg"]);

// Recognized font weights
const WEIGHT_KEYWORDS = new Set([
  "normal", "bold", "bolder", "lighter",
  "100", "200", "300", "400", "500", "600", "700", "800", "900"
]);

// Recognized font styles
const STYLE_KEYWORDS = new Set(["normal", "italic", "oblique"]);

/**
 * Parses and expands a single CSS `font:` shorthand value into longhand properties.
 * 
 * @param {string} value The shorthand value string (e.g. "700 54px/1 'Inter', sans-serif")
 * @returns {string|null} Replacement longhand CSS string, or null if cannot be parsed
 */
export function expandFontShorthand(value) {
  const trimmed = value.trim().replace(/;$/, "");
  if (!trimmed) return null;

  // Reject system font keywords
  const systemFonts = ["caption", "icon", "menu", "message-box", "small-caption", "status-bar"];
  if (systemFonts.includes(trimmed.toLowerCase())) {
    return null;
  }

  // Regex to split prefix (style, weight), size/line-height, and font-family
  // Example matches:
  // "400 34px/1.4 'JetBrains Mono', monospace"
  // "italic 700 16px/1.5 'Inter', sans-serif"
  // "24px/1.2 Arial, sans-serif"
  // "500 28px 'Inter', sans-serif"
  const fontRegex = /^(?:(?<style>italic|oblique|normal)\s+)?(?:(?<weight>bold|bolder|lighter|[1-9]00|normal)\s+)?(?<size>[0-9.]+(?:px|rem|em|%|pt|vw|vh))(?:\/(?<lh>[0-9.]+(?:px|rem|em|%)?))?\s+(?<family>.+)$/i;

  // Also check inverted style/weight order: "bold italic 24px/1.2 ..."
  const fontRegexInverted = /^(?:(?<weight>bold|bolder|lighter|[1-9]00|normal)\s+)?(?:(?<style>italic|oblique|normal)\s+)?(?<size>[0-9.]+(?:px|rem|em|%|pt|vw|vh))(?:\/(?<lh>[0-9.]+(?:px|rem|em|%)?))?\s+(?<family>.+)$/i;

  let match = trimmed.match(fontRegex) || trimmed.match(fontRegexInverted);
  if (!match || !match.groups) {
    return null;
  }

  const { style, weight, size, lh, family } = match.groups;
  const parts = [];

  // Font family is primary
  parts.push(`font-family: ${family.trim()};`);

  if (weight && weight.toLowerCase() !== "normal") {
    parts.push(`font-weight: ${weight};`);
  } else if (weight && weight.toLowerCase() === "normal") {
    parts.push(`font-weight: 400;`);
  }

  if (style && style.toLowerCase() !== "normal") {
    parts.push(`font-style: ${style};`);
  }

  parts.push(`font-size: ${size};`);

  if (lh) {
    parts.push(`line-height: ${lh};`);
  }

  return parts.join(" ");
}

/**
 * Sanitizes all font shorthand declarations in a given CSS or HTML string.
 * 
 * @param {string} content Source code containing CSS declarations
 * @returns {{ output: string, count: number, matches: Array<{ before: string, after: string }> }}
 */
export function sanitizeFontCss(content) {
  let count = 0;
  const matches = [];

  // Match `font:` declarations inside style rules, ignoring `font-*:`, `@font-face`, etc.
  // Negative lookahead (?![a-zA-Z-]) ensures we only match bare `font:`
  const fontDeclarationRegex = /(?<![a-zA-Z-])font\s*:\s*([^;{}]+);/g;

  const output = content.replace(fontDeclarationRegex, (fullMatch, value) => {
    // Check if it's already a compound property like font-family or font-size (caught by lookbehind)
    const expanded = expandFontShorthand(value);
    if (expanded) {
      count++;
      matches.push({ before: fullMatch, after: expanded });
      return expanded;
    }
    return fullMatch;
  });

  return { output, count, matches };
}

/**
 * Sanitizes a single file on disk.
 * 
 * @param {string} filePath Absolute or relative path to file
 * @param {object} options
 * @param {boolean} [options.dryRun=false]
 * @returns {{ path: string, modified: boolean, count: number, matches: Array }}
 */
export function sanitizeFile(filePath, { dryRun = false } = {}) {
  const content = readFileSync(filePath, "utf8");
  const { output, count, matches } = sanitizeFontCss(content);

  const modified = count > 0;
  if (modified && !dryRun) {
    writeFileSync(filePath, output, "utf8");
  }

  return { path: filePath, modified, count, matches };
}

/**
 * Recursively scans and sanitizes files in a directory.
 * 
 * @param {string} dirPath Directory path
 * @param {object} options
 * @param {Set<string>} [options.extensions=DEFAULT_EXTS]
 * @param {boolean} [options.dryRun=false]
 * @param {boolean} [options.check=false]
 * @param {boolean} [options.verbose=false]
 * @returns {{ totalFiles: number, totalRewrites: number, results: Array }}
 */
export function sanitizeDirectory(dirPath, options = {}) {
  const {
    extensions = DEFAULT_EXTS,
    dryRun = false,
    verbose = false
  } = options;

  const results = [];
  let totalFiles = 0;
  let totalRewrites = 0;

  function walk(currentDir) {
    const entries = readdirSync(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = join(currentDir, entry.name);
      if (entry.isDirectory()) {
        // Skip hidden folders and node_modules
        if (entry.name.startsWith(".") || entry.name === "node_modules") continue;
        walk(fullPath);
      } else if (entry.isFile()) {
        const ext = extname(entry.name).toLowerCase();
        if (extensions.has(ext)) {
          totalFiles++;
          const res = sanitizeFile(fullPath, { dryRun });
          if (res.modified) {
            totalRewrites += res.count;
            results.push(res);
            if (verbose) {
              console.log(`[REWRITE] ${relative(process.cwd(), fullPath)}: ${res.count} shorthand(s) expanded`);
            }
          }
        }
      }
    }
  }

  walk(resolve(dirPath));
  return { totalFiles, totalRewrites, results };
}

// CLI runner when invoked directly
if (import.meta.url === `file:///${process.argv[1].replace(/\\/g, "/")}`) {
  const args = process.argv.slice(2);
  let dryRun = false;
  let check = false;
  let verbose = false;
  let targetDir = null;
  const targetFiles = [];

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--dry-run") {
      dryRun = true;
    } else if (arg === "--check") {
      check = true;
      dryRun = true;
    } else if (arg === "--verbose" || arg === "-v") {
      verbose = true;
    } else if (arg === "--dir" || arg === "-d") {
      targetDir = args[++i];
    } else if (!arg.startsWith("-")) {
      targetFiles.push(arg);
    }
  }

  console.log("=== HyperFrames Font Longhand Sanitizer ===");
  if (dryRun) console.log("Mode: DRY RUN (no files modified)");
  if (check) console.log("Mode: CHECK (exit code 1 if unexpanded shorthands found)");

  let totalRewrites = 0;
  let filesModified = 0;

  if (targetFiles.length > 0) {
    for (const file of targetFiles) {
      const res = sanitizeFile(file, { dryRun });
      if (res.modified) {
        filesModified++;
        totalRewrites += res.count;
        console.log(`✓ ${file}: ${res.count} shorthand declarations expanded`);
      } else if (verbose) {
        console.log(`- ${file}: clean`);
      }
    }
  } else {
    const scanDir = targetDir || ".";
    const report = sanitizeDirectory(scanDir, { dryRun, verbose });
    totalRewrites = report.totalRewrites;
    filesModified = report.results.length;

    console.log(`Scanned ${report.totalFiles} files in ${scanDir}`);
    console.log(`Found ${totalRewrites} shorthand declarations across ${filesModified} file(s)`);
  }

  if (check && totalRewrites > 0) {
    console.error(`\n[FAIL] Found ${totalRewrites} unexpanded font shorthand(s). Run without --check to fix.`);
    process.exit(1);
  }

  console.log("\nComplete.");
}
