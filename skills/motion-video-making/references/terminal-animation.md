# Data-Driven Terminal Animation Reference

Guide to building authentic terminal animations from real CLI output.

---

## 1. Capture Pipeline

Never fake or manually type terminal output in HTML. Real terminal stdout includes natural formatting irregularities, headers, and column alignments that create credibility.

### Workflow:
1. Run target CLI binary via Python `subprocess.run()`.
2. Capture both stdout and stderr with explicit UTF-8 encoding.
3. Assert `returncode == 0` to verify successful execution.
4. Save raw output blocks to `assets/real_output.txt`.

Example capture script: `scripts/capture_real_stdout.py`.

---

## 2. DOM Generation Architecture

The raw text file is split into logical command blocks:
- Prompt command line (starts with `$ `)
- Immediate output lines
- Highlighted summary numbers
- Sequential execution traces

### Character Spanning
For realistic character-by-character typing:
```javascript
const chars = (str, cls = "c") =>
  [...str].map((ch) => `<span class="${cls}">${escapeHtml(ch)}</span>`).join("");
```
Markup generated:
```html
<div class="ln" id="cmd1">
  <span class="c p">$ </span>
  <span class="c">s</span><span class="c">u</span><span class="c">p</span><span class="c">e</span><span class="c">r</span>...
</div>
```

### GSAP Typing Animation
Animate character opacity using zero duration and a tight stagger:
```javascript
tl.fromTo(
  "#cmd1 .c",
  { opacity: 0 },
  { opacity: 1, duration: 0.001, stagger: 0.018, ease: "none" }
);
```
- `stagger: 0.018` yields ~55 characters per second (rapid, realistic developer typing).
- Instant stdout lines appear all at once (`ease: "none", duration: 0.1`).
- Trace lines appear with staggered line entrance (`stagger: 0.17`).

---

## 3. Marker Swipe Highlights

To highlight key quantitative wins (e.g. `755 RTTI classes`, `0 JVM`):
1. Wrap the target text in `<span class="hl" id="hl-win">755</span>`.
2. Apply CSS background gradient:
   ```css
   .hl {
     background: linear-gradient(#B8F433, #B8F433) no-repeat left center;
     background-size: 0% 100%;
     transition: none;
   }
   ```
3. Animate `backgroundSize` with GSAP:
   ```javascript
   tl.to("#hl-win", {
     backgroundSize: "100% 100%",
     color: "#0A0A0A",
     duration: 0.4,
     ease: "power2.inOut"
   });
   ```
This produces an authentic fluorescent highlighter pen effect directly on the terminal output.

---

## 4. Line Wrapping Hygiene

- **Rule:** Never apply `white-space: pre-wrap;` to the `#terminal-body` container. If applied to the container, empty newline characters generate unwanted blank vertical space.
- **Remediation:** Apply `white-space: pre-wrap;` strictly to `.ln` line elements:
  ```css
  #terminal-body .ln {
    min-height: 1.4em;
    white-space: pre-wrap;
    word-break: break-all;
  }
  ```
