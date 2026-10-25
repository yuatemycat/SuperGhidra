# Vertical Video Safe-Zone Reference (1080 × 1920)

Specifications for TikTok, Instagram Reels, and YouTube Shorts.

## 1. Dimensional Canvas

| Property | Value | Notes |
| :--- | :--- | :--- |
| **Resolution** | 1080 × 1920 px | 9:16 Aspect Ratio |
| **Framerate** | 30.0 fps | Standard social video framerate |
| **Duration** | 15.0 – 60.0 s | Keep punchy launch films under 30.0 s |
| **Safe Width** | 0 to 940 px | Avoid right 140 px on all vertical platforms |
| **Safe Height** | 168 to 1330 px | Avoid top 168 px and bottom 590 px |

---

## 2. Platform Overlay Mapping

### TikTok UI Elements
- **Top 168 px:** Search icon, Following/For You tabs, live indicators.
- **Right 140 px (`x: 940 - 1080`):**
  - Creator profile avatar + Follow pill (`y: ~680 - 800`)
  - Like button + count (`y: ~830 - 950`)
  - Comment button + count (`y: ~980 - 1100`)
  - Bookmark button + count (`y: ~1130 - 1230`)
  - Share button + count (`y: ~1260 - 1360`)
- **Bottom 590 px (`y: 1330 - 1920`):**
  - Account handle (`@username`)
  - Multi-line caption and hashtags
  - Audio track marquee ticker
  - Bottom app navigation bar (Home, Shop, Inbox, Profile)

### Instagram Reels UI Elements
- **Top 160 px:** Camera icon, "Reels" header, audio indicator.
- **Right 140 px (`x: 940 - 1080`):** Like, comment, DM/share, three-dot menu, original audio thumbnail.
- **Bottom 480 px (`y: 1440 - 1920`):** Handle, follow button, caption truncation, audio title, search bar.

### YouTube Shorts UI Elements
- **Top 160 px:** Search, camera, three-dot overflow.
- **Right 140 px (`x: 940 - 1080`):** Like, dislike, comments, share, remix.
- **Bottom 420 px (`y: 1500 - 1920`):** Channel avatar, subscribe button, title, audio square.

---

## 3. Strict Typography Rules for Vertical Canvas

1. **Floor Size:** 28 px absolute minimum (e.g. window dot titles or tertiary footnotes).
2. **Body / Terminal Text:** 34 px to 44 px.
3. **Labels & Chips:** 48 px to 64 px (Inter Bold / 800).
4. **Hero Headlines:** 130 px to 220 px (Archivo Black 400).
5. **Giant Hook Numbers:** 350 px to 420 px.
6. **Line Length:** Maximum 5 English words or 8 Asian characters per line for primary claims. Break into multi-line beats instead of shrinking font size.
