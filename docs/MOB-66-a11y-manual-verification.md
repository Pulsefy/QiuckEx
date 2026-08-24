# MOB-66 — Mobile Accessibility Manual Verification Script

Issue: [Pulsefy/QiuckEx#856](https://github.com/Pulsefy/QiuckEx/issues/856)
Branch: `feat/MOB-66-a11y-screen-reader-focus-order`
Coverage: Payment screen, Scan-to-pay, Receipt, Settings (both legacy and route), Quick Receive, Payment Confirmation, Swap asset/rate selectors, Build Metadata, QR Preview Modal, Theme Selector.

---

## 0. Preconditions

- Physical iOS device (iPhone 12+) **or** simulator with VoiceOver enabled
- Physical Android device (API 33+) **or** emulator with TalkBack enabled
- Wallet in **connected** state (QuickEx Stellar wallet, demo-mode wallet, or testnet) — disconnect once to also validate the empty-state branch
- At least one historical transaction present (to exercise Receipt screen)
- Internet connection on (then toggle off briefly to verify payment-confirmation offline-disabled state)
- iOS minimum target ≥ 44pt / Android ≥ 48dp physical button dimension expectation

### How to enable screen readers

| Platform | Steps |
|---|---|
| **iOS — VoiceOver** | Settings → Accessibility → VoiceOver → **On**. Suggest adding the triple-click side-button shortcut. Three-finger tap = toggle speech rate rotor. Flick right = next focus stop. Double-tap = activate. Two-finger Z = Escape. |
| **Android — TalkBack** | Settings → Accessibility → TalkBack → **Use**. Suggest assigning volume-keys shortcut (hold both volume keys 3s). Swipe right = next focus stop. Double-tap = activate. Swipe down then left = Back. |

---

## 1. Payment Screen (`/link-generator` / `PaymentScreen.tsx`) — iOS VoiceOver

1. Launch QiuckEx. Navigate to the **Payment / Generate Link** screen.
2. Flick right repeatedly from the top. **Expected focus order (matches visual):**
   1. "Payment", heading
   2. "From asset: USDC…" row → value announcement matches visible balance + precision
   3. "To: @username or address" input → label + current value
   4. Asset selector: USDC card → role **radio**, (selected) if active. Next flick → XLM card, role **radio**, (unselected). Double-tap XLM → selection state toggles correctly and screen reader announces *selected*.
   5. Amount text input → announces label *"Amount (in XLM)"* followed by the typed number with decimal precision (e.g. `1.2500000 XLM` not just `1.25`).
   6. Memo input → announces label *"Memo (optional)"*
   7. X-Ray Privacy switch → role **switch**, announces *"X-Ray Privacy, enabled/disabled"*, double-tap to toggle → state announces change.
   8. Generate Link primary → role **button**, announces disabled state when amount empty, enabled state otherwise.
3. Touch-target check: Activate VoiceOver *"Item Chooser"* (two-finger scrub + triple tap) and note the asset selector cards, Generate button, and text inputs all accept the tap on first attempt anywhere on the visible element — no need to hunt for a tiny hot spot.
4. Enter amount `0.0000001 XLM` → confirm VO announces the full 7-decimal value. Type `1.00` USDC → confirm VO says "1 USDC" (not "1 point zero zero" trailing zeros).

## 2. Payment Screen — Android TalkBack

1. Identical steps to §1 on an Android device/emulator with TalkBack enabled.
2. **Android-specific note:** All touch targets expand to ≥48dp even when styled smaller — verify visually by drawing a 48dp square overlay next to each asset pill, amount input, Switch, and Generate button, and confirm the button extends at least that far.
3. Swipe-right focus order matches the iOS order exactly, including heading semantics at the top.
4. Focus *does not* land on the footer "Payments settle in ~5 seconds…" row — decorative element is excluded.

---

## 3. Scan to Pay (`/scan-to-pay`)

### 3a. Permission empty state (fresh install, camera not granted)
1. Open Scan to Pay from the tab.
2. With camera permission **denied**:
   - Focus order: heading ("Scan to pay") → status banner ("Camera permission required", role **alert**, live-region **assertive** so TB/VO re-announces it if a new alert replaces it) → *"Grant Access"* primary button → *"Go back"* secondary button.
   - Double-tap Grant Access → OS permission sheet appears (this is outside our a11y scope; grant it manually).

### 3b. Live camera view
1. Re-enter Scan to Pay after granting permission.
2. Swipe/flick right from the top. Expected focus stops:
   1. Title ("Scan a payment QR code") — heading
   2. Flash toggle — Pressable role **button**, announces state.checked ("Flash on/off") + hint ("Toggles rear camera LED").
   3. Close button — Pressable role **button**, label "Close scanner and go back".
3. **Focus-order check**: The corner brackets (top-left/top-right/bottom-left/bottom-right viewfinder), the dark overlay, and activity spinner do NOT receive independent focus stops. VoiceOver/TalkBack should stop only on semantically meaningful nodes. (If you hear a stop on just "Image" or empty, that's a regression.)
4. **Error banner test (Android)**: With TalkBack on, cover the lens or simulate network failure → when an error banner appears, TalkBack **interrupts** itself to announce the error live-region because of `role="alert"` + `accessibilityLiveRegion="assertive"`.

---

## 4. Receipt Screen (`/transaction/[id]` / `ReceiptScreen.tsx`)

1. Open any historical transaction → Receipt screen loads.
2. **Focus order (matches visual reading order):**
   1. Back button (role button, label "Go back to transactions list")
   2. Status badge + amount heading → wrapper announces together, e.g. *"Payment succeeded. You received 123.4567890 USDC from @alice. 2 minutes ago."* — no child stops for the green-check emoji, chip background, etc.
   3. Timeline: Each timeline node is a single combined stop (title + status + description + timestamp + tx hash). Visual connecting lines do NOT get focus.
   4. Cost comparison card — each row announces as one stop: *"You paid: 0.5000000 XLM"*, *"Fee: 0.00001 XLM"*, *"Rate: 1 XLM = 0.10 USDC"*.
   5. Expandable Metadata sections header — role button, state.expanded announced ("Expanded" / "Collapsed"). Double-tap to toggle → change announced.
   6. Each metadata row's 📋 copy icon — role **button** with a label including the **full** hash/value (e.g. *"Copy Contract ID. Value: 0aBc…9Zz. Double tap to copy."* — despite UI showing a truncated 8-char snippet.)
   7. Share button, Copy Support button, View on Explorer button — all labeled, role **button**.
3. **Precision / amount announcement check:**
   - Open a receipt with a 7-decimal XLM amount → verify VO/TB reads every decimal digit of the amount row.
   - Open a receipt with USDC (6 decimals) → verify VO reads the 6-decimal precision.
4. **Touch targets**: The copy/share icon-only buttons each measure at least 36×36 + hitSlop 4, so tapping the very edge still fires the action on first try.
5. **Metadata copy test**: Double-tap any metadata row copy icon → after success, screen reader announces a "Copied" follow-up via the label. Paste into notes → value matches the full, untruncated value from the accessibility label.

---

## 5. Settings Screen (BOTH: `/settings` route + legacy `SettingsScreen.tsx`)

### 5a. Route: `/settings` (`app/settings.tsx`)
1. Navigate to Settings.
2. Flick right from title ("Settings", heading).
3. **Security section** rows → role **link**, each row announces its label and a hint.
4. **Notifications card**:
   - Push Notifications row → Switch announces role **switch** + state (enabled/disabled).
   - Sound Effects row → Switch independent focus stop, state.checked announced.
   - App Badge row → Switch independent focus stop, state.checked announced.
5. **Background Sync card**:
   - Wi-Fi Only Switch → correct role + state.
   - Periodic Sync Switch → correct role + state.
   - Sync Frequency group: *Auto / 1 hour / 4 hours / 12 hours* each role **radio**, with `selected` state — one and only one announces selected at a time. Double-tapping another announces *"selected"*.
   - Last sync status card — one combined announcement, no children stops.
   - Sync Now button → disabled state announced if offline.
6. **Build Metadata panel** (child of settings) → see §7.
7. **Clear Data button** → role **button**, destructive action announced ("Deletes all local data…").
8. **Debug links** → role **link**, each with descriptive label.
9. Touch targets: Every Switch row is at least 48 tall (use a grid overlay). OptionCards for Sync Frequency ≥ 72 tall.

### 5b. Legacy screen: `src/screens/SettingsScreen.tsx`
1. Navigate to the legacy Settings entry point.
2. Theme selector: *Light / Dark / System* cards. Each is role **radio**, `selected` state announced independently. Visual swatches inside the card do NOT get a focus stop (decorative children hidden).
3. Toggle rows: *Push Notifications*, *X-Ray Mode* — wrapper View has a combined accessibilityLabel ("Push Notifications, enabled"), and the Switch itself is a role switch with state.checked.
4. Action rows: *Wallet address*, *Username*, *Network* — role **link** with a hint.
5. Disconnect Wallet → role **button**, destructive label.
6. Touch targets: Toggle rows ≥ 56 tall. Danger button ≥ 56 tall. Theme option cards ≥ 88 tall.
7. **Touch target visual check (cross-platform)**: Hold a ruler overlay next to each of the three Theme cards → confirm card height exceeds 44pt (iOS) / 48dp (Android). Repeat for the Disconnect button.

---

## 6. Payment Confirmation (`/payment-confirmation`)

1. Initiate any payment (via generated link or scan) to land on the confirmation page.
2. **Error / invalid-link state:**
   - Navigate with a malformed link → error screen. Focus: banner (role **alert**, live-region **assertive**) → "Go back" button.
   - No wallet connected → loading guard announces role **status**, "Waiting for wallet…", and only a Go back button focuses.
3. **Valid confirmation page:**
   - Heading: "Confirm payment" → heading semantics.
   - Rows: You pay / They receive / Fee / Rate. Each one focus stop with label + value + currency **including precision**, and a highlight clause ("Highlighted if amount").
   - Swap path asset selector → see §8.
   - Swap rate details → see §8.
   - Offline test: Put device into Airplane Mode → "Pay with Wallet" button announces **disabled** ("Pay… is disabled while offline. Connect to internet.").
   - Save Contact → label interpolates the username (`@alice`). Saving state → "Saving recipient @alice…".
   - "Pay X USDC to @alice" primary → full label announces amount, asset, privacy clause (if any), and recipient username.
4. Focus order: Heading → registry banner → 4 data rows → Pay primary → Cancel secondary → Save Contact tertiary. Matches visual top-down, left-right.

---

## 7. Shared panels: BuildMetadataPanel, QRPreviewModal, ThemeSelector

### 7a. Build Metadata Panel (Settings → Build info, or Receipt → expand metadata)
1. Every row has a single combined label: `"Build Number: 12345. Tap to copy."` → role **button**. After copying → label changes to include "Copied." Visual child Text elements are decorative (no double-announcement).
2. "Copy All Metadata" button → full descriptive label with role **button**, minHeight 52.

### 7b. QR Preview Modal (`QRPreviewModal.tsx`)
1. Trigger a QR preview (Quick Receive → Share → Preview, or link generator → Preview).
2. **iOS VoiceOver focus trap test:** With VO running, flick right repeatedly after the modal opens → focus **does not escape** behind the modal onto the background page. This is enforced by `accessibilityViewIsModal={true}`.
3. Focus order inside modal: Title ("QR Code", heading) → wrapper (label containing the **full encoded value**, e.g. `"QuickEx receive QR. Encoded: https://quickex.to/GADD...EA. Scan this to send payment."`) → Close button ("Close QR code preview. Dismiss modal and return to previous screen. Returns focus to the button that opened this.").
4. Dismiss the modal with Close → focus returns to the triggering button (system behavior on iOS; verify Android by triggering and dismissing → next swipe lands where expected, not at page top).
5. Touch target: Close button minHeight 56.

### 7c. Theme Selector (`ThemeSelector.tsx`)
1. Open Theme → Mode card group: Light / Dark / System.
   - Each: role **radio**, `accessibilityState.selected` matches the current mode.
   - Double-tap a different mode → "selected" announces.
   - Visual swatches, emoji labels inside each card are decorative (hidden).
2. Brand theme card group: Same pattern (role radio + selected state).

---

## 8. Swap components: SwapAssetSelector, SwapRateDetails

### 8a. SwapAssetSelector
1. Open a cross-asset payment confirmation → asset path screen shows.
2. **Loading state**: Heading ("Finding best route…", heading) + spinner (label "Loading swap options") + status text. No double-stops on the spinner image.
3. **Empty state**: Combined label + heading ("No swap routes found").
4. **Best-path options**: Each option card:
   - `role="radio"`, one and only one `selected`.
   - `accessibilityLabel = "Pay 1.2345678 XLM to receive 0.123456 USDC. Via 2 hops. Rate: 1 XLM = 0.1 USDC. Selected / Unselected."`
   - Hint: "Double tap to select this route."
   - Visual badges, arrows, gradient backgrounds inside the card are hidden from a11y (decorative).
5. Touch target: optionCard minHeight 104 → easily meets 48dp.

### 8b. SwapRateDetails
1. After route selection, Rate Details section shows.
2. Expiry countdown container — one combined label including min/sec. If <10s left, warning clause in label.
3. Refresh button — full descriptive label + role button, minHeight 36.
4. Four data rows (you pay / they receive / fee / rate) → combined label per row, values include full precision.
5. Slippage adjust: Expand/collapse header role button + state.expanded.
   - Presets (0.1% / 0.5% / 1%): role **radio**, selected state per preset. Height 44 (bumped from 36).
   - Custom input: `accessibilityValue={{percent: true}}` + label.
6. Summary bar: one combined label ("This swap expires in 29 seconds. 1.23 XLM → 0.12 USDC").
7. Warning container: `role="alert"` so it interrupts.
8. Route path visualization: wrapper label "Asset A → Asset B → Asset C. 2 hops via Stellar DEX order book." Visual SVG nodes decorative.

---

## 9. Quick Receive (`/quick-receive`)

1. **Empty state (wallet disconnected):**
   - Combined label on wrapper View ("No wallet connected. Connect your Stellar wallet to display your QR code and start receiving payments.").
   - Connect Wallet button: role **button** + label + hint. minHeight 48.
2. **Connected state:**
   - Badge container: one combined label ("Wallet connected. FREighter on PUBLIC network.").
   - Username/address: TouchableOpacity role **button**, label = "Public key GADD…ZZEA. Tap to copy full Stellar address to clipboard.", hint = "Copies full public key: GADD…64char…ZZEA".
   - QR wrapper: combined label containing **full** receive link value.
   - Copy Link primary: label includes full link + role button.
   - Copy Address secondary: label includes full 56-char public key + role button.
   - Share secondary: descriptive label referencing system share sheet + role button.
3. **Touch targets**: All three buttons minHeight 48, justifyContent: center. Username button has 8/16 hitSlop.

---

## 10. Cross-cutting: Focus order general procedure (applies to ALL screens)

**For every screen in §1–§9, repeat this generic focus-order check:**

1. Enable screen reader.
2. Starting from screen title, flick right through every focus stop end-to-end.
3. Write down the order of labels you hear.
4. Visually compare this order against the rendered screen reading top-to-bottom, left-to-right.
5. **Pass condition**: The audible order matches the visual reading order. If a focus stop "jumps backwards" or visits a right-side element before a left-side same-row element, that's a **fail**.
6. Second pass: Flick left from the last element → the order inverts correctly.

---

## 11. Cross-cutting: Modal focus-trap & focus-restore procedure (ALL modals)

1. With VO/TB on, navigate to the **trigger button** that opens the modal (e.g. "Preview QR" in link-generator, or any custom modal).
2. Note which button currently holds focus.
3. Activate the trigger button to open the modal.
4. Flick right repeatedly: **PASS** if focus is **inside** the modal, and the next stops never hit background content (no escape behind modal).
5. Dismiss via Close/Done or two-finger Z/back gesture.
6. **PASS restore** if focus returns to the *original trigger button* (or a sensible nearby element) — NOT the top of the page, NOT the element behind/above.
7. **iOS-specific check**: Open Xcode → Accessibility Inspector → select app → select "Modal panel" element → confirm the `<Modal>` component has `accessibilityViewIsModal = true` in the Attributes.

---

## 12. Cross-cutting: Minimum touch-target size procedure (ALL screens & ALL interactive elements)

Repeat on **both** a physical iPhone and Android device:

1. Enable the **on-screen grid/developer ruler** overlay (iOS: Settings → Accessibility → Zoom → Show Controller → Zoom Region Full Screen → use lens as a ruler; Android: Developer options → Show surface updates or Layout bounds + Display cutout simulation 48dp square).
2. For every interactive element you tested in §1–§9 (buttons, asset radio cards, Switch rows, input fields, icon-only copy/share buttons, frequency option cards):
   - Place a 48×48 dp (Android) / 44×44 pt (iOS) square overlay **centered** on the element's visual hit area.
   - **PASS condition (hard):** The element's visible tappable region fully contains the square, OR the element declares `hitSlop` sufficient to bring its effective touch rect to those dimensions.
   - Practical test: Tap the very edge/corner of the visual button on first try → action fires immediately (no need to aim for center).
3. Known exemptions (**fail** if touched on edge): none — *all* interactive elements in this issue scope have been bumped.

---

## 13. Platform-specific notes (1 each)

### iOS (VoiceOver)
> **Rotors check.** With VO active, twist two fingers on screen like turning a dial → select *"Headings"* rotor. Flick down → VoiceOver jumps directly from heading to heading across all screens. **PASS** if every screen in §1–§9 has exactly **one** H1 heading (title) and optional H2/H3 for section titles (Metadata, Notifications card, Build info — each one heading). The container "Quick Receive Connected" is not a heading. If you hear more than 1 heading of the same level per screen grouping, that's a regression.

### Android (TalkBack)
> **Headings shortcut + Traversal order view.** Enable TalkBack → open the Global Context Menu (swipe down then right) → *Headings and landmarks* → TalkBack offers a skip-to-heading list (same verification as iOS rotor above). Additionally, open *Developer options → Show layout bounds* (flashes rects) while scrolling. **PASS** if the accessibility focus highlight (green border) always aligns with the layout-bounds rect of the same element. Misalignment = focus-order / tree-order bug (or missing `importantForAccessibility=no` on a decorative overlay).

---

## 14. Acceptance Criteria Quick Checklist

Copy-paste this into your PR body and ✅ each line after running the script:

```
## Manual verification (per MOB-66 doc)
- [ ] AC 1 Labels/roles — Payment screen (§1) ✔️ iOS  ☐ Android
- [ ] AC 1 Labels/roles — Scan to pay (§3) ☐ iOS  ☐ Android
- [ ] AC 1 Labels/roles — Receipt (§4) ☐ iOS  ☐ Android
- [ ] AC 1 Labels/roles — Settings BOTH (§5) ☐ iOS  ☐ Android
- [ ] AC 1 Labels/roles — Payment confirmation (§6) ☐ iOS  ☐ Android
- [ ] AC 1 Labels/roles — Shared panels (§7: BuildMetadata, QRModal, Theme) ☐ iOS  ☐ Android
- [ ] AC 1 Labels/roles — Swap components (§8) ☐ iOS  ☐ Android
- [ ] AC 1 Labels/roles — Quick Receive (§9) ☐ iOS  ☐ Android
- [ ] AC 2 Focus order (§10) — all screens ☐ iOS  ☐ Android
- [ ] AC 2 Modal focus trap + restore (§11) — QRPreviewModal ☐ iOS  ☐ Android
- [ ] AC 3 Precision / unambiguous amount — XLM (7 dec) + USDC (6 dec) ☐ iOS  ☐ Android
- [ ] AC 4 Min touch targets ≥48dp / ≥44pt (§12) — all interactive elements ☐ iOS  ☐ Android
- [ ] AC 5 Documented script — this file reviewed (§0–§13 complete) ☐ iOS  ☐ Android
```
