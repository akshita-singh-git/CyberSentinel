# CyberSentinel UI refresh

## Visual direction
- Deep midnight navy foundation with electric violet, vivid aqua, hot pink, and amber accents.
- Stronger contrast for navigation, status indicators, severity labels, and primary actions.
- More luminous gradients and subtle ambient background lighting.

## Motion and depth
- Auth card entrance animation and floating ambient background glows.
- Subtle hover lift and perspective treatment on dashboard cards.
- Floating brand mark and AI orb.
- Respects `prefers-reduced-motion` for accessibility.

## Bug fix
- API error responses whose `detail` is an object or validation-error array are now serialized safely instead of rendering as `[object Object]`.

Animations are CSS-based and do not add runtime dependencies.
