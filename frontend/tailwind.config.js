/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // issue-local-016: `gray` and `brand` resolve through CSS custom
        // properties (defined per-theme in src/index.css, switched by the
        // document's `data-theme` attribute) instead of literal hex, using
        // Tailwind's documented `rgb(var(--x) / <alpha-value>)` pattern —
        // required so existing opacity-modifier usages across the app
        // (`bg-gray-800/50`, `border-brand-700/30`, etc.) keep working.
        // Every existing `bg-gray-950`, `border-brand-700`, `.tab-active`,
        // `.toggle-on`, focus rings, etc. now re-skins per-theme with zero
        // changes to any component file.
        //
        // Severity badges / status colors (red, green, orange, yellow-as-
        // stock, blue) deliberately stay on Tailwind's built-in palettes,
        // untouched by this — only `gray` and `brand` are redirected, so
        // error=red / success=green meaning stays constant across themes.
        gray: {
          50:  'rgb(var(--color-gray-50) / <alpha-value>)',
          100: 'rgb(var(--color-gray-100) / <alpha-value>)',
          200: 'rgb(var(--color-gray-200) / <alpha-value>)',
          300: 'rgb(var(--color-gray-300) / <alpha-value>)',
          400: 'rgb(var(--color-gray-400) / <alpha-value>)',
          500: 'rgb(var(--color-gray-500) / <alpha-value>)',
          600: 'rgb(var(--color-gray-600) / <alpha-value>)',
          700: 'rgb(var(--color-gray-700) / <alpha-value>)',
          800: 'rgb(var(--color-gray-800) / <alpha-value>)',
          900: 'rgb(var(--color-gray-900) / <alpha-value>)',
          950: 'rgb(var(--color-gray-950) / <alpha-value>)',
        },
        brand: {
          50:  'rgb(var(--color-brand-50) / <alpha-value>)',
          100: 'rgb(var(--color-brand-100) / <alpha-value>)',
          200: 'rgb(var(--color-brand-200) / <alpha-value>)',
          300: 'rgb(var(--color-brand-300) / <alpha-value>)',
          400: 'rgb(var(--color-brand-400) / <alpha-value>)',
          500: 'rgb(var(--color-brand-500) / <alpha-value>)',
          600: 'rgb(var(--color-brand-600) / <alpha-value>)',
          700: 'rgb(var(--color-brand-700) / <alpha-value>)',
          800: 'rgb(var(--color-brand-800) / <alpha-value>)',
          900: 'rgb(var(--color-brand-900) / <alpha-value>)',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
    },
  },
  plugins: [],
}
