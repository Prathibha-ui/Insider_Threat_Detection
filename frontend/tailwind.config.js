/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        background: '#090d16',
        surface: '#0f172a',
        'surface-hover': '#1e293b',
        border: '#1e293b',
        'border-light': '#334155',
        primary: {
          DEFAULT: '#3b82f6',
          dark: '#1d4ed8',
          light: '#60a5fa'
        },
        danger: {
          DEFAULT: '#ef4444',
          dark: '#991b1b',
          glow: 'rgba(239, 68, 68, 0.2)'
        },
        warning: {
          DEFAULT: '#f59e0b',
          dark: '#92400e'
        },
        success: {
          DEFAULT: '#10b981',
          dark: '#065f46'
        },
        muted: '#64748b'
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace']
      }
    },
  },
  plugins: [],
}