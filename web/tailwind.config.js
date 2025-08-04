/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Cyber-Noir Color Palette from demospec
        'deep-black': '#0A0A0B',
        'rich-navy': '#0F172A',
        'electric-blue': '#0EA5E9',
        'cyber-purple': '#8B5CF6',
        'neon-cyan': '#06B6D4',
        'success-green': '#10B981',
        'warning-amber': '#F59E0B',
        'critical-red': '#EF4444',
        'info-blue': '#3B82F6',
        'ghost-white': '#F8FAFC',
        'silver': '#94A3B8',
        'charcoal': '#1E293B',
      },
      fontFamily: {
        'sans': ['Inter', 'system-ui', 'sans-serif'],
        'mono': ['JetBrains Mono', 'Fira Code', 'monospace'],
        'display': ['Space Grotesk', 'Inter', 'sans-serif'],
      },
      animation: {
        'pulse-glow': 'pulse-glow 2s ease-in-out infinite alternate',
        'float': 'float 6s ease-in-out infinite',
        'matrix-rain': 'matrix-rain 20s linear infinite',
        'scan-line': 'scan-line 2s linear infinite',
        'typewriter': 'typewriter 4s steps(40) 1s 1 normal both',
        'blink': 'blink 1s infinite',
      },
      keyframes: {
        'pulse-glow': {
          '0%': { 
            boxShadow: '0 0 5px #0EA5E9, 0 0 10px #0EA5E9, 0 0 15px #0EA5E9',
            transform: 'scale(1)'
          },
          '100%': { 
            boxShadow: '0 0 10px #0EA5E9, 0 0 20px #0EA5E9, 0 0 30px #0EA5E9',
            transform: 'scale(1.05)'
          }
        },
        'float': {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-20px)' }
        },
        'matrix-rain': {
          '0%': { transform: 'translateY(-100vh)' },
          '100%': { transform: 'translateY(100vh)' }
        },
        'scan-line': {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100vw)' }
        },
        'typewriter': {
          'from': { width: '0' },
          'to': { width: '100%' }
        },
        'blink': {
          'from, to': { borderColor: 'transparent' },
          '50%': { borderColor: '#0EA5E9' }
        }
      },
      backdropBlur: {
        'xs': '2px',
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'gradient-conic': 'conic-gradient(from 180deg at 50% 50%, var(--tw-gradient-stops))',
        'cyber-grid': 'linear-gradient(rgba(14, 165, 233, 0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(14, 165, 233, 0.1) 1px, transparent 1px)',
      },
      backgroundSize: {
        'grid': '50px 50px',
      }
    },
  },
  plugins: [],
}