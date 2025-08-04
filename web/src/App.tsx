import React from 'react'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { Toaster } from 'react-hot-toast'

// Components
import Navbar from './components/Navbar'
import Footer from './components/Footer'
import MatrixRain from './components/MatrixRain'
import ScrollToTop from './components/ScrollToTop'

// Pages
import Home from './pages/Home'
import Demo from './pages/Demo'
import APIPlayground from './pages/APIPlayground'
import CLI from './pages/CLI'

import Pricing from './pages/Pricing'
import Documentation from './pages/Documentation'

// Hooks
import { useKonamiCode } from './hooks/useKonamiCode'

function App() {
  const [matrixMode, setMatrixMode] = useKonamiCode()

  return (
    <Router>
      <div className="min-h-screen bg-deep-black text-ghost-white relative overflow-x-hidden">
        {/* Matrix Rain Effect (Easter Egg) */}
        <AnimatePresence>
          {matrixMode && <MatrixRain />}
        </AnimatePresence>

        {/* Background Grid */}
        <div className="fixed inset-0 cyber-grid opacity-20 pointer-events-none" />
        
        {/* Gradient Mesh Background */}
        <div className="fixed inset-0 gradient-mesh opacity-30 pointer-events-none" />

        {/* Main Content */}
        <div className="relative z-10">
          <Navbar />
          
          <main className="min-h-screen">
            <AnimatePresence mode="wait">
              <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/demo" element={<Demo />} />
                <Route path="/api" element={<APIPlayground />} />
                <Route path="/cli" element={<CLI />} />

                <Route path="/pricing" element={<Pricing />} />
                <Route path="/docs" element={<Documentation />} />
              </Routes>
            </AnimatePresence>
          </main>
          
          <Footer />
        </div>

        {/* Scroll to Top */}
        <ScrollToTop />
        
        {/* Toast Notifications */}
        <Toaster
          position="top-right"
          toastOptions={{
            duration: 4000,
            style: {
              background: '#0F172A',
              color: '#F8FAFC',
              border: '1px solid #0EA5E9',
              borderRadius: '8px',
            },
            success: {
              iconTheme: {
                primary: '#10B981',
                secondary: '#F8FAFC',
              },
            },
            error: {
              iconTheme: {
                primary: '#EF4444',
                secondary: '#F8FAFC',
              },
            },
          }}
        />
      </div>
    </Router>
  )
}

export default App