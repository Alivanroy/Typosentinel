import './App.css'

function App() {
  return (
    <div className="App">
      <header className="App-header">
        <h1>Typosentinel Enterprise</h1>
        <p>Production Security Scanner</p>
        <div className="features">
          <div className="feature-card">
            <h3>Real-time Scanning</h3>
            <p>Advanced ML-powered typosquatting detection</p>
          </div>
          <div className="feature-card">
            <h3>Enterprise Security</h3>
            <p>Comprehensive threat intelligence and monitoring</p>
          </div>
          <div className="feature-card">
            <h3>API Integration</h3>
            <p>Seamless integration with your security infrastructure</p>
          </div>
        </div>
      </header>
    </div>
  )
}

export default App