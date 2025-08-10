import { useState } from 'react'

export function Test() {
  const [count, setCount] = useState(0)
  const [message, setMessage] = useState('')

  const handleClick = () => {
    setCount(count + 1)
    setMessage(`Button clicked ${count + 1} times!`)
    console.log('Button clicked!', count + 1)
    alert(`Button works! Clicked ${count + 1} times`)
  }

  const handleAlert = () => {
    alert('Alert button works!')
  }

  const handleConsole = () => {
    console.log('Console button works!')
    setMessage('Check console - message logged!')
  }

  return (
    <div className="p-8 max-w-4xl mx-auto">
      <h1 className="text-3xl font-bold mb-8">Button Test Page</h1>
      
      <div className="space-y-6">
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h2 className="text-xl font-semibold mb-4">Basic Button Test</h2>
          <button 
            onClick={handleClick}
            className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg mr-4"
          >
            Click Me (Count: {count})
          </button>
          {message && (
            <p className="mt-4 text-green-600 font-medium">{message}</p>
          )}
        </div>

        <div className="bg-white p-6 rounded-lg shadow-md">
          <h2 className="text-xl font-semibold mb-4">Alert Test</h2>
          <button 
            onClick={handleAlert}
            className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg"
          >
            Show Alert
          </button>
        </div>

        <div className="bg-white p-6 rounded-lg shadow-md">
          <h2 className="text-xl font-semibold mb-4">Console Test</h2>
          <button 
            onClick={handleConsole}
            className="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg"
          >
            Log to Console
          </button>
        </div>

        <div className="bg-white p-6 rounded-lg shadow-md">
          <h2 className="text-xl font-semibold mb-4">Inline Function Test</h2>
          <button 
            onClick={() => {
              alert('Inline function works!')
              console.log('Inline function executed')
            }}
            className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg"
          >
            Inline Function
          </button>
        </div>

        <div className="bg-white p-6 rounded-lg shadow-md">
          <h2 className="text-xl font-semibold mb-4">Event Object Test</h2>
          <button 
            onClick={(e) => {
              console.log('Event object:', e)
              alert(`Event type: ${e.type}, Target: ${(e.target as HTMLElement)?.tagName || 'Unknown'}`)
            }}
            className="bg-orange-600 hover:bg-orange-700 text-white px-4 py-2 rounded-lg"
          >
            Event Object Test
          </button>
        </div>
      </div>

      <div className="mt-8 bg-gray-100 p-4 rounded-lg">
        <h3 className="font-semibold mb-2">Instructions:</h3>
        <ul className="list-disc list-inside space-y-1 text-sm">
          <li>Click each button to test functionality</li>
          <li>Check browser console (F12) for console messages</li>
          <li>Look for alert dialogs</li>
          <li>Verify counter updates</li>
          <li>If any button doesn't work, there's a JavaScript issue</li>
        </ul>
      </div>
    </div>
  )
}