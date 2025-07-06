import React, { useState, useEffect, useRef } from 'react';
import { useDispatch } from 'react-redux';
import { startScan } from '../../store/slices/scanSlice';
import './Terminal.css';

const Terminal = ({ isOpen, onClose }) => {
  const [input, setInput] = useState('');
  const [history, setHistory] = useState([
    { type: 'system', content: 'TypoSentinel Security Scanner v1.0.0' },
    { type: 'system', content: 'Type "help" for available commands' },
    { type: 'prompt', content: 'typosentinel@scanner:~$ ' }
  ]);
  const [isProcessing, setIsProcessing] = useState(false);
  const [currentScanId, setCurrentScanId] = useState(null);
  const terminalRef = useRef(null);
  const inputRef = useRef(null);
  const dispatch = useDispatch();

  const commands = {
    help: {
      description: 'Show available commands',
      usage: 'help [command]',
      execute: (args) => {
        if (args.length === 0) {
          return [
            'Available commands:',
            '  scan <package>     - Scan a package for vulnerabilities',
            '  scan-demo          - Run a demonstration scan',
            '  status             - Show scanner status',
            '  clear              - Clear terminal',
            '  exit               - Close terminal',
            '  help [command]     - Show help for specific command'
          ];
        } else {
          const cmd = commands[args[0]];
          return cmd ? [`${args[0]}: ${cmd.description}`, `Usage: ${cmd.usage}`] : [`Unknown command: ${args[0]}`];
        }
      }
    },
    scan: {
      description: 'Scan a package for vulnerabilities',
      usage: 'scan <package-name>',
      execute: async (args) => {
        if (args.length === 0) {
          return ['Error: Package name required', 'Usage: scan <package-name>'];
        }
        const packageName = args[0];
        setIsProcessing(true);
        
        try {
          const scanConfig = {
            packageName,
            scanType: 'vulnerability',
            options: {
              deepScan: true,
              checkDependencies: true
            }
          };
          
          const result = await dispatch(startScan(scanConfig)).unwrap();
          setCurrentScanId(result.scanId);
          
          return [
            `Starting scan for package: ${packageName}`,
            `Scan ID: ${result.scanId}`,
            'Analyzing package dependencies...',
            'Checking for known vulnerabilities...',
            'Scan completed successfully!',
            `Results: ${result.threatsFound || 0} threats found`
          ];
        } catch (error) {
          return [`Error: ${error.message || 'Scan failed'}`];
        } finally {
          setIsProcessing(false);
        }
      }
    },
    'scan-demo': {
      description: 'Run a demonstration scan',
      usage: 'scan-demo',
      execute: async () => {
        setIsProcessing(true);
        const demoSteps = [
          'Initializing TypoSentinel scanner...',
          'Loading vulnerability database...',
          'Scanning package: express@4.18.0',
          'Analyzing dependencies (247 packages)...',
          'Checking for typosquatting attacks...',
          'Validating package integrity...',
          'Scanning for malicious code patterns...',
          'Cross-referencing with threat intelligence...',
          '',
          '🔍 SCAN RESULTS:',
          '  ✅ Package integrity: VERIFIED',
          '  ⚠️  Dependencies with vulnerabilities: 3',
          '  🚨 Critical threats: 1',
          '  📊 Risk score: 7.2/10',
          '',
          '📋 THREAT SUMMARY:',
          '  • CVE-2022-0778: High severity in openssl dependency',
          '  • Potential typosquatting: expresss (similar to express)',
          '  • Outdated dependency: lodash@4.17.20 (known vulnerabilities)',
          '',
          '✨ Scan completed in 2.3 seconds'
        ];
        
        return new Promise((resolve) => {
          let stepIndex = 0;
          const results = [];
          
          const showNextStep = () => {
            if (stepIndex < demoSteps.length) {
              results.push(demoSteps[stepIndex]);
              setHistory(prev => [
                ...prev,
                { type: 'output', content: demoSteps[stepIndex] }
              ]);
              stepIndex++;
              setTimeout(showNextStep, stepIndex < 10 ? 300 : 100);
            } else {
              setIsProcessing(false);
              resolve(results);
            }
          };
          
          setTimeout(showNextStep, 500);
        });
      }
    },
    status: {
      description: 'Show scanner status',
      usage: 'status',
      execute: () => {
        return [
          'Scanner Status: ONLINE',
          'Database Version: 2024.01.15',
          'Last Update: 2 hours ago',
          `Active Scans: ${currentScanId ? 1 : 0}`,
          'Memory Usage: 45.2 MB',
          'Uptime: 2d 14h 32m'
        ];
      }
    },
    clear: {
      description: 'Clear terminal',
      usage: 'clear',
      execute: () => {
        setHistory([
          { type: 'system', content: 'TypoSentinel Security Scanner v1.0.0' },
          { type: 'prompt', content: 'typosentinel@scanner:~$ ' }
        ]);
        return [];
      }
    },
    exit: {
      description: 'Close terminal',
      usage: 'exit',
      execute: () => {
        onClose();
        return ['Terminal session ended.'];
      }
    }
  };

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [history]);

  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus();
    }
  }, [isOpen]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!input.trim() || isProcessing) return;

    const command = input.trim();
    const [cmd, ...args] = command.split(' ');

    // Add command to history
    setHistory(prev => [
      ...prev,
      { type: 'command', content: `typosentinel@scanner:~$ ${command}` }
    ]);

    setInput('');

    if (commands[cmd]) {
      try {
        const result = await commands[cmd].execute(args);
        if (result && result.length > 0) {
          setHistory(prev => [
            ...prev,
            ...result.map(line => ({ type: 'output', content: line }))
          ]);
        }
      } catch (error) {
        setHistory(prev => [
          ...prev,
          { type: 'error', content: `Error: ${error.message}` }
        ]);
      }
    } else {
      setHistory(prev => [
        ...prev,
        { type: 'error', content: `Command not found: ${cmd}. Type 'help' for available commands.` }
      ]);
    }

    // Add new prompt
    if (cmd !== 'clear' && cmd !== 'exit') {
      setHistory(prev => [
        ...prev,
        { type: 'prompt', content: 'typosentinel@scanner:~$ ' }
      ]);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'l' && e.ctrlKey) {
      e.preventDefault();
      commands.clear.execute();
    }
  };

  if (!isOpen) return null;

  return (
    <div className="terminal-overlay">
      <div className="terminal-window">
        <div className="terminal-header">
          <div className="terminal-controls">
            <div className="terminal-button close" onClick={onClose}></div>
            <div className="terminal-button minimize"></div>
            <div className="terminal-button maximize"></div>
          </div>
          <div className="terminal-title">TypoSentinel Scanner Terminal</div>
        </div>
        
        <div className="terminal-body" ref={terminalRef}>
          {history.map((line, index) => (
            <div key={index} className={`terminal-line ${line.type}`}>
              {line.content}
            </div>
          ))}
          
          {!isProcessing && (
            <form onSubmit={handleSubmit} className="terminal-input-form">
              <span className="terminal-prompt">typosentinel@scanner:~$ </span>
              <input
                ref={inputRef}
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                className="terminal-input"
                autoComplete="off"
                spellCheck="false"
              />
            </form>
          )}
          
          {isProcessing && (
            <div className="terminal-line processing">
              <span className="processing-indicator">⠋</span> Processing...
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Terminal;