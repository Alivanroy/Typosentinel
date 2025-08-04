#!/usr/bin/env python3
"""
Enterprise Testing Demonstration Script
Shows how to run various enterprise-level security tests
"""

import os
import sys
import time
import subprocess
import json
from datetime import datetime

def print_banner():
    """Print demonstration banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                 TypoSentinel Enterprise Testing              ║
    ║              Real-World Attack Simulation Demo               ║
    ╚══════════════════════════════════════════════════════════════╝
    
    This demonstration showcases TypoSentinel's ability to detect
    sophisticated attacks in enterprise environments:
    
    🎯 Typosquatting Attacks (Basic → Advanced → AI-Generated)
    🔗 Supply Chain Compromises (Dependency Confusion → Malicious Updates)
    🏛️ Nation-State Attacks (APT Campaigns → Zero-Day Exploits)
    🔬 Advanced Persistent Threats (Multi-Stage → AI-Powered)
    ⚛️ Quantum-Era Attacks (Cryptographic → Network)
    📊 Performance & Compliance Testing
    
    """
    print(banner)

def check_prerequisites():
    """Check if Docker and required tools are available"""
    print("🔍 Checking prerequisites...")
    
    # Check Docker
    try:
        result = subprocess.run(["docker", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ Docker: {result.stdout.strip()}")
        else:
            print("❌ Docker not found. Please install Docker first.")
            return False
    except FileNotFoundError:
        print("❌ Docker not found. Please install Docker first.")
        return False
    
    # Check Docker Compose
    try:
        result = subprocess.run(["docker-compose", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✅ Docker Compose: {result.stdout.strip()}")
        else:
            print("❌ Docker Compose not found. Please install Docker Compose first.")
            return False
    except FileNotFoundError:
        print("❌ Docker Compose not found. Please install Docker Compose first.")
        return False
    
    # Check available disk space (need at least 10GB)
    try:
        import shutil
        total, used, free = shutil.disk_usage("/")
        free_gb = free // (1024**3)
        if free_gb >= 10:
            print(f"✅ Disk Space: {free_gb}GB available")
        else:
            print(f"⚠️ Warning: Only {free_gb}GB available. Recommend at least 10GB.")
    except:
        print("⚠️ Could not check disk space")
    
    print("✅ Prerequisites check completed!\n")
    return True

def run_demo_scenario(scenario_name, description, intensity="low"):
    """Run a specific demo scenario"""
    print(f"\n🚀 Running: {scenario_name}")
    print(f"📝 Description: {description}")
    print(f"⚡ Intensity: {intensity}")
    print("─" * 60)
    
    start_time = time.time()
    
    try:
        # Run the enterprise test
        cmd = [
            "python3", "run_enterprise_tests.py",
            "--category", scenario_name.lower().replace(" ", "_"),
            "--intensity", intensity
        ]
        
        print(f"🔧 Executing: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        execution_time = time.time() - start_time
        
        if result.returncode == 0:
            print(f"✅ {scenario_name} completed successfully in {execution_time:.1f}s")
            
            # Try to parse and display key results
            try:
                if result.stdout:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'Detection Rate' in line or 'Success Rate' in line or 'Response Time' in line:
                            print(f"📊 {line.strip()}")
            except:
                pass
                
        else:
            print(f"❌ {scenario_name} failed: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print(f"⏰ {scenario_name} timed out after 5 minutes")
    except Exception as e:
        print(f"💥 Error running {scenario_name}: {e}")
    
    print("─" * 60)

def run_quick_demo():
    """Run a quick demonstration of key capabilities"""
    print("🎬 Starting Quick Demo (Low Intensity)")
    print("This demo runs lightweight tests to showcase core capabilities\n")
    
    scenarios = [
        ("typosquatting", "Basic typosquatting detection with character substitution"),
        ("supply_chain", "Dependency confusion and malicious update detection"),
        ("nation_state", "APT campaign and zero-day exploit simulation"),
    ]
    
    for scenario, description in scenarios:
        run_demo_scenario(scenario, description, "low")
        time.sleep(2)  # Brief pause between scenarios

def run_comprehensive_demo():
    """Run comprehensive enterprise testing"""
    print("🏢 Starting Comprehensive Enterprise Demo (Medium Intensity)")
    print("This demo runs realistic enterprise-level testing scenarios\n")
    
    scenarios = [
        ("typosquatting", "Advanced typosquatting with AI-generated variants"),
        ("supply_chain", "Sophisticated supply chain compromise scenarios"),
        ("nation_state", "Nation-state level APT campaigns"),
        ("advanced_persistent", "Multi-stage APT with AI-powered techniques"),
        ("quantum_era", "Next-generation quantum-era attack simulation"),
    ]
    
    for scenario, description in scenarios:
        run_demo_scenario(scenario, description, "medium")
        time.sleep(5)  # Pause between scenarios

def run_performance_demo():
    """Run performance and load testing demonstration"""
    print("⚡ Starting Performance Testing Demo")
    print("This demo tests TypoSentinel's performance under load\n")
    
    print("🔧 Running performance tests...")
    
    try:
        cmd = [
            "python3", "attack-simulator/performance_tester.py",
            "--intensity", "medium",
            "--test-type", "load",
            "--output", "demo_performance_results.json"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        if result.returncode == 0:
            print("✅ Performance testing completed successfully")
            
            # Display key metrics
            if result.stdout:
                lines = result.stdout.split('\n')
                for line in lines:
                    if any(keyword in line for keyword in ['Requests:', 'Rate:', 'Time:', 'Accuracy:']):
                        print(f"📊 {line.strip()}")
        else:
            print(f"❌ Performance testing failed: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print("⏰ Performance testing timed out")
    except Exception as e:
        print(f"💥 Error in performance testing: {e}")

def show_monitoring_info():
    """Show information about monitoring and observability"""
    print("\n📊 Monitoring & Observability")
    print("─" * 60)
    print("Once the enterprise environment is running, you can access:")
    print("")
    print("🎯 TypoSentinel Scanner:     http://localhost:8080")
    print("📈 Grafana Dashboards:      http://localhost:3000")
    print("🔍 Prometheus Metrics:      http://localhost:9090")
    print("📋 Kibana Logs:             http://localhost:5601")
    print("⚖️ HAProxy Stats:           http://localhost:8404/stats")
    print("🌐 Load Balancer:           http://localhost:80")
    print("")
    print("Default credentials:")
    print("  Grafana: admin / enterprise123")
    print("  HAProxy: admin / enterprise123")
    print("─" * 60)

def cleanup_demo():
    """Clean up demo environment"""
    print("\n🧹 Cleaning up demo environment...")
    
    try:
        cmd = ["python3", "run_enterprise_tests.py", "--cleanup-only"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Demo environment cleaned up successfully")
        else:
            print("⚠️ Cleanup may have encountered issues")
            
    except Exception as e:
        print(f"💥 Error during cleanup: {e}")

def main():
    """Main demonstration function"""
    print_banner()
    
    if not check_prerequisites():
        print("❌ Prerequisites not met. Please install required tools and try again.")
        sys.exit(1)
    
    print("Select demonstration type:")
    print("1. Quick Demo (5-10 minutes) - Basic attack scenarios")
    print("2. Comprehensive Demo (30-45 minutes) - Full enterprise testing")
    print("3. Performance Demo (10-15 minutes) - Load and stress testing")
    print("4. Show Monitoring Info - Access URLs and credentials")
    print("5. Cleanup Environment - Remove demo containers")
    print("6. Exit")
    
    while True:
        try:
            choice = input("\nEnter your choice (1-6): ").strip()
            
            if choice == "1":
                run_quick_demo()
                break
            elif choice == "2":
                run_comprehensive_demo()
                break
            elif choice == "3":
                run_performance_demo()
                break
            elif choice == "4":
                show_monitoring_info()
                break
            elif choice == "5":
                cleanup_demo()
                break
            elif choice == "6":
                print("👋 Goodbye!")
                break
            else:
                print("❌ Invalid choice. Please enter 1-6.")
                
        except KeyboardInterrupt:
            print("\n\n🛑 Demo interrupted by user")
            cleanup_demo()
            break
        except Exception as e:
            print(f"💥 Unexpected error: {e}")
            break
    
    print("\n🎉 Demo completed!")
    print("For more information, see: tests/enterprise/README.md")

if __name__ == "__main__":
    # Change to the enterprise tests directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    main()