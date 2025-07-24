#!/bin/bash

# TypoSentinel Dynamic Analyzer - Performance Monitor
# This script monitors system resources during stress testing

echo "🔍 TypoSentinel Performance Monitor"
echo "=================================="
echo ""

# Function to get current timestamp
timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

# Function to monitor Docker containers
monitor_docker() {
    echo "📊 Docker Container Monitoring:"
    echo "$(timestamp) - Active containers:"
    docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "(typosentinel|sandbox)" || echo "No TypoSentinel containers running"
    echo ""
    
    echo "$(timestamp) - Docker system usage:"
    docker system df
    echo ""
}

# Function to monitor system resources
monitor_system() {
    echo "💻 System Resource Monitoring:"
    echo "$(timestamp) - CPU and Memory usage:"
    
    # macOS specific commands
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "CPU Usage:"
        top -l 1 -n 0 | grep "CPU usage" || echo "CPU info not available"
        
        echo "Memory Usage:"
        vm_stat | head -10
        
        echo "Disk Usage:"
        df -h / | tail -1
    else
        # Linux commands
        echo "CPU Usage:"
        top -bn1 | grep "Cpu(s)" || echo "CPU info not available"
        
        echo "Memory Usage:"
        free -h
        
        echo "Disk Usage:"
        df -h / | tail -1
    fi
    echo ""
}

# Function to monitor network
monitor_network() {
    echo "🌐 Network Monitoring:"
    echo "$(timestamp) - Network connections:"
    netstat -an | grep -E "(LISTEN|ESTABLISHED)" | grep -E "(8080|3000|4000)" | head -5 || echo "No relevant network connections"
    echo ""
}

# Function to monitor processes
monitor_processes() {
    echo "⚙️  Process Monitoring:"
    echo "$(timestamp) - TypoSentinel related processes:"
    ps aux | grep -E "(typosentinel|stress-test|docker)" | grep -v grep | head -10 || echo "No TypoSentinel processes found"
    echo ""
}

# Function to run continuous monitoring
continuous_monitor() {
    local duration=${1:-60}  # Default 60 seconds
    local interval=${2:-5}   # Default 5 seconds
    
    echo "🔄 Starting continuous monitoring for ${duration} seconds (interval: ${interval}s)"
    echo "=================================================================="
    
    local end_time=$(($(date +%s) + duration))
    
    while [ $(date +%s) -lt $end_time ]; do
        echo ""
        echo "📈 Monitoring Report - $(timestamp)"
        echo "----------------------------------------"
        
        monitor_system
        monitor_docker
        monitor_network
        monitor_processes
        
        echo "⏱️  Sleeping for ${interval} seconds..."
        echo "========================================"
        sleep $interval
    done
    
    echo ""
    echo "✅ Monitoring completed!"
}

# Function to generate performance report
generate_report() {
    local output_file="performance_report_$(date +%Y%m%d_%H%M%S).txt"
    
    echo "📋 Generating Performance Report: $output_file"
    echo "=============================================="
    
    {
        echo "TypoSentinel Dynamic Analyzer - Performance Report"
        echo "Generated: $(timestamp)"
        echo "=================================================="
        echo ""
        
        monitor_system
        monitor_docker
        monitor_network
        monitor_processes
        
        echo "Docker Images:"
        docker images | grep -E "(node|alpine)" | head -5
        echo ""
        
        echo "Docker Volumes:"
        docker volume ls | head -10
        echo ""
        
        echo "System Information:"
        if [[ "$OSTYPE" == "darwin"* ]]; then
            system_profiler SPSoftwareDataType | grep -E "(System Version|Kernel Version)"
            system_profiler SPHardwareDataType | grep -E "(Model Name|Total Number of Cores|Memory)"
        else
            uname -a
            lscpu | head -10
        fi
        
    } > "$output_file"
    
    echo "✅ Report saved to: $output_file"
}

# Function to cleanup test artifacts
cleanup_test_artifacts() {
    echo "🧹 Cleaning up test artifacts..."
    
    # Remove test containers
    echo "Removing test containers..."
    docker ps -a | grep -E "(stress-test|sandbox)" | awk '{print $1}' | xargs -r docker rm -f 2>/dev/null || true
    
    # Remove test directories
    echo "Removing test directories..."
    rm -rf stress-test-results 2>/dev/null || true
    
    # Clean up Docker system
    echo "Cleaning Docker system..."
    docker system prune -f 2>/dev/null || true
    
    echo "✅ Cleanup completed!"
}

# Function to run pre-test checks
pre_test_checks() {
    echo "🔍 Running pre-test checks..."
    echo "============================="
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        echo "❌ Docker is not installed or not in PATH"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        echo "❌ Docker daemon is not running"
        exit 1
    fi
    
    echo "✅ Docker is available and running"
    
    # Check available disk space
    available_space=$(df / | tail -1 | awk '{print $4}')
    if [ "$available_space" -lt 1048576 ]; then  # Less than 1GB
        echo "⚠️  Warning: Low disk space (less than 1GB available)"
    else
        echo "✅ Sufficient disk space available"
    fi
    
    # Check available memory
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS memory check
        available_mem=$(vm_stat | grep "Pages free" | awk '{print $3}' | sed 's/\.//')
        if [ "$available_mem" -lt 100000 ]; then  # Rough estimate
            echo "⚠️  Warning: Low available memory"
        else
            echo "✅ Sufficient memory available"
        fi
    fi
    
    # Check for existing test artifacts
    if [ -d "stress-test-results" ]; then
        echo "⚠️  Warning: Previous test results found, will be cleaned up"
    fi
    
    echo ""
}

# Function to run post-test analysis
post_test_analysis() {
    echo "📊 Running post-test analysis..."
    echo "================================"
    
    # Check for any remaining containers
    remaining_containers=$(docker ps -a | grep -E "(stress-test|sandbox)" | wc -l)
    if [ "$remaining_containers" -gt 0 ]; then
        echo "⚠️  Warning: $remaining_containers test containers still exist"
        docker ps -a | grep -E "(stress-test|sandbox)"
    else
        echo "✅ No test containers remaining"
    fi
    
    # Check Docker system usage
    echo ""
    echo "Docker system usage after tests:"
    docker system df
    
    # Check for test result files
    if [ -d "stress-test-results" ]; then
        echo ""
        echo "Test result files:"
        find stress-test-results -type f -name "*.json" -o -name "*.log" | head -10
    fi
    
    echo ""
}

# Main script logic
case "${1:-help}" in
    "monitor")
        duration=${2:-60}
        interval=${3:-5}
        continuous_monitor $duration $interval
        ;;
    "report")
        generate_report
        ;;
    "cleanup")
        cleanup_test_artifacts
        ;;
    "pre-check")
        pre_test_checks
        ;;
    "post-analysis")
        post_test_analysis
        ;;
    "full-monitor")
        echo "🚀 Running full monitoring session..."
        pre_test_checks
        echo ""
        echo "Starting stress test monitoring..."
        continuous_monitor 120 10  # 2 minutes, 10-second intervals
        echo ""
        post_test_analysis
        echo ""
        generate_report
        ;;
    "help"|*)
        echo "Usage: $0 {monitor|report|cleanup|pre-check|post-analysis|full-monitor|help}"
        echo ""
        echo "Commands:"
        echo "  monitor [duration] [interval]  - Monitor system for specified duration (default: 60s, 5s interval)"
        echo "  report                        - Generate performance report"
        echo "  cleanup                       - Clean up test artifacts"
        echo "  pre-check                     - Run pre-test system checks"
        echo "  post-analysis                 - Run post-test analysis"
        echo "  full-monitor                  - Run complete monitoring session"
        echo "  help                          - Show this help message"
        echo ""
        echo "Examples:"
        echo "  $0 monitor 120 10            - Monitor for 2 minutes with 10-second intervals"
        echo "  $0 full-monitor               - Run complete monitoring session"
        ;;
esac