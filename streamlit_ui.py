"""
Streamlit UI for Wazuh LLM Security Assistant
"""
import streamlit as st
import requests
from datetime import datetime
import time
import base64
import os
import json
import plotly.express as px
import pandas as pd

# Logo helper function
def get_logo_path():
    """Get logo file path if it exists"""
    logo_paths = [
        "assets/images/resilmesh_logo.png",
        "assets/images/resilmesh-logo.svg",
        "assets/images/resilmesh-logo.ico"
    ]
    for path in logo_paths:
        if os.path.exists(path):
            return path
    return None

def get_base64_logo():
    """Convert logo to base64 for embedding in HTML"""
    logo_path = get_logo_path()
    if logo_path and logo_path.endswith('.png'):
        try:
            with open(logo_path, "rb") as f:
                return base64.b64encode(f.read()).decode()
        except Exception:
            pass
    return None

# Page configuration
logo_path = get_logo_path()
st.set_page_config(
    page_title="Resilmesh Wazuh Security Assistant",
    page_icon=logo_path if logo_path else "🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .status-indicator {
        display: inline-block;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        margin-right: 5px;
    }
    .status-online {
        background-color: #28a745;
    }
    .status-offline {
        background-color: #dc3545;
    }
    .query-examples {
        background-color: #f8f9fa;
        border-left: 4px solid #007bff;
        padding: 1rem;
        margin: 1rem 0;
    }
    .response-container {
        background-color: #ffffff;
        border: 1px solid #dee2e6;
        border-radius: 0.5rem;
        padding: 1rem;
        margin: 1rem 0;
    }
    .error-message {
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        border-radius: 0.5rem;
        padding: 1rem;
        color: #721c24;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'messages' not in st.session_state:
    st.session_state.messages = []
if 'session_id' not in st.session_state:
    st.session_state.session_id = f"session_{int(time.time())}"
if 'last_query' not in st.session_state:
    st.session_state.last_query = ""

# Configuration
API_BASE_URL = "http://localhost:8000"

def check_api_health():
    """Check if the API is running"""
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

def send_query(query: str, session_id: str):
    """Send query to the API"""
    try:
        response = requests.post(
            f"{API_BASE_URL}/query",
            json={"query": query, "session_id": session_id},
            timeout=60
        )
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"API Error: {response.status_code}", "details": response.text}
    except requests.exceptions.RequestException as e:
        return {"error": f"Connection Error: {str(e)}"}

def reset_session():
    """Reset the conversation session"""
    try:
        response = requests.post(f"{API_BASE_URL}/reset", timeout=10)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

def extract_stacked_data_from_response(response_text):
    """Extract structured stacked visualization data from LLM response"""
    try:
        # Look for JSON-like structures in the response
        lines = response_text.split('\n')
        json_start = -1
        json_end = -1
        
        for i, line in enumerate(lines):
            if '{' in line and ('stack_analysis' in line or 'stacked_data' in line or 'visualization_config' in line):
                json_start = i
                break
        
        if json_start == -1:
            return None
            
        # Find the end of the JSON block
        brace_count = 0
        for i in range(json_start, len(lines)):
            line = lines[i]
            brace_count += line.count('{') - line.count('}')
            if brace_count == 0 and '}' in line:
                json_end = i
                break
        
        if json_end == -1:
            return None
            
        # Extract and parse JSON
        json_text = '\n'.join(lines[json_start:json_end + 1])
        return json.loads(json_text)
        
    except Exception:
        return None

def render_stacked_chart(stacked_data_structure):
    """Render a stacked bar chart from the structured visualization data"""
    try:
        if not stacked_data_structure:
            return None
            
        # Extract data
        stack_analysis = stacked_data_structure.get('stack_analysis', {})
        stacked_data = stacked_data_structure.get('stacked_data', [])
        visualization_config = stacked_data_structure.get('visualization_config', {})
        stack_summary = stacked_data_structure.get('stack_summary', {})
        
        if not stacked_data:
            return None
            
        # Prepare data for plotting
        chart_data = []
        for bucket in stacked_data:
            timestamp = bucket.get('timestamp', '')
            time_bucket = bucket.get('time_bucket', 'Current Period')
            stack_breakdown = bucket.get('stack_breakdown', {})
            
            for category, count in stack_breakdown.items():
                chart_data.append({
                    'Time': time_bucket,
                    'Category': category,
                    'Count': count,
                    'Timestamp': timestamp
                })
        
        if not chart_data:
            return None
            
        df = pd.DataFrame(chart_data)
        
        # Get colors from config
        colors = visualization_config.get('color_palette', [])
        if not colors:
            colors = px.colors.qualitative.Set1
            
        # Create stacked bar chart
        fig = px.bar(
            df, 
            x='Time', 
            y='Count',
            color='Category',
            title=f"Stacked {stack_analysis.get('stack_dimension', 'Alert').title()} Analysis",
            color_discrete_sequence=colors,
            hover_data=['Timestamp']
        )
        
        # Update layout
        fig.update_layout(
            xaxis_title="Time Period",
            yaxis_title="Alert Count",
            legend_title=f"{stack_analysis.get('stack_dimension', 'Dimension').title()}",
            height=500,
            showlegend=True
        )
        
        return fig, stack_summary
        
    except Exception as e:
        st.error(f"Error rendering chart: {str(e)}")
        return None

def display_stack_summary(stack_summary):
    """Display summary statistics for the stacked chart"""
    if not stack_summary:
        return
        
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric(
            "Peak Activity", 
            stack_summary.get('peak_total', 0),
            help="Maximum alerts in a single time period"
        )
    
    with col2:
        st.metric(
            "Dominant Category", 
            stack_summary.get('dominant_category', 'Unknown'),
            help="Category with highest alert count"
        )
        
    with col3:
        temporal_dist = stack_summary.get('temporal_distribution', 'unknown')
        st.metric(
            "Distribution", 
            temporal_dist.title(),
            help="Pattern of alert distribution over time"
        )
    
    # Show category percentages
    category_percentages = stack_summary.get('category_percentages', {})
    if category_percentages:
        st.subheader("Category Breakdown")
        
        # Create a simple bar chart for percentages
        perc_df = pd.DataFrame([
            {'Category': cat, 'Percentage': perc} 
            for cat, perc in category_percentages.items()
        ])
        
        fig_perc = px.bar(
            perc_df, 
            x='Category', 
            y='Percentage',
            title="Alert Distribution by Category (%)",
            text='Percentage'
        )
        fig_perc.update_traces(texttemplate='%{text}%', textposition='outside')
        fig_perc.update_layout(height=300)
        st.plotly_chart(fig_perc, use_container_width=True)

# Main UI
# Add Resilmesh logo at the top center using get_logo_path function
main_logo_path = get_logo_path()
if main_logo_path:
    # Convert logo to base64 and display as HTML centered above heading
    try:
        with open(main_logo_path, "rb") as f:
            logo_data = base64.b64encode(f.read()).decode()
        st.markdown(f'<div style="text-align: center; margin-bottom: 1rem;"><img src="data:image/png;base64,{logo_data}" width="200" style="display: block; margin: 0 auto;"></div>', unsafe_allow_html=True)
    except Exception:
        st.markdown('<div style="text-align: center; margin-bottom: 1rem;"><strong>Resilmesh Logo</strong></div>', unsafe_allow_html=True)

# Main header - always use shield icon
st.markdown('<h1 class="main-header">🛡️ Resilmesh Wazuh Security Assistant</h1>', unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.header("Configuration")

    # API Status
    api_status = check_api_health()
    status_class = "status-online" if api_status else "status-offline"
    status_text = "Online" if api_status else "Offline"
    st.markdown(f'<div><span class="status-indicator {status_class}"></span>API Status: {status_text}</div>', unsafe_allow_html=True)

    st.markdown("---")

    # Session Management
    st.subheader("Session Management")
    st.text(f"Session ID: {st.session_state.session_id[-8:]}")

    if st.button("🔄 Reset Session"):
        if reset_session():
            st.session_state.messages = []
            st.session_state.session_id = f"session_{int(time.time())}"
            st.success("Session reset successfully!")
        else:
            st.error("Failed to reset session")

    st.markdown("---")

    # Quick Actions
    st.subheader("Quick Actions")

    example_queries = [
        "Show me the top 10 hosts with most alerts this week",
        "Create hourly stacked chart of top 5 hosts generating alerts",
        "Generate stacked visualization of alert severity over last 24 hours",
        "What alerts are there for user admin?",
        "Find hosts with more than 50 failed login attempts",
        "Show me critical alerts from the last hour",
        "Create stacked chart showing rule types distribution",
        "Which agents are disconnected?",
        "Find authentication failures in the last 24 hours"
    ]

    selected_example = st.selectbox(
        "Example Queries:",
        ["Select an example..."] + example_queries
    )

    if st.button("Use Example Query") and selected_example != "Select an example...":
        st.session_state.current_query = selected_example

# Main content area
if not api_status:
    st.error("⚠️ API is not running. Please start the FastAPI server first:")
    st.code("python main.py", language="bash")
    st.stop()

# Query input
st.subheader("Ask a Security Question")

# Use example query if selected
current_query = st.session_state.get('current_query', '')
if current_query:
    st.session_state.current_query = ''  # Clear after use

query = st.text_input(
    "Enter your security question:",
    value=current_query,
    placeholder="e.g., Show me the top 10 hosts with most alerts this week...",
    key="query_input"
)

if st.button("📋 Clear History"):
    st.session_state.messages = []
    st.rerun()

# Process query - automatically submit on Enter
if query and query.strip() and query != st.session_state.last_query:
    # Update last query to prevent duplicate submissions
    st.session_state.last_query = query
    
    # Add user message to history
    st.session_state.messages.append({
        "role": "user",
        "content": query,
        "timestamp": datetime.now().strftime("%H:%M:%S")
    })

    # Show loading spinner
    with st.spinner("🤔 Analyzing your security question..."):
        response = send_query(query, st.session_state.session_id)

    # Add assistant response to history
    if "error" in response:
        st.session_state.messages.append({
            "role": "error",
            "content": response["error"],
            "details": response.get("details", ""),
            "timestamp": datetime.now().strftime("%H:%M:%S")
        })
    else:
        st.session_state.messages.append({
            "role": "assistant",
            "content": response["response"],
            "timestamp": datetime.now().strftime("%H:%M:%S")
        })

    # Rerun to update the interface
    st.rerun()

# Display conversation history
if st.session_state.messages:
    st.subheader("Conversation History")

    for i, message in enumerate(reversed(st.session_state.messages)):
        with st.container():
            col1, col2 = st.columns([1, 10])

            with col1:
                if message["role"] == "user":
                    st.markdown("**👤 You**")
                elif message["role"] == "assistant":
                    st.markdown("**🤖 Assistant**")
                else:
                    st.markdown("**❌ Error**")

            with col2:
                st.markdown(f"*{message['timestamp']}*")

                if message["role"] == "error":
                    st.markdown(f'<div class="error-message">{message["content"]}</div>', unsafe_allow_html=True)
                    if message.get("details"):
                        with st.expander("Error Details"):
                            st.text(message["details"])
                else:
                    # Check if the response contains stacked visualization data
                    if message["role"] == "assistant":
                        stacked_data = extract_stacked_data_from_response(message["content"])
                        if stacked_data:
                            # Display the chart first
                            chart_result = render_stacked_chart(stacked_data)
                            if chart_result:
                                fig, stack_summary = chart_result
                                st.plotly_chart(fig, use_container_width=True)
                                
                                # Display summary metrics
                                display_stack_summary(stack_summary)
                                
                                # Show a condensed version of the text response
                                st.markdown(f'<div class="response-container">{message["content"]}</div>', unsafe_allow_html=True)
                            else:
                                # Fallback to text only
                                st.markdown(f'<div class="response-container">{message["content"]}</div>', unsafe_allow_html=True)
                        else:
                            # Regular text response
                            st.markdown(f'<div class="response-container">{message["content"]}</div>', unsafe_allow_html=True)
                    else:
                        st.markdown(f'<div class="response-container">{message["content"]}</div>', unsafe_allow_html=True)

            st.markdown("---")

# Help section
with st.expander("ℹ️ Help & Examples"):
    st.markdown("""
    ### How to Use
    1. **Start the API server** first: `python main.py`
    2. **Ask security questions** in natural language and press Enter to submit
    3. **Use example queries** from the sidebar for quick start
    4. **Reset session** to clear conversation history

    ### Example Queries
    """)

    for example in example_queries:
        st.markdown(f"• {example}")

    st.markdown("""
    ### Available Functions
    - **Alert Analysis**: Ranking, counting, filtering alerts
    - **Entity Investigation**: Investigate hosts, users, processes, files
    - **Threat Detection**: MITRE ATT&CK techniques and threat actors
    - **Relationship Mapping**: Connections between entities
    - **Anomaly Detection**: Unusual patterns and behaviors
    - **Timeline Reconstruction**: Chronological event analysis
    - **Vulnerability Checking**: CVE and patch status
    - **Agent Monitoring**: Agent health and connectivity
    """)

# Footer
st.markdown("---")
st.markdown("**Wazuh LLM Security Assistant** - Powered by Claude 3.5 Sonnet via LangChain")
