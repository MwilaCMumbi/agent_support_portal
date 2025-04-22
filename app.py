import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, time, timedelta
import time
import uuid
from typing import Dict, List, Optional, TypedDict
import sqlite3
import json
import hashlib
import os

# ============================================
# CONFIGURATION & CONSTANTS
# ============================================

# Database configuration
DB_NAME = "vitalite_cases.db"
PERSISTENCE_DIR = ".streamlit"
PERSISTENCE_FILE = os.path.join(PERSISTENCE_DIR, "app_state.json")

# Constants
CHANNELS = ["WhatsApp", "Voice Call", "Email"]
ROLES = ["Agent", "Sales and Service Assistant", "Agent Team Leader", 
         "Regional Manager", "Assistant Regional Manager"]
REGIONS = ["Lusaka", "Western", "North-Western", "Northern", "Southern", 
           "Central", "Luapula", "Eastern", "Copperbelt", "Muchinga"]
ISSUE_TYPES = ["Commissions", "Tokens", "Registration Failure", "Float", "Stock",
               "Edit own account request", "Edit customer request", 
               "Reporting New Fault", "Follow up on previously reported fault",
               "Balance inquiry", "Campaign related", "Call back request",
               "Call was dropped", "Customer feedback"]
USER_ROLES = ["Admin", "Manager", "Agent"]

# ============================================
# DATA MODELS
# ============================================

class User(TypedDict):
    username: str
    password_hash: str
    role: str
    region: str
    active: bool

class CaseReporter(TypedDict):
    name: str
    role: str
    agent_number: Optional[str]
    contact: str

class CaseIssue(TypedDict):
    type: str
    description: str
    attachments: List[str]

class CaseResolution(TypedDict):
    notes: str
    action_taken: str
    timestamp: str

class CaseTimestamps(TypedDict):
    received: Optional[str]
    logged: str
    resolved: Optional[str]

class Case(TypedDict):
    case_id: str
    channel: str
    timestamps: CaseTimestamps
    reporter: CaseReporter
    region: str
    issue: CaseIssue
    status: str
    resolution: Optional[CaseResolution]
    handled_by: str

# ============================================
# PERSISTENCE & SECURITY
# ============================================

def hash_password(password: str) -> str:
    """Hash a password for storing."""
    salt = "vitalite_salt"  # In production, use a unique salt per user
    return hashlib.sha256((password + salt).encode()).hexdigest()

def verify_password(stored_hash: str, provided_password: str) -> bool:
    """Verify a stored password against one provided by user"""
    return stored_hash == hash_password(provided_password)

def save_persistent_data(data: dict):
    """Save persistent data to file"""
    if not os.path.exists(PERSISTENCE_DIR):
        os.makedirs(PERSISTENCE_DIR)
    with open(PERSISTENCE_FILE, 'w') as f:
        json.dump(data, f)

def load_persistent_data() -> dict:
    """Load persistent data from file"""
    if os.path.exists(PERSISTENCE_FILE):
        with open(PERSISTENCE_FILE, 'r') as f:
            return json.load(f)
    return {}

# ============================================
# DATABASE FUNCTIONS
# ============================================

def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Cases table (stores entire case as JSON for flexibility)
    c.execute('''CREATE TABLE IF NOT EXISTS cases
                 (case_id TEXT PRIMARY KEY,
                  case_data TEXT,
                  status TEXT,
                  region TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Create indexes for faster queries
    c.execute('''CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status)''')
    c.execute('''CREATE INDEX IF NOT EXISTS idx_cases_region ON cases(region)''')
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY,
                  password_hash TEXT,
                  role TEXT,
                  region TEXT,
                  active BOOLEAN DEFAULT 1,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Insert default admin user if not exists
    admin_hash = hash_password("admin123")
    c.execute('''INSERT OR IGNORE INTO users VALUES 
              (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)''', 
              ("admin", admin_hash, "Admin", "All", True))
    
    conn.commit()
    conn.close()

def save_case(case: Case):
    """Save a case to the database"""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    case_json = json.dumps(case)
    c.execute('''INSERT OR REPLACE INTO cases VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)''', 
              (case['case_id'], case_json, case.get('status', 'Open'), case['region']))
    conn.commit()
    conn.close()

def get_case(case_id: str) -> Optional[Case]:
    """Retrieve a single case by ID"""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT case_data FROM cases WHERE case_id=?", (case_id,))
    result = c.fetchone()
    conn.close()
    return json.loads(result[0]) if result else None

def get_all_cases(region_filter: str = None, status_filter: str = None) -> List[Case]:
    """Retrieve all cases with optional filters"""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    query = "SELECT case_data FROM cases"
    params = []
    
    conditions = []
    if region_filter and region_filter != "All":
        conditions.append("region=?")
        params.append(region_filter)
    if status_filter and status_filter != "All":
        conditions.append("status=?")
        params.append(status_filter)
    
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    
    c.execute(query, params)
    cases = [json.loads(row[0]) for row in c.fetchall()]
    conn.close()
    return cases

def delete_case(case_id: str):
    """Delete a case from the database"""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM cases WHERE case_id=?", (case_id,))
    conn.commit()
    conn.close()

def save_user(user: User):
    """Save a user to the database"""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''INSERT OR REPLACE INTO users VALUES 
              (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)''', 
              (user['username'], user['password_hash'], user['role'], 
               user['region'], user['active']))
    conn.commit()
    conn.close()

def get_user(username: str) -> Optional[User]:
    """Retrieve a single user by username"""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    
    if row:
        return {
            "username": row[0],
            "password_hash": row[1],
            "role": row[2],
            "region": row[3],
            "active": bool(row[4])
        }
    return None

def get_all_users() -> List[User]:
    """Retrieve all users from the database"""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    users = [{
        "username": row[0],
        "password_hash": row[1],
        "role": row[2],
        "region": row[3],
        "active": bool(row[4])
    } for row in c.fetchall()]
    conn.close()
    return users

def delete_user(username: str):
    """Delete a user from the database"""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE username=?", (username,))
    conn.commit()
    conn.close()

# Initialize the database
init_db()

# ============================================
# UI HELPER FUNCTIONS
# ============================================

def setup_page_config():
    """Configure the page settings and apply custom CSS."""
    st.set_page_config(
        page_title="VITALITE Agent Management Query Portal",
        page_icon="🆘",
        layout="wide"
    )
    
    # Modern, sleek CSS styling
    st.markdown("""
    <style>
        :root {
            --primary: #003366;
            --secondary: #ffcc00;
            --accent: #5cb85c;
            --danger: #d9534f;
            --warning: #f0ad4e;
            --light-bg: #f8f9fa;
        }
        
        .stButton>button {
            background-color: var(--primary);
            color: white;
            border-radius: 8px;
            padding: 0.5rem 1rem;
            border: none;
            font-weight: 500;
            transition: all 0.2s;
        }
        .stButton>button:hover {
            background-color: #004080;
            transform: translateY(-1px);
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        .report-title {
            font-size: 28px;
            color: var(--primary);
            font-weight: 700;
            margin-bottom: 1.5rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--primary);
        }
        
        .case-card {
            border-left: 4px solid var(--primary);
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 12px rgba(0,0,0,0.08);
        }
        
        .status-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 12px;
            font-size: 0.85rem;
            font-weight: 600;
        }
        
        .status-open {
            background-color: rgba(217, 83, 79, 0.1);
            color: var(--danger);
        }
        
        .status-closed {
            background-color: rgba(92, 184, 92, 0.1);
            color: var(--accent);
        }
        
        .status-escalated {
            background-color: rgba(240, 173, 78, 0.1);
            color: var(--warning);
        }
        
        .required-field::after {
            content: " *";
            color: var(--danger);
        }
        
        .form-section {
            background-color: white;
            padding: 1.5rem;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            margin-bottom: 1.5rem;
        }
        
        .success-message {
            background-color: rgba(92, 184, 92, 0.1);
            padding: 1rem;
            border-radius: 8px;
            border-left: 4px solid var(--accent);
            margin-bottom: 1.5rem;
        }
        
        .portal-title {
            font-size: 24px;
            font-weight: bold;
            color: var(--primary);
            margin-bottom: 1rem;
            text-align: center;
        }
        
        .sidebar-title {
            font-size: 20px;
            font-weight: bold;
            color: var(--primary);
            margin-bottom: 1rem;
            text-align: center;
        }
        
        .user-card {
            background-color: white;
            padding: 1rem;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            margin-bottom: 1rem;
        }
    </style>
    """, unsafe_allow_html=True)

def initialize_session_state():
    """Initialize all required session state variables."""
    defaults = {
        'current_case': None,
        'logged_in': False,
        'current_page': "dashboard",
        'user': None,
        'case_filter': 'All',
        'new_case_submitted': False,
        'form_data': {},
        'users': get_all_users(),
        'remember_me': False
    }
    
    # Load persistent data
    persistent_data = load_persistent_data()
    
    for key, value in defaults.items():
        if key not in st.session_state:
            # Use persistent data if available, otherwise use defaults
            st.session_state[key] = persistent_data.get(key, value)
    
    # Check for remembered login
    if not st.session_state.logged_in and persistent_data.get('remember_me'):
        username = persistent_data.get('username')
        if username:
            user = get_user(username)
            if user:
                st.session_state.logged_in = True
                st.session_state.user = user
                st.session_state.current_page = "dashboard"

# ============================================
# AUTHENTICATION
# ============================================

def login_page():
    """Render the login page and handle authentication."""
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown('<div class="portal-title">VITALITE Agent Management Query Portal</div>', unsafe_allow_html=True)
        with st.container():
            with st.form("login", clear_on_submit=True):
                st.subheader("Agent Login")
                username = st.text_input("Username", placeholder="Enter your username")
                password = st.text_input("Password", type="password", placeholder="Enter your password")
                remember_me = st.checkbox("Remember me", value=st.session_state.get('remember_me', False))
                submit = st.form_submit_button("Login", use_container_width=True)
                
                if submit:
                    if username and password:
                        user = get_user(username)
                        if user and user['active'] and verify_password(user['password_hash'], password):
                            st.session_state.logged_in = True
                            st.session_state.user = user
                            st.session_state.current_page = "dashboard"
                            st.session_state.remember_me = remember_me
                            
                            # Save to persistent storage if "Remember me" is checked
                            if remember_me:
                                save_persistent_data({
                                    'username': username,
                                    'remember_me': True
                                })
                            else:
                                save_persistent_data({})
                            
                            st.success("Login successful!")
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error("Invalid credentials or inactive account")
                    else:
                        st.error("Please enter both username and password")

# ============================================
# CASE MANAGEMENT
# ============================================

def generate_case_id() -> str:
    """Generate a unique case ID."""
    return f"VL-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8]}"

def create_new_case(form_data: Dict) -> Case:
    """Create a new case dictionary from form data."""
    case = {
        "case_id": generate_case_id(),
        "channel": form_data['channel'],
        "timestamps": {
            "received": form_data.get('received_time'),
            "logged": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "resolved": None
        },
        "reporter": {
            "name": form_data['name'],
            "role": form_data['role'],
            "agent_number": form_data.get('agent_num'),
            "contact": form_data.get('phone') or form_data.get('email')
        },
        "region": form_data['region'],
        "issue": {
            "type": form_data['issue_type'],
            "description": form_data['description'],
            "attachments": form_data.get('attachments', [])
        },
        "status": "Open",
        "resolution": None,
        "handled_by": st.session_state.user['username']
    }
    
    if form_data.get('resolution_notes'):
        case['resolution'] = {
            "notes": form_data['resolution_notes'],
            "action_taken": "Initial notes",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    
    return case

def new_case_form():
    """Render the form for creating new cases."""
    st.markdown('<div class="report-title">New Case Entry</div>', unsafe_allow_html=True)
    
    if 'form_data' not in st.session_state:
        st.session_state.form_data = {}
    
    with st.form("case_form", clear_on_submit=True):
        # Section 1: Channel Selection
        channel = st.radio("How was this issue reported?", CHANNELS, horizontal=True)
	attachments = []
        
        # Section 2: Reporter Information
        name = st.text_input("Full Name", help="Enter the reporter's full name")
        role = st.selectbox("Role", ROLES)
        agent_num = st.text_input("Agent Number", help="Required for Agent role", 
                                disabled=role != "Agent")
        
        # Dynamic contact field
        if channel in ["WhatsApp", "Voice Call"]:
            phone = st.text_input("Phone Number")
            if channel == "WhatsApp":
                received_date = st.date_input("Message Date")
                received_time = st.time_input("Message Time")
                received_time_str = datetime.combine(received_date, received_time).strftime("%Y-%m-%d %H:%M:%S")
        else:
            email = st.text_input("Email Address")
        
        # Section 3: Location
        region = st.selectbox("Region", REGIONS)
        
        # Section 4: Issue Description
        issue_type = st.selectbox("Issue Type", ISSUE_TYPES)
        description = st.text_area("Detailed Description", height=150,
                                 help="Provide as much detail as possible about the issue")
        resolution_notes = st.text_area("Resolution Notes (Optional)", height=100,
                                      help="You can add resolution notes now or later")
        
        # Section 5: Attachments
        if channel in ["WhatsApp", "Email"]:
            uploaded_files = st.file_uploader("Upload screenshots or documents", 
                                           accept_multiple_files=True,
                                           type=['png', 'jpg', 'jpeg', 'pdf'])
            attachments = [file.name for file in uploaded_files] if uploaded_files else []
        
        # Form submission
        if st.form_submit_button("Submit Case", use_container_width=True):
            # Validate required fields
            if not all([name, role, region, issue_type, description]):
                st.error("Please fill all required fields")
                return
            
            if role == "Agent" and not agent_num:
                st.error("Agent number is required for Agent role")
                return
            
            if channel in ["WhatsApp", "Voice Call"] and not phone:
                st.error("Phone number is required for this channel")
                return
            
            if channel == "Email" and not email:
                st.error("Email address is required for email cases")
                return
            
            # Create and save case
            new_case = create_new_case({
                'channel': channel,
                'name': name,
                'role': role,
                'agent_num': agent_num if role == "Agent" else None,
                'phone': phone if channel in ["WhatsApp", "Voice Call"] else None,
                'email': email if channel == "Email" else None,
                'received_time': received_time_str if channel == "WhatsApp" else None,
                'region': region,
                'issue_type': issue_type,
                'description': description,
                'resolution_notes': resolution_notes,
                'attachments': attachments
            })
            
            save_case(new_case)
            st.session_state.new_case_submitted = True
            st.session_state.current_case = new_case
            st.rerun()

    # Post-submission message
    if st.session_state.get('new_case_submitted') and st.session_state.current_case:
        case = st.session_state.current_case
        st.markdown(f"""
        <div class="success-message">
            <h3>Case {case['case_id']} created successfully!</h3>
            <p>Status: <span class="status-badge status-open">Open</span></p>
        </div>
        """, unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Go to Dashboard", use_container_width=True):
                st.session_state.current_page = "dashboard"
                st.session_state.new_case_submitted = False
                st.rerun()
        with col2:
            if st.button("Create Another Case", use_container_width=True):
                st.session_state.new_case_submitted = False
                st.rerun()

def display_case_details(case: Case):
    """Display detailed information about a case."""
    if not case:
        st.warning("No case data available")
        return
    
    status_class = f"status-{case['status'].lower()}" if case.get('status') else ""
    
    with st.container():
        st.markdown(f"""
        <div class="case-card">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <h3>Case {case.get('case_id', 'N/A')}</h3>
                <span class="status-badge {status_class}">{case.get('status', 'Unknown')}</span>
            </div>
            <div style="margin-top: 1rem;">
                <p><strong>Reporter:</strong> {case['reporter'].get('name', 'N/A')} ({case['reporter'].get('role', 'N/A')})</p>
                <p><strong>Contact:</strong> {case['reporter'].get('contact', 'N/A')}</p>
                <p><strong>Region:</strong> {case.get('region', 'N/A')}</p>
                <p><strong>Issue Type:</strong> {case['issue'].get('type', 'N/A')}</p>
                <p><strong>Description:</strong> {case['issue'].get('description', 'N/A')}</p>
                <p><strong>Logged by:</strong> {case.get('handled_by', 'N/A')} at {case['timestamps'].get('logged', 'N/A')}</p>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        if case.get('channel') == "WhatsApp" and case['timestamps'].get('received'):
            try:
                received = datetime.strptime(case['timestamps']['received'], "%Y-%m-%d %H:%M:%S")
                logged = datetime.strptime(case['timestamps']['logged'], "%Y-%m-%d %H:%M:%S")
                response_mins = (logged - received).total_seconds() / 60
                st.metric("WhatsApp Response Time", f"{response_mins:.1f} minutes")
            except:
                pass

def resolve_case(case: Case):
    """Render the case resolution interface."""
    if not case:
        st.error("No case selected")
        st.session_state.current_case = None
        st.rerun()
        return
    
    st.markdown(f'<div class="report-title">Case Resolution</div>', unsafe_allow_html=True)
    display_case_details(case)
    
    with st.form("resolution_form"):
        st.subheader("Resolution Details")
        existing_notes = case['resolution'].get('notes', "") if case.get('resolution') else ""
        resolution_notes = st.text_area("Resolution Notes", value=existing_notes, height=150)
        
        col1, col2 = st.columns([1, 1])
        with col1:
            close = st.form_submit_button("✅ Close Case", use_container_width=True)
        with col2:
            escalate = st.form_submit_button("⚠️ Escalate", use_container_width=True)
        
        if (close or escalate) and resolution_notes:
            if close:
                case['status'] = "Closed"
                action = "closed"
            else:
                case['status'] = "Open"
                action = "escalated (marked as Open)"
            
            case['resolution'] = {
                "notes": resolution_notes,
                "action_taken": "Closed by agent" if close else "Escalated to senior support",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            save_case(case)
            st.success(f"Case has been {action} successfully!")
            time.sleep(1)
            st.session_state.current_case = None
            st.rerun()

def display_case_list():
    """Display a list of cases with filtering options."""
    st.subheader("Case Management")
    
    # Filter controls
    col1, col2 = st.columns([1, 1])
    with col1:
        filter_option = st.selectbox("Filter by status", ['All', 'Open', 'Closed'], key='case_filter')
    with col2:
        region_filter = st.selectbox("Filter by region", ["All"] + REGIONS, key='region_filter')
    
    cases = get_all_cases(region_filter if region_filter != "All" else None, 
                         filter_option if filter_option != "All" else None)
    
    if not cases:
        st.info("No cases found matching the selected filters")
        return
    
    for case in cases:
        if not case:
            continue
            
        with st.container():
            display_case_details(case)
            
            # Action buttons
            col1, col2, col3 = st.columns([2, 1, 1])
            with col1:
                if st.button(f"View/Resolve", key=f"view_{case['case_id']}", use_container_width=True):
                    st.session_state.current_case = case
                    st.rerun()
            with col3:
                if st.button(f"Delete", key=f"delete_{case['case_id']}", use_container_width=True):
                    delete_case(case['case_id'])
                    st.success("Case deleted successfully!")
                    time.sleep(1)
                    st.rerun()
            
            st.markdown("---")

# ============================================
# DASHBOARD & ANALYTICS
# ============================================

def dashboard():
    """Render the analytics dashboard."""
    st.markdown('<div class="report-title">VITALITE Agent Management Query Portal</div>', unsafe_allow_html=True)
    
    cases = get_all_cases()
    if not cases:
        st.info("No cases logged yet")
        return
    
    # Create DataFrame for analysis
    df = pd.DataFrame([{
        'case_id': case['case_id'],
        'status': case['status'],
        'region': case['region'],
        'issue_type': case['issue']['type'],
        'channel': case['channel'],
        'logged': case['timestamps']['logged']
    } for case in cases])
    
    # KPI Cards
    st.subheader("Performance Metrics")
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Cases", len(df))
    col2.metric("Open Cases", len(df[df['status'] == 'Open']))
    resolution_rate = (len(df[df['status'] == 'Closed']) / len(df)) * 100 if len(df) > 0 else 0
    col3.metric("Resolution Rate", f"{resolution_rate:.1f}%")
    
    # Charts
    tab1, tab2, tab3 = st.tabs(["Cases by Type", "Cases by Status", "Channel Distribution"])
    
    with tab1:
        st.bar_chart(df['issue_type'].value_counts())
    
    with tab2:
        st.bar_chart(df['status'].value_counts())
    
    with tab3:
        fig = px.pie(df, names='channel', title='Case Channel Distribution')
        st.plotly_chart(fig)
    
    # Case List
    display_case_list()
    
    # Data Export
    with st.expander("Export Options"):
        if cases:
            st.download_button(
                label="Download All Cases as CSV",
                data=df.to_csv(index=False),
                file_name="vitalite_cases.csv",
                mime="text/csv"
            )
        else:
            st.warning("No cases to export")

# ============================================
# USER MANAGEMENT
# ============================================

def user_management():
    """User management interface for admins."""
    st.markdown('<div class="report-title">User Management</div>', unsafe_allow_html=True)
    
    if st.session_state.user['role'] != "Admin":
        st.warning("You don't have permission to access this page")
        return
    
    # Add new user form
    with st.expander("Add New User", expanded=True):
        with st.form("user_form"):
            col1, col2 = st.columns(2)
            with col1:
                new_username = st.text_input("Username")
                new_role = st.selectbox("Role", USER_ROLES)
            with col2:
                new_password = st.text_input("Password", type="password")
                new_region = st.selectbox("Region", ["All"] + REGIONS)
            
            if st.form_submit_button("Add User"):
                if new_username and new_password:
                    if get_user(new_username):
                        st.error("Username already exists")
                    else:
                        save_user({
                            "username": new_username,
                            "password_hash": hash_password(new_password),
                            "role": new_role,
                            "region": new_region,
                            "active": True
                        })
                        st.session_state.users = get_all_users()
                        st.success("User added successfully!")
                        st.rerun()
                else:
                    st.error("Please fill all fields")
    
    # User list with edit/delete options
    st.subheader("User List")
    for user in st.session_state.users:
        with st.container():
            st.markdown(f"""
            <div class="user-card">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <h4>{user['username']}</h4>
                    <span>{'Active' if user['active'] else 'Inactive'}</span>
                </div>
                <p><strong>Role:</strong> {user['role']}</p>
                <p><strong>Region:</strong> {user['region']}</p>
            </div>
            """, unsafe_allow_html=True)
            
            col1, col2, col3 = st.columns([1, 1, 2])
            with col1:
                if st.button(f"Edit", key=f"edit_{user['username']}"):
                    st.session_state.editing_user = user
                    st.session_state.current_page = "edit_user"
                    st.rerun()
            with col2:
                if st.button(f"Delete", key=f"delete_{user['username']}"):
                    delete_user(user['username'])
                    st.session_state.users = get_all_users()
                    st.success("User deleted successfully!")
                    time.sleep(1)
                    st.rerun()

def edit_user():
    """Edit user details."""
    if 'editing_user' not in st.session_state:
        st.error("No user selected for editing")
        st.session_state.current_page = "user_management"
        st.rerun()
    
    user = st.session_state.editing_user
    st.markdown(f'<div class="report-title">Edit User: {user["username"]}</div>', unsafe_allow_html=True)
    
    with st.form("edit_user_form"):
        new_password = st.text_input("New Password", type="password", value="", 
                                   placeholder="Leave blank to keep current")
        new_role = st.selectbox("Role", USER_ROLES, index=USER_ROLES.index(user['role']))
        new_region = st.selectbox("Region", ["All"] + REGIONS, index=(["All"] + REGIONS).index(user['region']))
        active = st.checkbox("Active", value=user['active'])
        
        col1, col2 = st.columns(2)
        with col1:
            if st.form_submit_button("Save Changes"):
                updated_user = {
                    "username": user['username'],
                    "password_hash": user['password_hash'] if not new_password else hash_password(new_password),
                    "role": new_role,
                    "region": new_region,
                    "active": active
                }
                save_user(updated_user)
                st.session_state.users = get_all_users()
                st.success("User updated successfully!")
                time.sleep(1)
                st.session_state.current_page = "user_management"
                st.rerun()
        with col2:
            if st.form_submit_button("Cancel"):
                st.session_state.current_page = "user_management"
                st.rerun()

# ============================================
# MAIN APP FLOW
# ============================================

def main():
    """Main application flow controller."""
    # Sidebar Navigation
    st.sidebar.markdown('<div class="sidebar-title">VITALITE Agent Management</div>', unsafe_allow_html=True)
    st.sidebar.markdown(f"**Logged in as:** {st.session_state.user['username']} ({st.session_state.user['role']})")
    st.sidebar.markdown("---")
    
    nav_options = {
        "📊 Dashboard": "dashboard",
        "➕ New Case": "new_case",
    }
    
    if st.session_state.user['role'] == "Admin":
        nav_options["👥 User Management"] = "user_management"
    
    for label, page in nav_options.items():
        if st.sidebar.button(label, use_container_width=True):
            st.session_state.current_page = page
            st.session_state.current_case = None
            st.rerun()
    
    st.sidebar.markdown("---")
    if st.sidebar.button("🚪 Logout", use_container_width=True):
        st.session_state.logged_in = False
        st.session_state.current_case = None
        st.session_state.current_page = None
        save_persistent_data({})  # Clear persistent data on logout
        st.rerun()
    
    # Main Content
    if st.session_state.current_case:
        resolve_case(st.session_state.current_case)
    elif st.session_state.current_page == "dashboard":
        dashboard()
    elif st.session_state.current_page == "user_management":
        user_management()
    elif st.session_state.current_page == "edit_user":
        edit_user()
    else:
        new_case_form()

# ============================================
# RUN THE APP
# ============================================

if __name__ == "__main__":
    setup_page_config()
    initialize_session_state()
    
    if not st.session_state.logged_in:
        login_page()
    else:
        main()