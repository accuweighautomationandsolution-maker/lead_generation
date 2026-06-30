// State Variables
let currentTab = 'tab-overview';
let activeUser = null;
let allLeads = [];
let selectedLeadForQC = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    checkAuthState();
    setupEventListeners();
});

// 1. AUTHENTICATION LOGIC
function checkAuthState() {
    fetch('/api/auth/me')
        .then(res => res.json())
        .then(data => {
            if (data.username) {
                activeUser = data.username;
                showDashboard(data.username);
            } else {
                activeUser = null;
                showAuth();
            }
        })
        .catch(err => {
            console.error("Auth check failed:", err);
            showAuth();
        });
}

function showAuth() {
    document.getElementById('dashboard-view').classList.add('hidden');
    document.getElementById('auth-view').classList.remove('hidden');
}

function showDashboard(username) {
    document.getElementById('auth-view').classList.add('hidden');
    document.getElementById('dashboard-view').classList.remove('hidden');
    document.getElementById('current-user-display').innerText = username;
    
    // Default avatar letters
    if (username.length >= 2) {
        document.querySelector('.user-avatar').innerText = username.substring(0, 2).toUpperCase();
    } else {
        document.querySelector('.user-avatar').innerText = username.toUpperCase();
    }
    
    loadLeads();
}

// 2. DATA LOADING & STATS RENDERING
function loadLeads() {
    fetch('/api/leads')
        .then(res => {
            if (res.status === 401) {
                checkAuthState();
                throw new Error("Unauthorized");
            }
            return res.json();
        })
        .then(leads => {
            allLeads = leads;
            renderStats();
            renderQueue();
            renderTable();
        })
        .catch(err => console.error("Error loading leads:", err));
}

function renderStats() {
    const total = allLeads.length;
    const priorityA = allLeads.filter(l => l.priority === 'Priority A').length;
    const priorityB = allLeads.filter(l => l.priority === 'Priority B').length;
    const verified = allLeads.filter(l => l.verification_status === 'Verified').length;
    
    document.getElementById('stat-total').innerText = total;
    document.getElementById('stat-priority-a').innerText = priorityA;
    document.getElementById('stat-priority-b').innerText = priorityB;
    document.getElementById('stat-verified').innerText = verified;
}

// 3. TAB CONTROLLER
function switchTab(tabId) {
    // Update nav buttons
    document.querySelectorAll('.nav-item').forEach(btn => {
        if (btn.getAttribute('data-tab') === tabId) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });

    // Update tab panes
    document.querySelectorAll('.tab-pane').forEach(pane => {
        if (pane.id === tabId) {
            pane.classList.add('active');
        } else {
            pane.classList.remove('active');
        }
    });

    // Update headers
    const titleMap = {
        'tab-overview': 'Sales Pipeline Overview',
        'tab-intake': 'Raw Market Intelligence Ingestion',
        'tab-verification': 'Quality Control & Node Mapping',
        'tab-finished': 'Finished Deliverable Schema'
    };
    const subtitleMap = {
        'tab-overview': 'Interactive SOP Control Panel v1.0',
        'tab-intake': 'Stage 1: Gather and record target triggers',
        'tab-verification': 'Stage 2 & 3: Profile mapping and conflict resolution verification',
        'tab-finished': 'Stage 5: Fully validated leads list ready for SDR distribution'
    };

    document.getElementById('page-title').innerText = titleMap[tabId] || 'Dashboard';
    document.getElementById('page-subtitle').innerText = subtitleMap[tabId] || 'SOP control panel';
    
    currentTab = tabId;
}

// 4. INGESTION LOGIC (STAGE 1)
function handleIntakeSubmit(e) {
    e.preventDefault();
    
    const company = document.getElementById('intake-company').value.trim();
    const industry = document.getElementById('intake-industry').value;
    const location = document.getElementById('intake-location').value.trim();
    const source = document.getElementById('intake-source').value;
    const signal = document.getElementById('intake-signal').value.trim();
    
    if (!company) return;
    
    // Auto-calculate suggested priority based on key phrases (Page 8 Sorter Matrix)
    let autoPriority = "Priority C";
    const lowerSignal = (signal + " " + company).toLowerCase();
    
    const priorityAKeywords = ["new plant", "new facility", "factory expansion", "conveyor requirement", "packaging line", "secondary packaging", "tender released", "tender", "installation"];
    const priorityBKeywords = ["capacity expansion", "hiring automation", "automation engineer", "expansion planned", "warehouse expansion", "expand production"];
    
    if (priorityAKeywords.some(kw => lowerSignal.includes(kw))) {
        autoPriority = "Priority A";
    } else if (priorityBKeywords.some(kw => lowerSignal.includes(kw))) {
        autoPriority = "Priority B";
    }
    
    const newLead = {
        company: company,
        industry: industry,
        plant_location: location,
        source: source,
        buying_signal: signal,
        priority: autoPriority,
        verification_status: "Pending"
    };
    
    fetch('/api/leads', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newLead)
    })
    .then(res => res.json())
    .then(lead => {
        // Reset Ingestion Form
        document.getElementById('intake-form').reset();
        
        // Reload leads list
        loadLeads();
        
        // Select this lead and redirect directly to QC Verification to proceed with mapping
        selectedLeadForQC = lead;
        switchTab('tab-verification');
        setTimeout(() => {
            selectQueueLead(lead.id);
        }, 100);
    })
    .catch(err => console.error("Error creating lead:", err));
}

// Automated Discovery Scanner handlers
function runDiscoveryScan() {
    const sector = document.getElementById('discovery-sector').value;
    const region = document.getElementById('discovery-region').value;
    const loadingDiv = document.getElementById('discovery-loading');
    const resultsWrapper = document.getElementById('discovery-results-wrapper');
    
    loadingDiv.classList.remove('hidden');
    resultsWrapper.classList.add('hidden');
    
    fetch(`/api/discover?sector=${encodeURIComponent(sector)}&region=${encodeURIComponent(region)}`)
        .then(res => {
            if (res.status === 401) {
                checkAuthState();
                throw new Error("Unauthorized");
            }
            return res.json();
        })
        .then(results => {
            loadingDiv.classList.add('hidden');
            renderDiscoveryResults(results);
        })
        .catch(err => {
            loadingDiv.classList.add('hidden');
            console.error("Discovery failed:", err);
            alert("Discovery scan failed. Please check network connectivity or try again.");
        });
}

function renderDiscoveryResults(results) {
    const wrapper = document.getElementById('discovery-results-wrapper');
    const body = document.getElementById('discovery-results-body');
    body.innerHTML = '';
    
    if (!results || results.length === 0) {
        body.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:20px; color:var(--text-muted);">No active trigger signals found for this sector currently.</td></tr>';
        wrapper.classList.remove('hidden');
        return;
    }
    
    results.forEach(lead => {
        const tr = document.createElement('tr');
        const priorityClass = lead.priority.replace(' ', '-').toLowerCase();
        
        tr.innerHTML = `
            <td style="font-weight:600; color:var(--text-primary);">${escapeHTML(lead.company)}</td>
            <td title="${escapeHTML(lead.buying_signal)}" style="max-width:300px; overflow:hidden; text-overflow:ellipsis; white-space:normal; line-height:1.4;">${escapeHTML(lead.buying_signal)}</td>
            <td>
                <div style="font-weight:500;">${escapeHTML(lead.decision_maker)}</div>
                <div style="font-size:9px; color:var(--text-muted);">${escapeHTML(lead.designation)}</div>
            </td>
            <td><span class="badge ${priorityClass}">${escapeHTML(lead.priority)}</span></td>
            <td style="text-align:center;">
                <button type="button" class="btn primary-btn import-lead-btn" style="padding:6px 12px; font-size:10px; width:auto; border-radius:4px;">Import to Queue</button>
            </td>
        `;
        
        const importBtn = tr.querySelector('.import-lead-btn');
        importBtn.addEventListener('click', () => {
            importDiscoveredLead(lead, importBtn);
        });
        
        body.appendChild(tr);
    });
    
    wrapper.classList.remove('hidden');
}

function importDiscoveredLead(lead, btn) {
    btn.disabled = true;
    btn.innerText = 'Importing...';
    btn.style.background = 'var(--text-muted)';
    btn.style.boxShadow = 'none';
    
    fetch('/api/leads', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(lead)
    })
    .then(res => {
        if (!res.ok) throw new Error("Import failed");
        return res.json();
    })
    .then(importedLead => {
        btn.innerText = 'Imported ✓';
        btn.style.background = 'var(--success)';
        btn.style.color = '#070a13';
        btn.style.boxShadow = '0 0 10px rgba(16,185,129,0.3)';
        
        // Reload cache
        loadLeads();
    })
    .catch(err => {
        console.error("Import failed:", err);
        btn.disabled = false;
        btn.innerText = 'Import to Queue';
        btn.style.background = 'linear-gradient(135deg, var(--accent-glow) 0%, #0891b2 100%)';
        alert("Failed to import lead. Please try again.");
    });
}

// 5. QUALITY CONTROL & VERIFICATION CONTROLLER (STAGES 2, 3 & 4)
function renderQueue() {
    const queueContainer = document.getElementById('leads-queue');
    queueContainer.innerHTML = '';
    
    if (allLeads.length === 0) {
        queueContainer.innerHTML = '<div style="text-align:center; padding: 20px; color: var(--text-muted); font-size:12px;">Queue is empty</div>';
        return;
    }

    allLeads.forEach(lead => {
        const item = document.createElement('div');
        item.className = `queue-item ${selectedLeadForQC && selectedLeadForQC.id === lead.id ? 'active' : ''}`;
        item.setAttribute('data-id', lead.id);
        
        const priorityClass = lead.priority.replace(' ', '-').toLowerCase();
        const statusClass = lead.verification_status.toLowerCase();
        
        item.innerHTML = `
            <div class="queue-header">
                <span class="queue-company">${escapeHTML(lead.company)}</span>
                <span class="queue-date">${escapeHTML(lead.date_published.split('T')[0])}</span>
            </div>
            <div class="queue-meta">
                <span class="badge ${priorityClass}">${escapeHTML(lead.priority)}</span>
                <span class="badge status-${statusClass}">${escapeHTML(lead.verification_status)}</span>
            </div>
        `;
        
        item.addEventListener('click', () => selectQueueLead(lead.id));
        queueContainer.appendChild(item);
    });
}

function selectQueueLead(leadId) {
    const lead = allLeads.find(l => l.id === leadId);
    if (!lead) return;
    
    selectedLeadForQC = lead;
    
    // Highlight selected in queue list UI
    document.querySelectorAll('.queue-item').forEach(item => {
        if (item.getAttribute('data-id') === leadId) {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });

    // Toggle panels
    document.getElementById('verification-panel-empty').classList.add('hidden');
    document.getElementById('verification-panel-active').classList.remove('hidden');

    // Load form data
    document.getElementById('qc-lead-id').value = lead.id;
    document.getElementById('qc-company-title').innerText = lead.company;
    
    // Update badge priority color
    const badge = document.getElementById('qc-lead-priority-badge');
    badge.innerText = lead.priority;
    badge.className = `badge ${lead.priority.replace(' ', '-').toLowerCase()}`;
    
    // Set form fields
    const fields = [
        'decision_maker', 'designation', 'email', 'mobile', 'linkedin', 
        'website', 'source_a', 'source_b', 'project_details', 
        'estimated_requirement', 'priority', 'confidence', 'remarks'
    ];
    
    fields.forEach(field => {
        const elem = document.getElementById(`qc-${field}`);
        if (elem) {
            let val = lead[field] || '';
            // If the field is "Not Publicly Available", display as empty or standard placeholder
            if (val === 'Not Publicly Available') {
                elem.value = '';
                elem.placeholder = 'Not Publicly Available';
            } else {
                elem.value = val;
                elem.placeholder = '';
            }
        }
    });

    // Set conflict field (simplified mapping)
    const conflictElem = document.getElementById('qc-conflict-flag');
    if (lead.source_a !== 'Not Publicly Available' && lead.source_b !== 'Not Publicly Available') {
        conflictElem.value = lead.remarks.toLowerCase().includes('conflict') ? 'yes' : 'no';
    } else {
        conflictElem.value = 'no';
    }
}

// Automatic matrix scorer trigger
function runMatrixScorer() {
    if (!selectedLeadForQC) return;
    
    // Get text context from form inputs
    const projectDetails = document.getElementById('qc-project-details').value.trim();
    const decisionMaker = document.getElementById('qc-decision-maker').value.trim();
    const designation = document.getElementById('qc-designation').value.trim();
    const buyingSignal = selectedLeadForQC.buying_signal || '';
    
    const combinedText = `${projectDetails} ${decisionMaker} ${designation} ${buyingSignal}`.toLowerCase();
    
    let priorityVal = "Priority C";
    
    // Page 8 Matrix Scoring Rules
    const priorityAKeywords = ["new plant", "new facility", "factory expansion", "conveyor requirement", "packaging line", "secondary packaging", "tender released", "tender", "installation"];
    const priorityBKeywords = ["capacity expansion", "hiring automation", "automation engineer", "expansion planned", "warehouse expansion", "expand production"];
    
    if (priorityAKeywords.some(kw => combinedText.includes(kw))) {
        priorityVal = "Priority A";
    } else if (priorityBKeywords.some(kw => combinedText.includes(kw))) {
        priorityVal = "Priority B";
    }
    
    document.getElementById('qc-priority').value = priorityVal;
    
    // Auto-calculate suggested confidence based on completeness
    let confidenceVal = "Low";
    const hasDM = decisionMaker && decisionMaker !== 'Not Publicly Available';
    const hasEmail = document.getElementById('qc-email').value.trim() !== '';
    const hasSourceB = document.getElementById('qc-source-b').value.trim() !== '';
    
    if (hasDM && hasEmail && hasSourceB) {
        confidenceVal = "High";
    } else if (hasDM || hasEmail) {
        confidenceVal = "Medium";
    }
    
    document.getElementById('qc-confidence').value = confidenceVal;
    
    // Alert user visually
    alert(`Sorter Matrix Computed:\n- Assigned Priority: ${priorityVal}\n- Assigned Confidence: ${confidenceVal}`);
}

function handleQCSubmit(e) {
    e.preventDefault();
    if (!selectedLeadForQC) return;

    const leadId = document.getElementById('qc-lead-id').value;
    
    // Process form values
    const getVal = (id) => {
        const val = document.getElementById(id).value.trim();
        return val === '' ? 'Not Publicly Available' : val;
    };

    const updatePayload = {
        decision_maker: getVal('qc-decision-maker'),
        designation: getVal('qc-designation'),
        email: getVal('qc-email'),
        mobile: getVal('qc-mobile'),
        linkedin: getVal('qc-linkedin'),
        website: getVal('qc-website'),
        source_a: getVal('qc-source-a'),
        source_b: getVal('qc-source-b'),
        project_details: getVal('qc-project-details'),
        estimated_requirement: getVal('qc-estimated-requirement'),
        priority: document.getElementById('qc-priority').value,
        confidence_score: document.getElementById('qc-confidence').value,
        remarks: getVal('qc-remarks'),
        verification_status: "Verified" // committing verification
    };

    fetch(`/api/leads/${leadId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updatePayload)
    })
    .then(res => res.json())
    .then(() => {
        selectedLeadForQC = null;
        document.getElementById('verification-panel-active').classList.add('hidden');
        document.getElementById('verification-panel-empty').classList.remove('hidden');
        
        loadLeads();
        switchTab('tab-finished');
    })
    .catch(err => console.error("Error committing QC Verification:", err));
}

// 6. DELIVERABLE GRID CONTROLLER (STAGE 5)
function renderTable() {
    const tableBody = document.getElementById('leads-table-body');
    tableBody.innerHTML = '';
    
    const searchQuery = document.getElementById('grid-search').value.toLowerCase();
    const priorityFilter = document.getElementById('grid-filter-priority').value;
    const confidenceFilter = document.getElementById('grid-filter-confidence').value;
    
    // Filter logic
    const filteredLeads = allLeads.filter(lead => {
        const matchesSearch = lead.company.toLowerCase().includes(searchQuery) || 
                              lead.decision_maker.toLowerCase().includes(searchQuery) ||
                              lead.buying_signal.toLowerCase().includes(searchQuery);
                              
        const matchesPriority = priorityFilter ? lead.priority === priorityFilter : true;
        const matchesConfidence = confidenceFilter ? lead.confidence_score === confidenceFilter : true;
        
        return matchesSearch && matchesPriority && matchesConfidence;
    });

    if (filteredLeads.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="18" style="text-align:center; padding: 30px; color: var(--text-muted);">No records match criteria.</td></tr>';
        return;
    }

    filteredLeads.forEach(lead => {
        const tr = document.createElement('tr');
        
        const priorityClass = lead.priority.replace(' ', '-').toLowerCase();
        
        // Clean long texts for table view readability
        const truncate = (str, len = 40) => {
            if (!str) return '';
            if (str.length > len) return str.substring(0, len) + '...';
            return str;
        };

        tr.innerHTML = `
            <td><span class="badge ${priorityClass}">${escapeHTML(lead.priority)}</span></td>
            <td style="font-weight: 600;">${escapeHTML(lead.company)}</td>
            <td>${escapeHTML(lead.industry)}</td>
            <td>${escapeHTML(lead.plant_location)}</td>
            <td>${escapeHTML(lead.decision_maker)}</td>
            <td>${escapeHTML(lead.designation)}</td>
            <td>${escapeHTML(lead.email)}</td>
            <td>${escapeHTML(lead.mobile)}</td>
            <td>${escapeHTML(truncate(lead.linkedin, 20))}</td>
            <td>${escapeHTML(lead.website)}</td>
            <td title="${escapeHTML(lead.buying_signal)}">${escapeHTML(truncate(lead.buying_signal, 30))}</td>
            <td title="${escapeHTML(lead.project_details)}">${escapeHTML(truncate(lead.project_details, 30))}</td>
            <td>${escapeHTML(lead.estimated_requirement)}</td>
            <td>${escapeHTML(lead.source)}</td>
            <td>${escapeHTML(lead.date_published.split('T')[0])}</td>
            <td><span class="badge ${lead.confidence_score.toLowerCase()}-conf">${escapeHTML(lead.confidence_score)}</span></td>
            <td title="${escapeHTML(lead.remarks)}">${escapeHTML(truncate(lead.remarks, 20))}</td>
            <td class="actions-cell">
                <button class="row-action-btn" data-id="${lead.id}">Delete</button>
            </td>
        `;
        
        // Event listener for delete
        tr.querySelector('.row-action-btn').addEventListener('click', (e) => {
            e.stopPropagation();
            deleteLeadItem(lead.id);
        });
        
        tableBody.appendChild(tr);
    });
}

function deleteLeadItem(leadId) {
    if (!confirm("Are you sure you want to permanently delete this lead from target schema?")) return;
    
    fetch(`/api/leads/${leadId}`, {
        method: 'DELETE'
    })
    .then(res => res.json())
    .then(() => {
        loadLeads();
    })
    .catch(err => console.error("Error deleting lead:", err));
}

// 7. GLOBAL EVENT LISTENERS & SETUP
function setupEventListeners() {
    // Auth Toggle listeners
    document.getElementById('toggle-to-register').addEventListener('click', () => {
        document.getElementById('login-form').classList.add('hidden');
        document.getElementById('register-form').classList.remove('hidden');
    });

    document.getElementById('toggle-to-login').addEventListener('click', () => {
        document.getElementById('register-form').classList.add('hidden');
        document.getElementById('login-form').classList.remove('hidden');
    });

    // Form Submits
    document.getElementById('login-form').addEventListener('submit', handleLogin);
    document.getElementById('register-form').addEventListener('submit', handleRegister);
    document.getElementById('intake-form').addEventListener('submit', handleIntakeSubmit);
    document.getElementById('qc-form').addEventListener('submit', handleQCSubmit);
    
    // Sidebar Tabs
    document.querySelectorAll('.nav-item').forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.getAttribute('data-tab');
            switchTab(tabId);
        });
    });

    // Logout
    document.getElementById('logout-btn').addEventListener('click', handleLogout);

    // QC Matrix Scorer helper trigger
    document.getElementById('qc-autoclassify-btn').addEventListener('click', runMatrixScorer);

    // Automated Scanner scan trigger
    document.getElementById('discovery-scan-btn').addEventListener('click', runDiscoveryScan);

    // Table search & filters
    document.getElementById('grid-search').addEventListener('input', renderTable);
    document.getElementById('grid-filter-priority').addEventListener('change', renderTable);
    document.getElementById('grid-filter-confidence').addEventListener('change', renderTable);

    // Export Excel CSV download trigger
    document.getElementById('grid-export-btn').addEventListener('click', () => {
        window.location.href = '/api/leads/export';
    });
}

// Auth Handlers
function handleLogin(e) {
    e.preventDefault();
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;
    
    const errDiv = document.getElementById('login-error');
    errDiv.classList.add('hidden');

    fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    })
    .then(async res => {
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Login failed');
        return data;
    })
    .then(data => {
        document.getElementById('login-form').reset();
        activeUser = data.username;
        showDashboard(data.username);
    })
    .catch(err => {
        errDiv.innerText = err.message;
        errDiv.classList.remove('hidden');
    });
}

function handleRegister(e) {
    e.preventDefault();
    const username = document.getElementById('register-username').value.trim();
    const password = document.getElementById('register-password').value;
    
    const errDiv = document.getElementById('register-error');
    const successDiv = document.getElementById('register-success');
    errDiv.classList.add('hidden');
    successDiv.classList.add('hidden');

    fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
    })
    .then(async res => {
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Registration failed');
        return data;
    })
    .then(() => {
        document.getElementById('register-form').reset();
        successDiv.innerText = "Account created. You can now authenticate.";
        successDiv.classList.remove('hidden');
        setTimeout(() => {
            document.getElementById('register-form').classList.add('hidden');
            document.getElementById('login-form').classList.remove('hidden');
        }, 1500);
    })
    .catch(err => {
        errDiv.innerText = err.message;
        errDiv.classList.remove('hidden');
    });
}

function handleLogout() {
    fetch('/api/auth/logout', { method: 'POST' })
        .then(() => {
            activeUser = null;
            allLeads = [];
            selectedLeadForQC = null;
            showAuth();
        })
        .catch(err => console.error("Logout failed:", err));
}

// Utility Helpers
function escapeHTML(str) {
    if (!str) return '';
    return str.replace(/[&<>'"]/g, 
        tag => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            "'": '&#39;',
            '"': '&quot;'
        }[tag] || tag)
    );
}
