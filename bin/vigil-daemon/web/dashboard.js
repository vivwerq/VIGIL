/* ==========================================================================
   VIGIL // AI NOC Dashboard Custom Controller Logic (Vanilla JS)
   xcomrade.tech // Professional Aerospace/Defense NOC Design
   ========================================================================== */

// Helper to escape HTML tags to prevent XSS
function escapeHtml(str) {
    if (typeof str !== 'string') return '';
    return str.replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&#039;');
}

// --- Custom Canvas Sparkline Engine ---
class Sparkline {
    constructor(canvasId, color, maxVal = null) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');
        this.color = color;
        this.maxVal = maxVal;
        this.data = [];
        this.maxSamples = 30;
        
        this.resize();
        window.addEventListener('resize', () => this.resize());
    }
    
    resize() {
        if (!this.canvas) return;
        const rect = this.canvas.parentElement.getBoundingClientRect();
        this.canvas.width = rect.width;
        this.canvas.height = rect.height;
        this.draw();
    }
    
    push(val) {
        if (typeof val !== 'number' || isNaN(val)) return;
        this.data.push(val);
        if (this.data.length > this.maxSamples) {
            this.data.shift();
        }
        this.draw();
    }
    
    draw() {
        if (!this.canvas || !this.ctx) return;
        const ctx = this.ctx;
        const w = this.canvas.width;
        const h = this.canvas.height;
        
        ctx.clearRect(0, 0, w, h);
        
        if (this.data.length < 2) return;
        
        ctx.strokeStyle = 'rgba(26, 39, 54, 0.4)';
        ctx.lineWidth = 1;
        for (let i = 1; i < 4; i++) {
            const y = (h / 4) * i;
            ctx.beginPath();
            ctx.moveTo(0, y);
            ctx.lineTo(w, y);
            ctx.stroke();
        }
        
        let max = this.maxVal !== null ? this.maxVal : Math.max(...this.data);
        let min = Math.min(...this.data);
        if (max === min) max = min + 1.0;
        
        const points = [];
        const stepX = w / (this.maxSamples - 1);
        const startX = w - (this.data.length - 1) * stepX;
        
        for (let i = 0; i < this.data.length; i++) {
            const val = this.data[i];
            const x = startX + i * stepX;
            const y = h - 4 - ((val - min) / (max - min)) * (h - 8);
            points.push({ x, y });
        }
        
        // Area fill
        ctx.beginPath();
        ctx.moveTo(points[0].x, h);
        for (const p of points) ctx.lineTo(p.x, p.y);
        ctx.lineTo(points[points.length - 1].x, h);
        ctx.closePath();
        
        const grad = ctx.createLinearGradient(0, 0, 0, h);
        grad.addColorStop(0, this.color.replace('1)', '0.08)'));
        grad.addColorStop(1, this.color.replace('1)', '0.0)'));
        ctx.fillStyle = grad;
        ctx.fill();
        
        // Line stroke
        ctx.beginPath();
        ctx.moveTo(points[0].x, points[0].y);
        for (let i = 1; i < points.length; i++) ctx.lineTo(points[i].x, points[i].y);
        ctx.strokeStyle = this.color;
        ctx.lineWidth = 1.5;
        ctx.stroke();
    }
}

// --- Global State ---
let selectedAnomalyId = null;
let currentScenario = 'normal';
let lastChartHash = '';
let resolvedAnomalies = new Set();
let loadedReports = {};

// Instantiate Sparkline Charts (Teal for stats, Amber/Red for critical/warning)
const charts = {
    latency: new Sparkline('chart-latency', 'rgba(0, 168, 181, 1)'),
    loss: new Sparkline('chart-loss', 'rgba(217, 119, 6, 1)', 100),
    bandwidth: new Sparkline('chart-bandwidth', 'rgba(0, 168, 181, 1)', 100),
    prefixes: new Sparkline('chart-prefixes', 'rgba(0, 168, 181, 1)'),
    lsps: new Sparkline('chart-lsps', 'rgba(0, 168, 181, 1)'),
    errors: new Sparkline('chart-errors', 'rgba(217, 119, 6, 1)')
};

// --- Format Utilities ---
function formatTime(isoStr) {
    if (!isoStr) return 'N/A';
    const d = new Date(isoStr);
    if (isNaN(d.getTime())) return 'N/A';
    return d.toISOString().replace('T', ' ').substring(0, 19);
}

function formatUuid(uuid) {
    if (!uuid) return '';
    return uuid.substring(0, 8) + '…';
}

function clamp(val, min, max) {
    return Math.min(Math.max(val, min), max);
}

// --- API Interactions ---
async function selectScenario(name) {
    try {
        const response = await fetch('/api/simulate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scenario: name })
        });
        if (response.ok) {
            currentScenario = name;
            showStatusMessage(`SCENARIO "${name.toUpperCase()}" ACTIVE`);
        }
    } catch (e) {
        console.error("Failed to set scenario:", e);
    }
}

function showStatusMessage(msg) {
    const hudStatus = document.getElementById('copilot-hud-status');
    if (hudStatus) {
        hudStatus.innerText = msg.toUpperCase();
        hudStatus.style.borderColor = 'var(--color-teal)';
        setTimeout(() => {
            if (hudStatus.innerText === msg.toUpperCase()) {
                hudStatus.innerText = 'STANDBY';
                hudStatus.style.borderColor = '';
            }
        }, 3000);
    }
}

// Open detailed diagnostics modal popout
async function openAnomalyModal(id) {
    selectedAnomalyId = id;
    
    // Set active item in anomalies list
    document.querySelectorAll('.anomaly-item').forEach(item => {
        item.classList.toggle('selected', item.getAttribute('data-id') === id);
    });

    const modal = document.getElementById('diagnostics-modal');
    if (!modal) return;
    
    modal.classList.add('active');
    
    // Set placeholder loading states
    document.getElementById('modal-title').innerText = `DIAGNOSING EVENT ${formatUuid(id).toUpperCase()}`;
    document.getElementById('modal-issue').innerText = 'Loading...';
    document.getElementById('modal-confidence').innerText = 'Loading...';
    document.getElementById('modal-impact-time').innerText = 'Loading...';
    document.getElementById('modal-severity-val').innerText = 'Loading...';
    document.getElementById('modal-root-cause').innerText = 'Loading analysis from local LLM...';
    document.getElementById('modal-reasoning').innerText = 'Generating details...';
    document.getElementById('modal-playbook-commands').innerHTML = '<p style="color: var(--text-muted);">Fetching playbook...</p>';
    document.getElementById('modal-action-plan').innerHTML = '<p style="color: var(--text-muted);">Fetching plan...</p>';

    // Set buttons disabled state during fetch
    const resolveBtn = document.getElementById('modal-resolve-btn');
    const exportBtn = document.getElementById('modal-export-btn');
    if (resolveBtn) resolveBtn.disabled = true;
    if (exportBtn) exportBtn.disabled = true;

    try {
        const res = await fetch(`/api/anomalies/${id}`);
        if (!res.ok) throw new Error("Load failed");
        const report = await res.json();
        loadedReports[id] = report;
        
        // Render to normal HUD as well in case they close the modal
        renderAnomalyReport(report);

        // Populate modal data
        const sevClass = report.severity ? report.severity.toLowerCase() : 'info';
        
        // Priority label mapping
        let priorityLabel = 'P3 - INFO';
        if (sevClass === 'critical') priorityLabel = 'P1 - CRITICAL';
        else if (sevClass === 'warning' || sevClass === 'high') priorityLabel = 'P2 - WARNING';
        
        const priorityBadge = document.getElementById('modal-priority');
        if (priorityBadge) {
            priorityBadge.innerText = priorityLabel;
            priorityBadge.className = `modal-priority-badge severity-${sevClass}`;
        }
        
        document.getElementById('modal-title').innerText = `DIAGNOSTICS: EVENT ${formatUuid(id).toUpperCase()}`;
        document.getElementById('modal-issue').innerText = report.predicted_issue || report.diagnosis || 'Unclassified interface/route event.';
        document.getElementById('modal-confidence').innerText = report.confidence || '85%';
        
        let impactText = 'STABLE / MONITORING TREND';
        if (report.time_to_impact_secs !== undefined && report.time_to_impact_secs !== null) {
            impactText = `${report.time_to_impact_secs}s (Breach: ${report.predicted_breach_metric || 'Threshold'})`;
        }
        document.getElementById('modal-impact-time').innerText = impactText;
        document.getElementById('modal-severity-val').innerText = (report.severity || 'INFO').toUpperCase();
        
        document.getElementById('modal-root-cause').innerText = report.root_cause || report.diagnosis || 'No root cause details provided.';
        document.getElementById('modal-reasoning').innerText = report.reasoning || 'No reasoning details provided by model.';

        // Render playbooks
        const playbook = report.playbook;
        const playbookContainer = document.getElementById('modal-playbook-commands');
        if (playbookContainer) {
            if (playbook && playbook.suggested_commands && playbook.suggested_commands.length > 0) {
                playbookContainer.innerHTML = `
                    <p style="color: var(--text-secondary); font-size: 10px; margin-bottom: 8px;">
                        <strong>RATIONALE:</strong> ${escapeHtml(playbook.reasoning)}
                    </p>
                    <div class="playbook-commands">
                        ${playbook.suggested_commands.map(cmd => `
                            <div class="playbook-cmd-line">
                                <code>${escapeHtml(cmd)}</code>
                                <button class="btn-copy" onclick="navigator.clipboard.writeText('${escapeHtml(cmd).replace(/'/g, "\\'")}'); showStatusMessage('Copied to clipboard');">COPY</button>
                            </div>
                        `).join('')}
                    </div>
                `;
            } else {
                playbookContainer.innerHTML = '<p style="color: var(--text-muted);">No playbook suggestions available for this event.</p>';
            }
        }

        // Render Action Plan
        const stepsContainer = document.getElementById('modal-action-plan');
        if (stepsContainer) {
            if (report.mitigation && report.mitigation.length > 0) {
                stepsContainer.innerHTML = `
                    <ul class="diag-mitigation-list">
                        ${report.mitigation.map(step => `<li>${escapeHtml(step)}</li>`).join('')}
                    </ul>
                `;
            } else {
                stepsContainer.innerHTML = '<p style="color: var(--text-muted);">No zero-trust action plan steps generated.</p>';
            }
        }

        // Configure buttons
        if (resolveBtn) {
            resolveBtn.disabled = false;
            resolveBtn.onclick = () => {
                resolveAnomaly(id);
                closeAnomalyModal();
            };
        }
        
        if (exportBtn) {
            exportBtn.disabled = false;
            exportBtn.onclick = () => {
                exportReport(id);
            };
        }

    } catch (e) {
        document.getElementById('modal-root-cause').innerText = 'Failed to load detailed LLM diagnostics report.';
        document.getElementById('modal-issue').innerText = 'ERROR';
        document.getElementById('modal-confidence').innerText = 'N/A';
        document.getElementById('modal-impact-time').innerText = 'N/A';
        document.getElementById('modal-severity-val').innerText = 'N/A';
    }
}

// Close detailed diagnostics modal
function closeAnomalyModal() {
    const modal = document.getElementById('diagnostics-modal');
    if (modal) {
        modal.classList.remove('active');
    }
}

// Load and render detailed LLM diagnostic report
async function selectAnomaly(id) {
    selectedAnomalyId = id;
    
    document.querySelectorAll('.anomaly-item').forEach(item => {
        item.classList.toggle('selected', item.getAttribute('data-id') === id);
    });

    const hud = document.getElementById('diagnostics-hud');
    hud.innerHTML = `<div class="console-placeholder">Loading diagnostics report for ${escapeHtml(formatUuid(id))}…</div>`;

    try {
        const res = await fetch(`/api/anomalies/${id}`);
        if (!res.ok) throw new Error("Load failed");
        const report = await res.json();
        loadedReports[id] = report;
        renderAnomalyReport(report);
    } catch (e) {
        hud.innerHTML = `<div class="console-placeholder" style="color: var(--color-amber);">Failed to load LLM diagnostics report for ${escapeHtml(formatUuid(id))}.</div>`;
    }
}

function renderAnomalyReport(report) {
    const hud = document.getElementById('diagnostics-hud');
    const hudStatus = document.getElementById('copilot-hud-status');
    
    if (hudStatus) {
        hudStatus.innerText = 'REPORT LOADED';
        hudStatus.style.borderColor = 'var(--color-teal)';
    }

    const sevClass = report.severity ? report.severity.toLowerCase() : 'info';
    const scoreDisplay = (typeof report.score === 'number' && !isNaN(report.score))
        ? `${(report.score * 100).toFixed(1)}%` : 'N/A';
    
    const stepsHtml = (report.mitigation && report.mitigation.length > 0)
        ? `<ul class="diag-mitigation-list">
             ${report.mitigation.map(step => `<li>${escapeHtml(step)}</li>`).join('')}
           </ul>`
        : `<p style="color: var(--text-muted);">No mitigations generated.</p>`;

    const predictedIssue = report.predicted_issue || report.diagnosis || 'Unclassified interface/route event.';
    const confidence = report.confidence || '85%';
    const rootCause = report.root_cause || report.reasoning || 'No root cause details provided.';
    const recAction = report.recommended_action || (report.mitigation && report.mitigation[0]) || 'Manual inspection required.';
    const leadTime = report.estimated_lead_time || 'Immediate';
    
    // Time to impact details
    let timeToImpactHtml = '';
    if (report.time_to_impact_secs !== undefined && report.time_to_impact_secs !== null) {
        const breachMetric = report.predicted_breach_metric || 'Threshold';
        timeToImpactHtml = `
            <div class="incident-detail-row">
                <span class="incident-detail-label">ESTIMATED IMPACT:</span>
                <span style="color: var(--color-amber); font-weight: bold;">CRITICAL BREACH IN ${report.time_to_impact_secs} SECONDS</span> (Metric: ${escapeHtml(breachMetric)})
            </div>
        `;
    } else {
        timeToImpactHtml = `
            <div class="incident-detail-row">
                <span class="incident-detail-label">ESTIMATED IMPACT:</span>
                <span style="color: var(--color-ok);">STABLE / MONITORING TREND</span>
            </div>
        `;
    }

    const summaryCardHtml = `
        <div class="incident-summary-card severity-${sevClass}">
            <div class="incident-header">
                <div class="incident-title">${escapeHtml(predictedIssue)}</div>
                <span class="badge severity-${sevClass}">${escapeHtml(report.severity || 'INFO')}</span>
            </div>
            <div class="incident-badge-row">
                <div class="incident-badge-item highlight-teal">CONFIDENCE: ${escapeHtml(confidence)}</div>
                <div class="incident-badge-item highlight-amber">LEAD TIME: ${escapeHtml(leadTime)}</div>
            </div>
            ${timeToImpactHtml}
            <div class="incident-detail-row">
                <span class="incident-detail-label">ROOT CAUSE:</span>
                <span>${escapeHtml(rootCause)}</span>
            </div>
            <div class="incident-detail-row" style="margin-top: 6px; border-top: 1px dashed rgba(255,255,255,0.05); padding-top: 6px;">
                <span class="incident-detail-label" style="color: var(--color-teal);">RECOMMENDED ACTION:</span>
                <strong style="color: var(--text-primary);">${escapeHtml(recAction)}</strong>
            </div>
        </div>
    `;

    const playbook = report.playbook;
    let playbookHtml = '';
    if (playbook && playbook.suggested_commands && playbook.suggested_commands.length > 0) {
        playbookHtml = `
            <div class="diag-section">
                <div class="diag-title">PLAYBOOK REMEDIATION COMMANDS (COPY & RUN)</div>
                <p class="diag-body-text" style="color: var(--text-secondary); font-size: 10px; margin-bottom: 8px;">
                    <strong>RATIONALE:</strong> ${escapeHtml(playbook.reasoning)}
                </p>
                <div class="playbook-commands">
                    ${playbook.suggested_commands.map(cmd => `
                        <div class="playbook-cmd-line">
                            <code>${escapeHtml(cmd)}</code>
                            <button class="btn-copy" onclick="navigator.clipboard.writeText('${escapeHtml(cmd).replace(/'/g, "\\'")}'); showStatusMessage('Copied to clipboard');">COPY</button>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }

    hud.innerHTML = `
        <div class="diag-hud">
            ${summaryCardHtml}

            <div class="diag-section">
                <div class="diag-title">EXPERT SYSTEM & LLM REASONING</div>
                <p class="diag-body-text">${escapeHtml(report.reasoning || 'No reasoning details provided by model.')}</p>
            </div>

            <div class="diag-section">
                <div class="diag-title">IMPACT ASSESSMENT</div>
                <p class="diag-body-text">${escapeHtml(report.impact || 'Undergoing automatic impact rating.')}</p>
            </div>

            <div class="diag-section">
                <div class="diag-title">ZERO-TRUST SANITIZED ACTION PLAN</div>
                ${stepsHtml}
            </div>

            ${playbookHtml}

            <div class="diag-section diag-meta-grid">
                <div class="diag-meta-item"><strong>REPORT ID:</strong> ${escapeHtml(formatUuid(report.id))}</div>
                <div class="diag-meta-item"><strong>SEVERITY:</strong> <span class="badge severity-${sevClass}">${escapeHtml(report.severity || 'INFO')}</span></div>
                <div class="diag-meta-item"><strong>ANOMALY SCORE:</strong> ${scoreDisplay}</div>
                <div class="diag-meta-item"><strong>TIMESTAMP:</strong> ${escapeHtml(formatTime(report.analyzed_at))}</div>
            </div>

            <div class="hud-actions">
                <button class="btn-hud resolve-btn" onclick="resolveAnomaly('${report.id}')">MARK AS RESOLVED</button>
                <button class="btn-hud" onclick="exportReport('${report.id}')">EXPORT AUDIT REPORT</button>
            </div>
        </div>
    `;
}

// Locally resolve anomaly
function resolveAnomaly(id) {
    resolvedAnomalies.add(id);
    showStatusMessage(`ANOMALY ${formatUuid(id)} RESOLVED`);
    
    // Clear display
    if (selectedAnomalyId === id) {
        selectedAnomalyId = null;
        document.getElementById('diagnostics-hud').innerHTML = `
            <div class="hud-placeholder">
                <div class="hud-logo-watermark">VIGIL</div>
                <p>Select an anomaly from the left panel to review local LLM network diagnostics, root-cause assessment, and zero-trust sanitized mitigation actions.</p>
            </div>
        `;
    }
    
    // Refresh list
    fetchUpdate();
}

// Download report as clean text file
function exportReport(id) {
    const report = loadedReports[id];
    if (!report) return;
    
    const text = `=========================================
VIGIL AI NOC COPILOT REPORT
xcomrade.tech // SECURE MPLS OPERATIONS
=========================================
REPORT ID:   ${report.id}
TIMESTAMP:   ${formatTime(report.analyzed_at)}
SEVERITY:    ${report.severity || 'INFO'}
SCORE:       ${(report.score * 100).toFixed(1)}%

[DIAGNOSIS]
${report.diagnosis || 'N/A'}

[REASONING]
${report.reasoning || 'N/A'}

[IMPACT]
${report.impact || 'N/A'}

[MITIGATION COMMANDS]
${(report.mitigation || []).map((step, idx) => `${idx + 1}. ${step}`).join('\n')}

=========================================
GENERATED LOCALLY BY SECURE AIR-GAPPED VIGIL LLM
`;
    
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `VIGIL-Report-${id.substring(0, 8)}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// --- Data Fetch Loop ---
async function fetchUpdate() {
    try {
        // 1. Fetch system status
        const statusRes = await fetch('/api/status');
        let totalAnom = 0;
        let totalIngested = 0;
        if (statusRes.ok) {
            const status = await statusRes.json();
            totalIngested = status.total_ingested;
            totalAnom = status.total_anomalies;
            
            document.getElementById('stat-total-ingested').innerText = status.total_ingested;
            document.getElementById('stat-total-anomalies').innerText = status.total_anomalies;
        }

        // 2. Fetch latest telemetry
        const telemetryRes = await fetch('/api/telemetry');
        let telemetry = [];
        if (telemetryRes.ok) {
            telemetry = await telemetryRes.json();
            
            // Enumerate unique devices
            const devices = new Set();
            telemetry.forEach(env => {
                if (env.source && env.source.hostname) {
                    devices.add(env.source.hostname);
                }
            });
            document.getElementById('connected-devices-count').innerText = devices.size || 4;

            renderTelemetryTable(telemetry);
            updateMetricCharts(telemetry);
        }

        // 3. Fetch latest anomalies and filter resolved
        const anomaliesRes = await fetch('/api/anomalies');
        if (anomaliesRes.ok) {
            let anomalies = await anomaliesRes.json();
            
            // Filter resolved items
            anomalies = anomalies.filter(anom => !resolvedAnomalies.has(anom.id));
            
            renderAnomaliesList(anomalies);
            
            // Set header system status badge
            const statusBadge = document.getElementById('system-status-badge');
            if (statusBadge) {
                if (anomalies.some(anom => anom.severity === 'Critical')) {
                    statusBadge.innerText = 'CRITICAL';
                    statusBadge.className = 'sys-status-badge critical';
                } else if (anomalies.length > 0) {
                    statusBadge.innerText = 'DEGRADED';
                    statusBadge.className = 'sys-status-badge degraded';
                } else {
                    statusBadge.innerText = 'NORMAL';
                    statusBadge.className = 'sys-status-badge normal';
                }
            }
        }
    } catch (e) {
        console.error("Dashboard poll failed:", e);
    }
}

// Extract event info from the serde enum representation
function parseEvent(env) {
    let protocol = 'UNKNOWN';
    let details = '';
    let severity = 'INFO';

    if (!env.event) return { protocol, details, severity };

    if (env.event.Bgp) {
        const bgp = env.event.Bgp;
        protocol = 'BGP';
        severity = bgp.peer && bgp.peer.state === 'Established' ? 'INFO' : 'WARN';
        const peerAddr = bgp.peer ? bgp.peer.address : '?';
        const peerState = bgp.peer ? bgp.peer.state : '?';
        details = `Peer ${peerAddr} State: ${peerState}. Prefixes: ${bgp.affected_prefixes}. LocalPref: ${bgp.local_preference}`;
    } else if (env.event.Lsp) {
        const lsp = env.event.Lsp;
        protocol = 'LSP';
        severity = lsp.packet_loss_pct > 5.0 ? 'HIGH' : (lsp.packet_loss_pct > 1.0 ? 'WARN' : 'INFO');
        details = `${lsp.label_path || lsp.source || '?'} → ${lsp.destination || '?'}. Latency: ${(lsp.latency_us / 1000).toFixed(1)}ms. Loss: ${lsp.packet_loss_pct.toFixed(2)}%. Reroutes: ${lsp.reroute_count}`;
    } else if (env.event.Interface) {
        const iface = env.event.Interface;
        protocol = 'IFACE';
        severity = iface.utilization_pct > 85.0 ? 'HIGH' : (iface.utilization_pct > 70.0 ? 'WARN' : 'INFO');
        const speedG = iface.speed_bps ? (iface.speed_bps / 1e9).toFixed(1) : '?';
        details = `Port: ${iface.interface_name || '?'}. Util: ${iface.utilization_pct.toFixed(1)}%. Speed: ${speedG}G. CRC: ${iface.crc_errors}`;
    } else if (env.event.Snmp) {
        const snmp = env.event.Snmp;
        protocol = 'SNMP';
        severity = snmp.severity === 'Critical' ? 'HIGH' : (snmp.severity === 'High' ? 'WARN' : 'INFO');
        details = `Trap: ${snmp.trap_type || snmp.oid || '?'}. ${snmp.description || ''}`;
    } else if (env.event.Ospf) {
        const ospf = env.event.Ospf;
        protocol = 'OSPF';
        severity = 'WARN';
        details = `Router: ${ospf.router_id || '?'}. Area: ${ospf.area_id || '?'}. Neighbor: ${ospf.neighbor_id || '?'}`;
    }

    return { protocol, details, severity };
}

// Render the telemetry table with color coding
function renderTelemetryTable(events) {
    const tbody = document.getElementById('event-log-body');
    if (!tbody || events.length === 0) return;

    tbody.innerHTML = events.map(env => {
        const { protocol, details, severity } = parseEvent(env);
        const sevClass = severity.toLowerCase();
        
        let rowClass = 'log-row-normal';
        if (severity === 'WARN') rowClass = 'log-row-warn';
        if (severity === 'HIGH' || severity === 'CRITICAL') rowClass = 'log-row-anomaly';

        return `
            <tr class="${rowClass}">
                <td>${escapeHtml(formatTime(env.timestamp))}</td>
                <td>${escapeHtml(formatUuid(env.id))}</td>
                <td>${escapeHtml(env.source ? env.source.hostname : 'N/A')}</td>
                <td><strong>${escapeHtml(protocol)}</strong></td>
                <td><span class="badge severity-${sevClass}">${escapeHtml(severity)}</span></td>
                <td style="font-size: 10px;">${escapeHtml(details)}</td>
            </tr>
        `;
    }).join('');
}

// Render anomalies list on the left panel
function renderAnomaliesList(anomalies) {
    const container = document.getElementById('anomalies-list');
    if (!container) return;

    if (anomalies.length === 0) {
        container.innerHTML = `<div class="console-placeholder">No active anomalies detected. system secure.</div>`;
        document.getElementById('anomaly-badge').innerText = '0 ACTIVE';
        document.getElementById('anomaly-badge').className = 'anomaly-count-badge zero';
        return;
    }

    // Sort anomalies: Critical (P1) > Warning (P2) > Info (P3)
    const priorityWeight = { 'critical': 3, 'warning': 2, 'info': 1 };
    anomalies.sort((a, b) => {
        const sevA = (a.severity || 'warning').toLowerCase();
        const sevB = (b.severity || 'warning').toLowerCase();
        return (priorityWeight[sevB] || 0) - (priorityWeight[sevA] || 0);
    });

    document.getElementById('anomaly-badge').innerText = `${anomalies.length} ACTIVE`;
    document.getElementById('anomaly-badge').className = 'anomaly-count-badge';

    container.innerHTML = anomalies.map(rep => {
        const isSelected = rep.id === selectedAnomalyId ? 'selected' : '';
        const sevStr = rep.severity ? (typeof rep.severity === 'object' ? Object.keys(rep.severity)[0] : String(rep.severity)) : 'Warning';
        const isCritical = sevStr === 'High' || sevStr === 'Critical' ? 'critical-anomaly' : '';
        const scoreDisplay = (typeof rep.score === 'number' && !isNaN(rep.score))
            ? `${(rep.score * 100).toFixed(1)}%` : 'N/A';
        
        let priorityLabel = 'P3 - INFO';
        let priorityClass = 'severity-info';
        if (sevStr.toLowerCase() === 'critical') {
            priorityLabel = 'P1 - CRITICAL';
            priorityClass = 'severity-critical';
        } else if (sevStr.toLowerCase() === 'warning' || sevStr.toLowerCase() === 'high') {
            priorityLabel = 'P2 - WARNING';
            priorityClass = 'severity-warn';
        }

        return `
            <div class="anomaly-item ${isSelected} ${isCritical}" data-id="${rep.id}" onclick="openAnomalyModal('${rep.id}')" style="cursor: pointer;">
                <div class="anomaly-meta">
                    <span class="badge ${priorityClass}" style="font-size: 8px; font-weight: 800; padding: 1px 4px;">${escapeHtml(priorityLabel)}</span>
                    <span class="anomaly-time">${escapeHtml(formatTime(rep.analyzed_at))}</span>
                </div>
                <div class="anomaly-item-title">${escapeHtml(rep.explanation || 'Anomalous metric deviation detected.')}</div>
                <div class="anomaly-item-footer">
                    <span class="anomaly-item-score">CONSENSUS SCORE: ${scoreDisplay}</span>
                    <button class="btn-diagnose" onclick="event.stopPropagation(); openAnomalyModal('${rep.id}')">DIAGNOSE WITH AI</button>
                </div>
            </div>
        `;
    }).join('');

    // Auto-select latest anomaly if none is selected
    if (selectedAnomalyId === null && anomalies.length > 0) {
        selectAnomaly(anomalies[0].id);
    }
}

// Feed data points into sparkline charts
function updateMetricCharts(events) {
    if (events.length === 0) return;
    
    // Hash latest events to prevent duplicate updates
    const newHash = events.length + '_' + (events[0] ? events[0].id : '');
    if (newHash === lastChartHash) return;
    lastChartHash = newHash;

    // Aggregate statistics
    let totalLatency = 0, latencyCount = 0;
    let maxLoss = 0;
    let totalUtil = 0, utilCount = 0;
    let maxPrefixes = 0;
    let activeLspSet = new Set();
    let totalCrc = 0;

    events.forEach(env => {
        if (!env.event) return;
        
        if (env.event.Lsp) {
            const lsp = env.event.Lsp;
            totalLatency += lsp.latency_us / 1000;
            latencyCount++;
            if (lsp.packet_loss_pct > maxLoss) maxLoss = lsp.packet_loss_pct;
            if (lsp.label_path) activeLspSet.add(lsp.label_path);
        }
        
        if (env.event.Interface) {
            const iface = env.event.Interface;
            totalUtil += iface.utilization_pct;
            utilCount++;
            totalCrc += iface.crc_errors;
        }
        
        if (env.event.Bgp) {
            const bgp = env.event.Bgp;
            if (bgp.affected_prefixes > maxPrefixes) maxPrefixes = bgp.affected_prefixes;
        }
    });

    // Compute averages and update UI sparklines
    const currentLatency = latencyCount > 0 ? totalLatency / latencyCount : 20.0;
    charts.latency.push(currentLatency);
    document.getElementById('val-latency').innerText = `${currentLatency.toFixed(1)} ms`;
    
    const latencyComp = document.getElementById('comp-latency');
    if (currentLatency > 40.0) {
        latencyComp.innerText = `+${(currentLatency - 20.0).toFixed(0)}ms ABOVE BASELINE`;
        latencyComp.className = 'metric-comparison elevated';
    } else {
        latencyComp.innerText = 'NOMINAL (20ms)';
        latencyComp.className = 'metric-comparison normal';
    }

    charts.loss.push(maxLoss);
    document.getElementById('val-loss').innerText = `${maxLoss.toFixed(2)} %`;
    
    const lossComp = document.getElementById('comp-loss');
    if (maxLoss > 1.0) {
        lossComp.innerText = `PACKET LOSS DETECTED`;
        lossComp.className = 'metric-comparison elevated';
    } else {
        lossComp.innerText = 'NOMINAL (0.00%)';
        lossComp.className = 'metric-comparison normal';
    }

    const currentUtil = utilCount > 0 ? totalUtil / utilCount : 50.0;
    charts.bandwidth.push(currentUtil);
    document.getElementById('val-bandwidth').innerText = `${currentUtil.toFixed(1)} %`;
    
    const utilComp = document.getElementById('comp-bandwidth');
    if (currentUtil > 80.0) {
        utilComp.innerText = `LINK OVERUTILIZATION`;
        utilComp.className = 'metric-comparison elevated';
    } else {
        utilComp.innerText = 'NOMINAL (50%)';
        utilComp.className = 'metric-comparison normal';
    }

    const currentPrefixes = maxPrefixes || 1200;
    charts.prefixes.push(currentPrefixes);
    document.getElementById('val-prefixes').innerText = currentPrefixes;
    
    const prefixComp = document.getElementById('comp-prefixes');
    if (currentPrefixes > 1500 || currentPrefixes < 800) {
        prefixComp.innerText = `PREFIX DRIFT DETECTED`;
        prefixComp.className = 'metric-comparison elevated';
    } else {
        prefixComp.innerText = 'NOMINAL (1200)';
        prefixComp.className = 'metric-comparison normal';
    }

    const currentLspCount = activeLspSet.size || 8;
    charts.lsps.push(currentLspCount);
    document.getElementById('val-lsps').innerText = currentLspCount;
    
    const lspComp = document.getElementById('comp-lsps');
    if (currentLspCount < 6) {
        lspComp.innerText = `PATH FLAP / DOWN`;
        lspComp.className = 'metric-comparison elevated';
    } else {
        lspComp.innerText = 'NOMINAL (8)';
        lspComp.className = 'metric-comparison normal';
    }

    charts.errors.push(totalCrc);
    document.getElementById('val-errors').innerText = totalCrc;
    
    const errorComp = document.getElementById('comp-errors');
    if (totalCrc > 0) {
        errorComp.innerText = `${totalCrc} UNRESOLVED ERRORS`;
        errorComp.className = 'metric-comparison elevated';
    } else {
        errorComp.innerText = 'NOMINAL (0)';
        errorComp.className = 'metric-comparison normal';
    }
}

// --- Initialization ---
document.addEventListener('DOMContentLoaded', () => {
    // Clock & Last Updated indicator
    setInterval(() => {
        const now = new Date();
        const timeStr = formatTime(now.toISOString());
        document.getElementById('system-time').innerText = `UTC: ${timeStr}`;
        document.getElementById('last-updated-time').innerText = timeStr;
    }, 1000);
    
    fetchUpdate();
    
    // Poll every 1.5 seconds
    setInterval(fetchUpdate, 1500);

    // Setup Scenario Select handler
    const select = document.getElementById('scenario-select');
    if (select) {
        select.addEventListener('change', (e) => {
            selectScenario(e.target.value);
        });
    }

    // Setup Modal Close handlers
    const modalCloseBtn = document.getElementById('modal-close-btn');
    if (modalCloseBtn) {
        modalCloseBtn.addEventListener('click', closeAnomalyModal);
    }
    const modalOverlay = document.getElementById('diagnostics-modal');
    if (modalOverlay) {
        modalOverlay.addEventListener('click', (e) => {
            if (e.target === modalOverlay) {
                closeAnomalyModal();
            }
        });
    }
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeAnomalyModal();
        }
    });
});
