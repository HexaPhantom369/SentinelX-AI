const numberFormatter = new Intl.NumberFormat();

function setText(id, value) {
    const element = document.getElementById(id);
    if (element) element.textContent = value;
}

function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

function renderAlerts(alerts) {
    const emptyState = document.getElementById("alerts-empty");
    const tableWrap = document.getElementById("alerts-table-wrap");
    const tableBody = document.getElementById("alerts-table-body");
    tableBody.replaceChildren();

    if (!alerts.length) {
        emptyState.hidden = false;
        tableWrap.hidden = true;
        return;
    }

    emptyState.hidden = true;
    tableWrap.hidden = false;
    for (const alert of alerts) {
        const row = document.createElement("tr");
        const title = document.createElement("td");
        const alertTitle = document.createElement("strong");
        alertTitle.className = "alert-rule-name";
        alertTitle.textContent = alert.title;
        const explanation = document.createElement("small");
        explanation.className = "table-subtext alert-explanation";
        explanation.textContent = alert.explanation;
        title.append(alertTitle, explanation);
        const severity = document.createElement("td");
        const severityBadge = document.createElement("span");
        severityBadge.className = `severity-badge severity-badge-${alert.severity}`;
        severityBadge.textContent = alert.severity;
        severity.append(severityBadge);
        const status = document.createElement("td");
        status.textContent = alert.status;
        const rule = document.createElement("td");
        const ruleName = document.createElement("strong");
        ruleName.className = "alert-rule-name";
        ruleName.textContent = alert.rule_id ? `${alert.rule_id} · ${alert.rule_name}` : "—";
        const evidence = document.createElement("small");
        evidence.className = "table-subtext";
        evidence.textContent = `${numberFormatter.format(alert.evidence_count || 0)} evidence events`;
        rule.append(ruleName, evidence);
        const mapping = document.createElement("td");
        if (alert.mitre_technique_id) {
            const technique = document.createElement("span");
            technique.className = "mitre-badge";
            technique.textContent = `${alert.mitre_technique_id} · ${alert.mitre_technique_name}`;
            technique.title = alert.mitre_rationale || "";
            mapping.append(technique);
        } else {
            mapping.textContent = "Not mapped";
        }
        const triggered = document.createElement("td");
        triggered.textContent = formatDate(alert.triggered_at);
        const action = document.createElement("td");
        const solveButton = document.createElement("button");
        solveButton.type = "button";
        solveButton.className = "table-action-button";
        solveButton.dataset.advisorType = "alert";
        solveButton.dataset.advisorId = alert.id;
        solveButton.textContent = "AI Solve";
        const intelButton = document.createElement("button");
        intelButton.type = "button";
        intelButton.className = "table-action-button table-action-button-secondary";
        intelButton.dataset.intelAlert = alert.id;
        intelButton.textContent = "Check IP";
        action.append(solveButton, intelButton);
        row.append(title, severity, rule, mapping, status, triggered, action);
        tableBody.append(row);
    }
}

function renderIncidents(incidents) {
    const emptyState = document.getElementById("incidents-empty");
    const tableWrap = document.getElementById("incidents-table-wrap");
    const tableBody = document.getElementById("incidents-table-body");
    tableBody.replaceChildren();
    if (!incidents.length) {
        emptyState.hidden = false;
        tableWrap.hidden = true;
        return;
    }

    emptyState.hidden = true;
    tableWrap.hidden = false;
    for (const incident of incidents) {
        const row = document.createElement("tr");
        const title = document.createElement("td");
        const titleText = document.createElement("strong");
        titleText.className = "alert-rule-name";
        titleText.textContent = incident.title;
        const id = document.createElement("small");
        id.className = "table-subtext";
        id.textContent = incident.id;
        title.append(titleText, id);

        const severity = document.createElement("td");
        const badge = document.createElement("span");
        badge.className = `severity-badge severity-badge-${incident.severity}`;
        badge.textContent = incident.severity;
        severity.append(badge);

        const state = document.createElement("td");
        const selector = document.createElement("select");
        selector.className = "incident-status-select";
        selector.dataset.incidentId = incident.id;
        selector.dataset.previousStatus = incident.status;
        for (const value of ["New", "Investigating", "Contained", "Resolved"]) {
            const option = document.createElement("option");
            option.value = value;
            option.textContent = value;
            option.selected = incident.status === value;
            selector.append(option);
        }
        state.append(selector);

        const counts = document.createElement("td");
        counts.textContent = `${numberFormatter.format(incident.alert_count)} alerts · ${numberFormatter.format(incident.evidence_count)} events`;
        const updated = document.createElement("td");
        updated.textContent = formatDate(incident.updated_at);
        const action = document.createElement("td");
        const detailsButton = document.createElement("button");
        detailsButton.type = "button";
        detailsButton.className = "table-action-button table-action-button-secondary";
        detailsButton.dataset.incidentDetails = incident.id;
        detailsButton.textContent = "Evidence";
        const solveButton = document.createElement("button");
        solveButton.type = "button";
        solveButton.className = "table-action-button";
        solveButton.dataset.advisorType = "incident";
        solveButton.dataset.advisorId = incident.id;
        solveButton.textContent = "AI Solve";
        action.append(detailsButton, solveButton);
        row.append(title, severity, state, counts, updated, action);
        tableBody.append(row);
    }
}

function renderAdvisor(data) {
    const content = document.getElementById("advisor-content");
    content.replaceChildren();
    const factsTitle = document.createElement("h3");
    factsTitle.textContent = "Observed facts";
    const facts = document.createElement("p");
    facts.className = "advisor-facts";
    const observed = data.observed_facts;
    facts.textContent = `${observed.alert_ids.length} linked alert(s) · ${observed.event_count} evidence event(s) · ${observed.event_types.join(", ") || "No event types"}`;
    content.append(factsTitle, facts);

    const recommendationsTitle = document.createElement("h3");
    recommendationsTitle.textContent = "Recommendations";
    const list = document.createElement("div");
    list.className = "advisor-recommendations";
    for (const recommendation of data.recommendations) {
        const item = document.createElement("article");
        item.className = "advisor-recommendation";
        const heading = document.createElement("strong");
        heading.textContent = recommendation.title;
        const rationale = document.createElement("p");
        rationale.textContent = recommendation.rationale;
        const status = document.createElement("small");
        status.textContent = recommendation.execution_available
            ? "Execution available only through an approved workflow."
            : recommendation.available
                ? "Recommendation only · no action executed"
                : "Unavailable with current evidence · no action executed";
        item.append(heading, rationale, status);
        if (recommendation.recommendation_id) {
            const reference = document.createElement("small");
            reference.className = "recommendation-id";
            reference.textContent = `Recommendation ID: ${recommendation.recommendation_id}`;
            item.append(reference);
        }
        list.append(item);
    }
    content.append(recommendationsTitle, list);
    if (data.mitre_mappings.length) {
        const mappings = document.createElement("p");
        mappings.className = "advisor-mappings";
        mappings.textContent = `MITRE ATT&CK: ${data.mitre_mappings.map((item) => `${item.technique_id} · ${item.technique_name}`).join("; ")}`;
        content.append(mappings);
    }
}

function renderThreatIntel(data) {
    const emptyState = document.getElementById("intel-empty");
    const tableWrap = document.getElementById("intel-table-wrap");
    const tableBody = document.getElementById("intel-table-body");
    tableBody.replaceChildren();
    if (!data.lookups.length) {
        emptyState.hidden = false;
        tableWrap.hidden = true;
        return;
    }
    emptyState.hidden = true;
    tableWrap.hidden = false;
    for (const lookup of data.lookups) {
        const row = document.createElement("tr");
        const ip = document.createElement("td");
        ip.textContent = lookup.indicator_value;
        const provider = document.createElement("td");
        provider.textContent = lookup.provider;
        const score = document.createElement("td");
        if (lookup.reputation_score === null) {
            score.textContent = lookup.error_summary || "Lookup failed";
        } else {
            const badge = document.createElement("span");
            badge.className = `intel-score${lookup.reputation_score >= 70 ? " intel-score-high" : lookup.reputation_score >= 30 ? " intel-score-medium" : ""}`;
            badge.textContent = `${lookup.reputation_score}/100`;
            score.append(badge);
        }
        const summary = document.createElement("td");
        summary.textContent = Object.entries(lookup.summary)
            .filter(([, value]) => value !== null && value !== undefined)
            .map(([key, value]) => `${key.replaceAll("_", " ")}: ${value}`)
            .join(" · ") || "No provider details";
        const date = document.createElement("td");
        date.textContent = formatDate(lookup.looked_up_at);
        row.append(ip, provider, score, summary, date);
        tableBody.append(row);
    }
}

function renderRemediations(data) {
    const emptyState = document.getElementById("remediation-empty");
    const list = document.getElementById("remediation-list");
    list.replaceChildren();
    const recommendations = data.recommendations.filter((item) =>
        item.status === "recommendation_only"
        && (item.execution_status === "not_requested" || item.execution_status === "executing" || item.execution_status === "executed" || item.execution_status === "failed"),
    );
    if (!recommendations.length) {
        emptyState.hidden = false;
        return;
    }

    emptyState.hidden = true;
    for (const recommendation of recommendations) {
        const card = document.createElement("article");
        card.className = "remediation-card";
        const heading = document.createElement("div");
        heading.className = "remediation-card-heading";
        const title = document.createElement("strong");
        title.textContent = recommendation.title;
        const status = document.createElement("span");
        const isActive = recommendation.execution_status === "executed"
            && recommendation.firewall_removal_status === "not_requested";
        const actionFailed = recommendation.execution_status === "failed"
            || recommendation.firewall_removal_status === "failed";
        const actionInProgress = recommendation.execution_status === "executing"
            || recommendation.firewall_removal_status === "removing";
        status.className = `remediation-state ${isActive ? "remediation-state-active" : actionFailed ? "remediation-state-failed" : "remediation-state-pending"}`;
        status.textContent = isActive
            ? "Firewall block active"
            : recommendation.firewall_removal_status === "removed"
                ? "Firewall block rolled back"
                : recommendation.firewall_removal_status === "failed"
                    ? "Rollback failed · inspect firewall"
                    : recommendation.execution_status === "failed"
                        ? "Execution failed · inspect audit"
                        : actionInProgress
                            ? "Firewall action in progress"
                            : "Pending approval";
        heading.append(title, status);
        const details = document.createElement("p");
        details.className = "remediation-target";
        const sourceIp = recommendation.target.source_ip || "No eligible target";
        const technique = recommendation.mitre_technique_id
            ? `${recommendation.mitre_technique_id}${recommendation.mitre_technique_name ? ` · ${recommendation.mitre_technique_name}` : ""}`
            : "No ATT&CK mapping";
        details.textContent = `${sourceIp} · ${technique} · ${recommendation.subject_title || recommendation.subject_type}`;
        const rationale = document.createElement("p");
        rationale.className = "remediation-rationale";
        rationale.textContent = recommendation.rationale;
        const actions = document.createElement("div");
        actions.className = "remediation-actions";
        if (recommendation.execution_status === "not_requested" && recommendation.target.available === true) {
            const approve = document.createElement("button");
            approve.type = "button";
            approve.className = "table-action-button";
            approve.dataset.remediationOperation = "approve";
            approve.dataset.remediationId = recommendation.id;
            approve.dataset.remediationIp = sourceIp;
            approve.textContent = "Approve Block";
            actions.append(approve);
        }
        if (isActive) {
            const rollback = document.createElement("button");
            rollback.type = "button";
            rollback.className = "danger-button";
            rollback.dataset.remediationOperation = "remove";
            rollback.dataset.remediationId = recommendation.id;
            rollback.dataset.remediationIp = sourceIp;
            rollback.textContent = "Rollback Rule";
            actions.append(rollback);
        }
        card.append(heading, details, rationale, actions);
        list.append(card);
    }
}

function renderSettings(data) {
    const provider = data.threat_intel;
    document.getElementById("intel-provider").value = provider.provider;
    document.getElementById("intel-enabled").checked = provider.enabled;
    const selected = provider.providers.find((item) => item.id === provider.provider);
    const status = provider.enabled
        ? provider.configured
            ? `${selected.name} is enabled and configured. Lookups are user-triggered.`
            : `${selected.name} is enabled but its API key is missing.`
        : "Threat intelligence lookups are disabled.";
    setText("intel-provider-status", status);
    setText(
        "host-monitor-status",
        data.host_monitor.agent_token_configured
            ? "Agent token is configured. The collector endpoint requires loopback and bearer-token validation."
            : "Agent is not configured. Set SENTINELX_AGENT_TOKEN in the SentinelX server environment.",
    );
}

function renderAudit(data) {
    const emptyState = document.getElementById("audit-empty");
    const tableWrap = document.getElementById("audit-table-wrap");
    const tableBody = document.getElementById("audit-table-body");
    tableBody.replaceChildren();
    if (!data.entries.length) {
        emptyState.hidden = false;
        tableWrap.hidden = true;
    } else {
        emptyState.hidden = true;
        tableWrap.hidden = false;
        for (const entry of data.entries) {
            const row = document.createElement("tr");
            for (const value of [
                formatDate(entry.created_at),
                entry.action,
                `${entry.entity_type}${entry.entity_id ? ` · ${entry.entity_id}` : ""}`,
                JSON.stringify(entry.details),
                entry.chain_valid ? "Verified" : "INVALID",
            ]) {
                const cell = document.createElement("td");
                cell.textContent = value;
                if (value === "Verified" || value === "INVALID") {
                    cell.className = value === "Verified" ? "audit-valid" : "audit-invalid";
                }
                row.append(cell);
            }
            tableBody.append(row);
        }
    }
    const verification = data.verification;
    const headerBadge = document.getElementById("audit-header-badge");
    headerBadge.className = `audit-header-badge ${verification.valid ? "audit-header-valid" : "audit-header-invalid"}`;
    headerBadge.textContent = verification.valid
        ? "Audit Chain: Cryptographically Verified"
        : "Audit Chain: Integrity Failure";
    headerBadge.title = verification.valid
        ? `SHA-256 chain valid · ${numberFormatter.format(verification.records_checked)} records checked. Tamper-evident local record, not an external signature.`
        : `Integrity failure in records: ${verification.invalid_records.join(", ")}`;
    showMessage(
        "audit-status",
        verification.valid
            ? `Chain valid · ${numberFormatter.format(verification.records_checked)} records checked through #${verification.verified_through_id}.`
            : `Chain integrity failure · ${verification.invalid_records.join(", ")}.`,
        verification.valid ? "success" : "error",
    );
}

function renderRules(rules) {
    const emptyState = document.getElementById("rules-empty");
    const tableWrap = document.getElementById("rules-table-wrap");
    const tableBody = document.getElementById("rules-table-body");
    tableBody.replaceChildren();
    if (!rules.length) {
        emptyState.textContent = "No detection rules are configured.";
        emptyState.hidden = false;
        tableWrap.hidden = true;
        return;
    }

    emptyState.hidden = true;
    tableWrap.hidden = false;
    for (const rule of rules) {
        const row = document.createElement("tr");
        const ruleCell = document.createElement("td");
        const ruleId = document.createElement("strong");
        ruleId.className = "alert-rule-name";
        ruleId.textContent = `${rule.rule_id} · ${rule.name}`;
        const enabled = document.createElement("small");
        enabled.className = "table-subtext";
        enabled.textContent = rule.enabled ? "Enabled" : "Disabled";
        ruleCell.append(ruleId, enabled);
        const description = document.createElement("td");
        const descriptionText = document.createElement("span");
        descriptionText.textContent = rule.description;
        const nextSteps = document.createElement("small");
        nextSteps.className = "table-subtext";
        try {
            const steps = JSON.parse(rule.recommended_steps_json);
            nextSteps.textContent = Array.isArray(steps) && steps.length
                ? `Investigation: ${steps.join(" · ")}`
                : "No investigation steps configured";
        } catch {
            nextSteps.textContent = "Investigation guidance unavailable";
        }
        const threshold = document.createElement("small");
        threshold.className = "table-subtext";
        try {
            const values = Object.entries(JSON.parse(rule.config_json));
            threshold.textContent = values.length
                ? `Thresholds: ${values.map(([key, value]) => `${key.replaceAll("_", " ")} ${value}`).join(" · ")}`
                : "Explicit event-type match";
        } catch {
            threshold.textContent = "Threshold configuration invalid";
        }
        description.append(descriptionText, threshold, nextSteps);
        const severity = document.createElement("td");
        const badge = document.createElement("span");
        badge.className = `severity-badge severity-badge-${rule.severity}`;
        badge.textContent = rule.severity;
        severity.append(badge);
        const mapping = document.createElement("td");
        if (rule.mitre_technique_id) {
            const technique = document.createElement("span");
            technique.className = "mitre-badge";
            technique.textContent = `${rule.mitre_technique_id} · ${rule.mitre_technique_name}`;
            technique.title = rule.mitre_rationale || "";
            mapping.append(technique);
        } else {
            mapping.textContent = "Not mapped";
        }
        row.append(ruleCell, description, severity, mapping);
        tableBody.append(row);
    }
}

function renderEvents(events) {
    const emptyState = document.getElementById("events-empty");
    const tableWrap = document.getElementById("events-table-wrap");
    const tableBody = document.getElementById("events-table-body");
    tableBody.replaceChildren();

    if (!events.length) {
        emptyState.hidden = false;
        tableWrap.hidden = true;
        return;
    }

    emptyState.hidden = true;
    tableWrap.hidden = false;
    for (const event of events) {
        const row = document.createElement("tr");
        for (const value of [
            formatDate(event.observed_at),
            event.event_type,
            event.outcome,
            event.username || "—",
            event.source_ip || "—",
            event.host_name || "—",
        ]) {
            const cell = document.createElement("td");
            cell.textContent = value;
            row.append(cell);
        }
        tableBody.append(row);
    }
}

function renderDashboard(data) {
    const stats = data.stats;
    const priorityAlerts = stats.critical_alerts + stats.high_alerts;
    setText("metric-events", numberFormatter.format(stats.security_events));
    setText("metric-alerts", numberFormatter.format(stats.alerts));
    setText("metric-priority", numberFormatter.format(priorityAlerts));
    setText("metric-critical", numberFormatter.format(stats.critical_alerts));
    setText("metric-high", numberFormatter.format(stats.high_alerts));
    setText("metric-incidents", numberFormatter.format(stats.open_incidents));
    setText("activity-count", numberFormatter.format(stats.security_events));
    setText("activity-rules", numberFormatter.format(stats.enabled_rules));
    setText("updated-at", `Updated ${formatDate(data.generated_at)}`);
    setText("ingestion-status", data.ingestion.status === "not_configured" ? "Not configured" : data.ingestion.status);
    if (data.ingestion.finished_at) {
        setText(
            "ingestion-detail",
            `${numberFormatter.format(data.ingestion.records_imported)} imported · ${numberFormatter.format(data.ingestion.records_duplicate)} duplicates · ${formatDate(data.ingestion.finished_at)}`,
        );
    }
    setText("ai-status", data.ai_analysis.status === "not_configured" ? "Not configured" : data.ai_analysis.status);

    const hasActivity = stats.security_events > 0 || stats.enabled_rules > 0;
    document.getElementById("activity-empty").hidden = hasActivity;
    document.getElementById("activity-summary").hidden = !hasActivity;
    renderAlerts(data.recent_alerts);
    renderEvents(data.recent_events);
}

function showMessage(elementId, message, kind) {
    const element = document.getElementById(elementId);
    element.textContent = message;
    element.className = `ingestion-message ingestion-message-${kind}`;
    element.hidden = false;
}

function showIngestionMessage(message, kind) {
    showMessage("ingestion-message", message, kind);
}

function renderIngestionErrors(errors) {
    const container = document.getElementById("ingestion-errors");
    container.replaceChildren();
    if (!errors.length) {
        container.hidden = true;
        return;
    }
    const heading = document.createElement("strong");
    heading.textContent = "Validation details";
    const list = document.createElement("ul");
    for (const error of errors) {
        const item = document.createElement("li");
        if (typeof error === "string") {
            item.textContent = error;
        } else {
            const prefix = error.record ? `Record ${error.record}: ` : "";
            item.textContent = `${prefix}${error.message}`;
        }
        list.append(item);
    }
    container.append(heading, list);
    container.hidden = false;
}

async function submitIngestion(event) {
    event.preventDefault();
    const fileInput = document.getElementById("log-file");
    const submitButton = document.getElementById("ingestion-submit");
    const file = fileInput.files[0];
    if (!file) {
        showIngestionMessage("Choose a JSON or CSV file first.", "error");
        return;
    }

    submitButton.disabled = true;
    submitButton.textContent = "Validating…";
    document.getElementById("ingestion-errors").hidden = true;
    showIngestionMessage("Validating and importing records…", "pending");
    try {
        const response = await fetch("/api/ingest", {
            method: "POST",
            body: new FormData(document.getElementById("ingestion-form")),
            headers: { Accept: "application/json" },
        });
        const result = await response.json();
        if (!response.ok && !result.data) {
            throw new Error(result.error?.message || "The file could not be imported.");
        }
        const job = result.data;
        const summary = `${job.status === "failed" ? "Import failed" : "Import complete"}: ${numberFormatter.format(job.records_imported)} imported, ${numberFormatter.format(job.records_rejected)} rejected, ${numberFormatter.format(job.records_duplicate)} duplicates.`;
        showIngestionMessage(summary, job.status === "failed" ? "error" : job.status === "partial" ? "warning" : "success");
        renderIngestionErrors(job.errors);
        await loadDashboard();
        if (job.status === "completed") {
            fileInput.value = "";
            setText("file-picker-label", "Choose a JSON or CSV file");
        }
    } catch (error) {
        showIngestionMessage(error.message, "error");
    } finally {
        submitButton.disabled = false;
        submitButton.textContent = "Validate and import";
    }
}

async function loadDashboard() {
    try {
        const [dashboardResponse, healthResponse, rulesResponse, incidentsResponse, intelResponse, settingsResponse, auditResponse, remediationResponse] = await Promise.all([
            fetch("/api/dashboard", { headers: { Accept: "application/json" } }),
            fetch("/api/health", { headers: { Accept: "application/json" } }),
            fetch("/api/detections/rules", { headers: { Accept: "application/json" } }),
            fetch("/api/incidents", { headers: { Accept: "application/json" } }),
            fetch("/api/threat-intel", { headers: { Accept: "application/json" } }),
            fetch("/api/settings", { headers: { Accept: "application/json" } }),
            fetch("/api/audit", { headers: { Accept: "application/json" } }),
            fetch("/api/remediation", { headers: { Accept: "application/json" } }),
        ]);
        if ([dashboardResponse, healthResponse, rulesResponse, incidentsResponse, intelResponse, settingsResponse, auditResponse, remediationResponse].some((response) => !response.ok)) {
            throw new Error("The local service could not load dashboard data.");
        }
        const dashboard = await dashboardResponse.json();
        const health = await healthResponse.json();
        const rules = await rulesResponse.json();
        const incidents = await incidentsResponse.json();
        const intel = await intelResponse.json();
        const settings = await settingsResponse.json();
        const audit = await auditResponse.json();
        const remediations = await remediationResponse.json();
        renderDashboard(dashboard.data);
        renderRules(rules.data.rules);
        renderIncidents(incidents.data.incidents);
        renderThreatIntel(intel.data);
        renderSettings(settings.data);
        renderAudit(audit.data);
        renderRemediations(remediations.data);
        setText("sidebar-health", health.data.status === "ok" ? "Service operational" : "Service unavailable");
        setText("service-status", health.data.status === "ok" ? "Operational" : "Unavailable");
        setText("database-status", health.data.database === "connected" ? "Connected" : "Unavailable");
        document.getElementById("dashboard-error").hidden = true;
    } catch (error) {
        setText("sidebar-health", "Connection unavailable");
        setText("service-status", "Unavailable");
        setText("database-status", "Unavailable");
        setText("dashboard-error-message", error.message);
        document.getElementById("dashboard-error").hidden = false;
    }
}

async function submitThreatIntelSettings(event) {
    event.preventDefault();
    const provider = document.getElementById("intel-provider").value;
    const enabled = document.getElementById("intel-enabled").checked;
    try {
        const response = await fetch("/api/settings/threat-intel", {
            method: "PUT",
            headers: { Accept: "application/json", "Content-Type": "application/json", "X-SentinelX-Request": "1" },
            body: JSON.stringify({ provider, enabled: provider === "disabled" ? false : enabled }),
        });
        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.error?.message || "Provider settings could not be saved.");
        }
        showMessage("intel-message", "Provider settings saved and audit-logged.", "success");
        await loadDashboard();
    } catch (error) {
        showMessage("intel-message", error.message, "error");
    }
}

async function testThreatIntelProvider() {
    const isMock = document.getElementById("intel-provider").value === "mock";
    const confirmation = isMock
        ? "Test the mock provider with a synthetic neutral result? No IP will leave this application."
        : "This sends the fixed public test IP 8.8.8.8 to your selected external provider. Continue?";
    if (!window.confirm(confirmation)) return;
    const button = document.getElementById("test-intel-provider");
    button.disabled = true;
    try {
        const response = await fetch("/api/settings/threat-intel/test", {
            method: "POST",
            headers: { Accept: "application/json", "X-SentinelX-Request": "1" },
        });
        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.error?.message || "Provider test failed.");
        }
        showMessage(
            "intel-message",
            `${result.data.provider} connected; test IP score ${result.data.score}/100. Audit entry recorded.`,
            "success",
        );
        await loadDashboard();
    } catch (error) {
        showMessage("intel-message", error.message, "error");
    } finally {
        button.disabled = false;
    }
}

async function enrichThreatIntel(subjectType, subjectId, triggerButton) {
    if (!window.confirm("This may send globally routable source IP addresses from alert evidence to the selected external reputation provider. Continue?")) return;
    const button = triggerButton || document.getElementById("enrich-observed-ips");
    button.disabled = true;
    try {
        const payload = subjectId ? { subject_type: subjectType, subject_id: subjectId } : {};
        const response = await fetch("/api/threat-intel/enrich", {
            method: "POST",
            headers: { Accept: "application/json", "Content-Type": "application/json", "X-SentinelX-Request": "1" },
            body: JSON.stringify(payload),
        });
        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.error?.message || "Threat intelligence enrichment failed.");
        }
        const { results, skipped } = result.data;
        showMessage(
            "intel-message",
            `Lookup finished: ${results.filter((item) => item.status !== "failed").length} completed/cached, ${results.filter((item) => item.status === "failed").length} failed, ${skipped.length} skipped.`,
            results.some((item) => item.status === "failed") ? "warning" : "success",
        );
        await loadDashboard();
    } catch (error) {
        showMessage("intel-message", error.message, "error");
    } finally {
        button.disabled = false;
    }
}

async function verifyAuditChain(buttonId = "verify-audit") {
    const button = document.getElementById(buttonId);
    button.disabled = true;
    try {
        const response = await fetch("/api/audit/verify", {
            headers: { Accept: "application/json" },
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error?.message || "Audit verification failed.");
        const historyResponse = await fetch("/api/audit", { headers: { Accept: "application/json" } });
        if (!historyResponse.ok) throw new Error("Audit verification ran, but the history could not be reloaded.");
        const history = await historyResponse.json();
        renderAudit({
            verification: result.data,
            entries: history.data.entries,
        });
    } catch (error) {
        showMessage("audit-status", error.message, "error");
    } finally {
        button.disabled = false;
    }
}

async function groupIncidents() {
    const button = document.getElementById("group-incidents");
    button.disabled = true;
    button.textContent = "Grouping alerts…";
    try {
        const response = await fetch("/api/incidents/group", {
            method: "POST",
            headers: { Accept: "application/json" },
        });
        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.error?.message || "Incident grouping failed.");
        }
        const data = result.data;
        showMessage(
            "incident-message",
            `Grouping complete: ${data.incidents_created} created, ${data.incidents_updated} updated, ${data.groups_unchanged} unchanged.`,
            "success",
        );
        await loadDashboard();
    } catch (error) {
        showMessage("incident-message", error.message, "error");
    } finally {
        button.disabled = false;
        button.textContent = "Group related alerts";
    }
}

async function updateIncidentStatus(select) {
    const previous = select.dataset.previousStatus;
    try {
        const response = await fetch(`/api/incidents/${encodeURIComponent(select.dataset.incidentId)}`, {
            method: "PATCH",
            headers: { Accept: "application/json", "Content-Type": "application/json" },
            body: JSON.stringify({ status: select.value }),
        });
        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.error?.message || "Incident status could not be updated.");
        }
        select.dataset.previousStatus = result.data.status;
        showMessage("incident-message", `Incident state updated to ${result.data.status}.`, "success");
        await loadDashboard();
    } catch (error) {
        select.value = previous;
        showMessage("incident-message", error.message, "error");
    }
}

async function runAdvisor(type, id, button) {
    const dialog = document.getElementById("advisor-dialog");
    const content = document.getElementById("advisor-content");
    content.replaceChildren();
    const loading = document.createElement("p");
    loading.textContent = "Assessing linked evidence…";
    content.append(loading);
    dialog.showModal();
    button.disabled = true;
    try {
        const response = await fetch("/api/remediation/run-advisor", {
            method: "POST",
            headers: { Accept: "application/json", "Content-Type": "application/json", "X-SentinelX-Request": "1" },
            body: JSON.stringify({ subject_type: type, subject_id: id }),
        });
        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.error?.message || "Recommendations could not be generated.");
        }
        renderAdvisor(result.data);
        await loadDashboard();
    } catch (error) {
        content.replaceChildren();
        const message = document.createElement("p");
        message.className = "advisor-error";
        message.textContent = error.message;
        content.append(message);
    } finally {
        button.disabled = false;
    }
}

async function showIncidentDetails(incidentId, button) {
    const dialog = document.getElementById("incident-dialog");
    const content = document.getElementById("incident-detail-content");
    const title = document.getElementById("incident-dialog-title");
    content.replaceChildren();
    const loading = document.createElement("p");
    loading.textContent = "Loading linked evidence…";
    content.append(loading);
    dialog.showModal();
    button.disabled = true;
    try {
        const response = await fetch(`/api/incidents/${encodeURIComponent(incidentId)}`, {
            headers: { Accept: "application/json" },
        });
        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.error?.message || "Incident details could not be loaded.");
        }
        const incident = result.data.incident;
        title.textContent = incident.title;
        content.replaceChildren();
        const summary = document.createElement("p");
        summary.className = "advisor-facts";
        summary.textContent = `${incident.status} · ${incident.severity} · ${result.data.alerts.length} linked alert(s)`;
        const timelineTitle = document.createElement("h3");
        timelineTitle.textContent = "Evidence timeline";
        const list = document.createElement("div");
        list.className = "incident-timeline";
        for (const entry of result.data.timeline) {
            const item = document.createElement("article");
            item.className = "incident-timeline-item";
            const label = document.createElement("strong");
            label.textContent = entry.type === "event"
                ? `${entry.data.event_type} · ${entry.data.outcome}`
                : entry.type === "alert"
                    ? entry.data.title
                    : "Investigation note";
            const timestamp = document.createElement("time");
            timestamp.dateTime = entry.timestamp;
            timestamp.textContent = formatDate(entry.timestamp);
            const detail = document.createElement("p");
            if (entry.type === "event") {
                detail.textContent = [
                    entry.data.username && `Account: ${entry.data.username}`,
                    entry.data.source_ip && `Source: ${entry.data.source_ip}`,
                    entry.data.host_name && `Host: ${entry.data.host_name}`,
                ].filter(Boolean).join(" · ") || "No additional event fields";
            } else if (entry.type === "alert") {
                detail.textContent = entry.data.explanation;
            } else {
                detail.textContent = entry.data.body;
            }
            item.append(label, timestamp, detail);
            list.append(item);
        }
        if (!result.data.timeline.length) {
            const empty = document.createElement("p");
            empty.className = "advisor-facts";
            empty.textContent = "No linked evidence or investigation notes are available.";
            list.append(empty);
        }
        content.append(summary, timelineTitle, list);
    } catch (error) {
        content.replaceChildren();
        const message = document.createElement("p");
        message.className = "advisor-error";
        message.textContent = error.message;
        content.append(message);
    } finally {
        button.disabled = false;
    }
}

async function runDetections() {
    const button = document.getElementById("run-detections");
    button.disabled = true;
    button.textContent = "Evaluating rules…";
    showMessage("detection-message", "Evaluating enabled rules against stored events…", "pending");
    try {
        const response = await fetch("/api/detection/run", {
            method: "POST",
            headers: { Accept: "application/json" },
        });
        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.error?.message || "Detection run could not be completed.");
        }
        const data = result.data;
        showMessage(
            "detection-message",
            `Evaluated ${numberFormatter.format(data.rules_evaluated)} rules against ${numberFormatter.format(data.events_evaluated)} events: ${numberFormatter.format(data.matches_found)} matches, ${numberFormatter.format(data.alerts_created)} new alerts.`,
            "success",
        );
        await loadDashboard();
    } catch (error) {
        showMessage("detection-message", error.message, "error");
    } finally {
        button.disabled = false;
        button.textContent = "Run detection rules";
    }
}

function openRemediationConfirmation(button) {
    const dialog = document.getElementById("remediation-confirm-dialog");
    const operation = button.dataset.remediationOperation;
    const ip = button.dataset.remediationIp;
    document.getElementById("remediation-confirm-title").textContent =
        operation === "approve" ? "Approve firewall block" : "Roll back firewall rule";
    document.getElementById("remediation-confirm-warning").textContent =
        operation === "approve"
            ? `This adds a Windows Firewall inbound block for ${ip}. It may interrupt legitimate connections from this address.`
            : `This removes the SentinelX-managed Windows Firewall rule for ${ip}.`;
    setText("remediation-confirm-target", ip);
    const input = document.getElementById("remediation-confirm-ip");
    input.value = "";
    input.dataset.actionId = button.dataset.remediationId;
    input.dataset.operation = operation;
    input.dataset.expectedIp = ip;
    input.dataset.requestFailed = "false";
    document.getElementById("remediation-confirm-submit").disabled = true;
    document.getElementById("remediation-confirm-submit").textContent =
        operation === "approve" ? "Confirm block" : "Confirm rollback";
    document.getElementById("remediation-confirm-error").hidden = true;
    dialog.showModal();
    input.focus();
}

async function submitRemediationConfirmation() {
    const input = document.getElementById("remediation-confirm-ip");
    const submit = document.getElementById("remediation-confirm-submit");
    const actionId = input.dataset.actionId;
    const operation = input.dataset.operation;
    const dialog = document.getElementById("remediation-confirm-dialog");
    submit.disabled = true;
    submit.textContent = operation === "approve" ? "Applying block…" : "Rolling back…";
    try {
        const response = await fetch(`/api/remediation/${operation}/${encodeURIComponent(actionId)}`, {
            method: "POST",
            headers: { Accept: "application/json", "Content-Type": "application/json", "X-SentinelX-Request": "1" },
            body: JSON.stringify({ confirm_ip: input.value }),
        });
        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.error?.message || "The firewall action was rejected.");
        }
        dialog.close();
        showMessage(
            "remediation-message",
            operation === "approve"
                ? `Firewall block added for ${result.data.source_ip}; approval and result were audit-logged.`
                : `SentinelX firewall rule removed for ${result.data.source_ip}; rollback was audit-logged.`,
            "success",
        );
        await loadDashboard();
    } catch (error) {
        const message = document.getElementById("remediation-confirm-error");
        message.textContent = error.message;
        message.hidden = false;
        input.dataset.requestFailed = "true";
        await loadDashboard();
    } finally {
        submit.textContent = operation === "approve" ? "Confirm block" : "Confirm rollback";
        submit.disabled = input.value !== input.dataset.expectedIp
            || input.dataset.requestFailed === "true";
    }
}

document.getElementById("current-year").textContent = new Date().getFullYear();
document.getElementById("ingestion-form").addEventListener("submit", submitIngestion);
document.getElementById("log-file").addEventListener("change", (event) => {
    const file = event.target.files[0];
    setText("file-picker-label", file ? file.name : "Choose a JSON or CSV file");
});
document.getElementById("run-detections").addEventListener("click", runDetections);
document.getElementById("group-incidents").addEventListener("click", groupIncidents);
document.getElementById("intel-settings-form").addEventListener("submit", submitThreatIntelSettings);
document.getElementById("test-intel-provider").addEventListener("click", testThreatIntelProvider);
document.getElementById("enrich-observed-ips").addEventListener("click", () => enrichThreatIntel());
document.getElementById("verify-audit").addEventListener("click", () => verifyAuditChain("verify-audit"));
document.getElementById("audit-header-verify").addEventListener("click", () => verifyAuditChain("audit-header-verify"));
document.getElementById("remediation-confirm-ip").addEventListener("input", (event) => {
    document.getElementById("remediation-confirm-submit").disabled =
        event.target.value !== event.target.dataset.expectedIp
        || event.target.dataset.requestFailed === "true";
});
document.getElementById("remediation-confirm-submit").addEventListener("click", submitRemediationConfirmation);
document.getElementById("remediation-confirm-close").addEventListener("click", () => {
    document.getElementById("remediation-confirm-dialog").close();
});
document.getElementById("remediation-confirm-cancel").addEventListener("click", () => {
    document.getElementById("remediation-confirm-dialog").close();
});
document.getElementById("advisor-close").addEventListener("click", () => {
    document.getElementById("advisor-dialog").close();
});
document.getElementById("incident-close").addEventListener("click", () => {
    document.getElementById("incident-dialog").close();
});
document.addEventListener("click", (event) => {
    const remediationButton = event.target.closest("[data-remediation-operation]");
    if (remediationButton) openRemediationConfirmation(remediationButton);
    const button = event.target.closest("[data-advisor-type]");
    if (button) runAdvisor(button.dataset.advisorType, button.dataset.advisorId, button);
    const detailsButton = event.target.closest("[data-incident-details]");
    if (detailsButton) showIncidentDetails(detailsButton.dataset.incidentDetails, detailsButton);
    const intelButton = event.target.closest("[data-intel-alert]");
    if (intelButton) enrichThreatIntel("alert", intelButton.dataset.intelAlert, intelButton);
});
document.addEventListener("change", (event) => {
    if (event.target.matches(".incident-status-select")) updateIncidentStatus(event.target);
});
loadDashboard();
