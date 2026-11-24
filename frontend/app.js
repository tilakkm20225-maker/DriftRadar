
const $ = (id) => document.getElementById(id);
const api = "";

function setFeedback(id, message, type = "") {
  const node = $(id);
  if (!node) return;
  node.textContent = message;
  node.className = `feedback ${type}`;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  }[c]));
}

async function request(url, options = {}) {
  const response = await fetch(api + url, options);
  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const detail = typeof data.detail === "string"
      ? data.detail
      : JSON.stringify(data.detail || data);

    throw new Error(detail || `Request failed (${response.status})`);
  }

  return data;
}

// =====================================
// M1 - DRIFT DETECTION
// =====================================

async function loadHealth() {
  try {
    const data = await request("/api/health");
    $("connection").textContent = `Connected · ${data.version}`;
  } catch {
    $("connection").textContent = "Unavailable";
  }
}

async function loadBaselines() {
  const rows = await request("/api/baselines");

  $("baselineCount").textContent = rows.length;

  const select = $("baselineSelect");
  const previous = select.value;

  select.innerHTML =
    '<option value="">Choose a baseline…</option>' +
    rows.map(row => `
      <option value="${escapeHtml(row.baseline_id)}">
        ${escapeHtml(row.name)} · ${row.sample_count} rows
      </option>
    `).join("");

  if (rows.some(row => row.baseline_id === previous)) {
    select.value = previous;
  }
}

async function loadHistory() {
  const rows = await request("/api/analyses");

  $("analysisCount").textContent = rows.length;

  $("latestStatus").textContent = rows.length
    ? rows[0].overall_status.replaceAll("_", " ")
    : "No analyses";

  $("latestStatus").className =
    `status-text ${rows.length && rows[0].drifted_features ? "bad" : "good"}`;

  $("historyBody").innerHTML = rows.length
    ? rows.map(row => `
        <tr>
          <td>${escapeHtml(row.analysis_id.slice(0, 12))}…</td>
          <td>${escapeHtml(row.baseline_id.slice(0, 12))}…</td>
          <td class="${row.drifted_features ? "bad" : "good"}">
            ${escapeHtml(row.overall_status)}
          </td>
          <td>${row.drifted_features}/${row.total_features}</td>
          <td>${escapeHtml(new Date(row.created_at).toLocaleString())}</td>
        </tr>
      `).join("")
    : '<tr><td colspan="5" class="empty">No history yet.</td></tr>';
}

function renderResult(result) {
  $("resultPill").textContent =
    result.overall_status.replaceAll("_", " ");

  $("resultPill").className =
    `tag ${result.drifted_features ? "bad" : "good"}`;

  $("interpretation").textContent = result.interpretation;

  $("resultsBody").innerHTML = result.results.map(row => `
    <tr>
      <td>${escapeHtml(row.feature)}</td>
      <td>${row.psi.toFixed(5)}</td>
      <td>${row.ks_statistic.toFixed(5)}</td>
      <td>${row.ks_p_value.toExponential(2)}</td>
      <td class="${row.drift_detected ? "bad" : "good"}">
        ${row.drift_detected ? "Drift signal" : "No signal"}
      </td>
    </tr>
  `).join("");
}

// =====================================
// M2 - MODEL RELIABILITY
// =====================================

function parseLabels(value) {
  const cleaned = value.trim();

  if (!cleaned) {
    throw new Error("Please enter the labels.");
  }

  const parts = cleaned.split(/[\s,;]+/).filter(Boolean);

  if (!parts.every(value => value === "0" || value === "1")) {
    throw new Error("Labels must contain only 0 and 1.");
  }

  return parts.map(Number);
}

function formatPercentage(value) {
  return `${(value * 100).toFixed(1)}%`;
}

function renderReliabilityResult(result) {
  $("metricPrecision").textContent =
    formatPercentage(result.precision);

  $("metricRecall").textContent =
    formatPercentage(result.recall);

  $("metricF1").textContent =
    formatPercentage(result.f1_score);

  $("metricFPR").textContent =
    formatPercentage(result.false_positive_rate);

  $("metricAccuracy").textContent =
    formatPercentage(result.accuracy);

  const matrix = result.confusion_matrix;

  $("matrixTP").textContent = matrix.true_positives;
  $("matrixTN").textContent = matrix.true_negatives;
  $("matrixFP").textContent = matrix.false_positives;
  $("matrixFN").textContent = matrix.false_negatives;
}

async function loadReliabilityHistory() {
  const rows = await request("/api/reliability/history");

  const body = $("reliabilityHistoryBody");
  if (!body) return;

  body.innerHTML = rows.length
    ? rows.map(row => `
        <tr>
          <td>${escapeHtml(row.model_version)}</td>
          <td>${row.sample_count}</td>
          <td>${formatPercentage(row.precision)}</td>
          <td>${formatPercentage(row.recall)}</td>
          <td>${formatPercentage(row.f1_score)}</td>
          <td>${formatPercentage(row.false_positive_rate)}</td>
          <td>${formatPercentage(row.accuracy)}</td>
          <td>${escapeHtml(
            row.created_at
              ? new Date(row.created_at).toLocaleString()
              : "Unknown"
          )}</td>
        </tr>
      `).join("")
    : '<tr><td colspan="8" class="empty">No reliability evaluations yet.</td></tr>';
}

async function refreshReliability() {
  try {
    await loadReliabilityHistory();
  } catch (error) {
    console.error("Could not load reliability history:", error);
  }
}

// =====================================
// FORM HANDLERS
// =====================================

$("baselineForm").addEventListener("submit", async event => {
  event.preventDefault();

  const form = event.currentTarget;
  const file = $("baselineFile").files[0];

  if (!file) return;

  const body = new FormData();
  body.append("name", $("baselineName").value);
  body.append("file", file);

  setFeedback(
    "baselineFeedback",
    "Uploading and validating CSV…"
  );

  try {
    const result = await request("/api/baselines", {
      method: "POST",
      body
    });

    setFeedback(
      "baselineFeedback",
      `Baseline registered: ${result.feature_count} features, ${result.sample_count} rows.`,
      "success"
    );

    form.reset();

    await refresh();

    $("baselineSelect").value = result.baseline_id;
  } catch (error) {
    setFeedback("baselineFeedback", error.message, "error");
  }
});

$("analysisForm").addEventListener("submit", async event => {
  event.preventDefault();

  const baselineId = $("baselineSelect").value;
  const file = $("currentFile").files[0];

  if (!baselineId || !file) {
    return setFeedback(
      "analysisFeedback",
      "Select a baseline and CSV file.",
      "error"
    );
  }

  const body = new FormData();
  body.append("file", file);

  setFeedback(
    "analysisFeedback",
    "Analyzing feature distributions…"
  );

  try {
    const result = await request(
      `/api/baselines/${encodeURIComponent(baselineId)}/analyze`,
      {
        method: "POST",
        body
      }
    );

    setFeedback(
      "analysisFeedback",
      `Analysis complete · ${result.drifted_features} of ${result.total_features} features flagged.`,
      "success"
    );

    renderResult(result);

    $("currentFile").value = "";

    await loadHistory();
  } catch (error) {
    setFeedback("analysisFeedback", error.message, "error");
  }
});

// M2 reliability evaluation form
const reliabilityForm = $("reliabilityForm");

if (reliabilityForm) {
  reliabilityForm.addEventListener("submit", async event => {
    event.preventDefault();

    try {
      const modelVersion = $("modelVersion").value.trim();

      if (!modelVersion) {
        throw new Error("Enter a model version.");
      }

      const yTrue = parseLabels($("trueLabels").value);
      const yPred = parseLabels($("predictedLabels").value);

      if (yTrue.length !== yPred.length) {
        throw new Error(
          "Actual and predicted labels must have equal lengths."
        );
      }

      if (yTrue.length < 20) {
        throw new Error(
          "Enter at least 20 actual and predicted labels."
        );
      }

      setFeedback(
        "reliabilityFeedback",
        "Evaluating model reliability…"
      );

      const result = await request("/api/reliability/evaluate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model_version: modelVersion,
          y_true: yTrue,
          y_pred: yPred
        })
      });

      renderReliabilityResult(result);

      setFeedback(
        "reliabilityFeedback",
        `Evaluation completed successfully · ${result.sample_count} samples evaluated.`,
        "success"
      );

      await loadReliabilityHistory();

    } catch (error) {
      setFeedback(
        "reliabilityFeedback",
        error.message,
        "error"
      );
    }
  });
}

// M2 history refresh button
const reliabilityRefreshBtn = $("reliabilityRefreshBtn");

if (reliabilityRefreshBtn) {
  reliabilityRefreshBtn.addEventListener(
    "click",
    () => refreshReliability()
  );
}


// =====================================
// M3 - THREAT ADAPTATION INTELLIGENCE
// =====================================


function renderThreatIntelligence(result) {
  $("threatEventCount").textContent = result.total_events;
  $("threatPatternCount").textContent = result.patterns_detected;
  $("threatSourceCount").textContent = result.unique_sources;
  $("threatRecommendationCount").textContent =
    result.recommendations.length;

  $("threatInterpretation").textContent =
    result.interpretation;

  const patterns = $("threatPatterns");

  patterns.innerHTML = result.patterns.length
    ? result.patterns.map(pattern => {
        const score = Number(pattern.confidence_score ?? 0);
        const level = pattern.confidence_level ?? "UNKNOWN";
        const factors = Array.isArray(pattern.confidence_factors)
          ? pattern.confidence_factors
          : [];

        return `
          <article class="panel">
            <div class="panel-heading">
              <h3>${escapeHtml(
                pattern.pattern.replaceAll("_", " ")
              )}</h3>
              <span class="tag bad">
                ${escapeHtml(pattern.severity)}
              </span>
            </div>

            <p>
              <strong>Observed count:</strong>
              ${Number(pattern.observed_count ?? 0)}
            </p>

            <div class="confidence-card">
              <h4>Threat confidence</h4>
              <p>
                <strong>${score}/95</strong>
                <span class="tag">${escapeHtml(level)}</span>
              </p>

              <ul>
                ${factors.map(factor =>
                  `<li>${escapeHtml(factor)}</li>`
                ).join("")}
              </ul>
              <small>Heuristic investigation score, not attack probability.</small>
            </div>

            ${pattern.source_ip
              ? `<p><strong>Source:</strong> ${escapeHtml(pattern.source_ip)}</p>`
              : ""
            }

            <p>${escapeHtml(pattern.evidence)}</p>
          </article>
        `;
      }).join("")
    : '<p class="empty">No configured threat patterns detected.</p>';

  const recommendations = $("threatRecommendations");

  recommendations.innerHTML = result.recommendations.length
    ? result.recommendations.map(item => `
        <article class="panel">
          <div class="panel-heading">
            <h3>${escapeHtml(item.action)}</h3>
            <span class="tag">${escapeHtml(item.priority)}</span>
          </div>

          <p>${escapeHtml(item.reason)}</p>

          <ul>
            ${item.suggested_response.map(action =>
              `<li>${escapeHtml(action)}</li>`
            ).join("")}
          </ul>
        </article>
      `).join("")
    : '<p class="empty">No recommendations generated.</p>';
}



async function loadThreatIntelligenceHistory() {
  const rows = await request(
    "/api/threat-intelligence/history"
  );

  $("threatHistoryBody").innerHTML = rows.length
    ? rows.map(row => `
        <tr>
          <td>${escapeHtml(row.record_id.slice(0, 12))}...</td>
          <td>${row.total_events}</td>
          <td>${row.patterns_detected}</td>
          <td>${escapeHtml(
            row.created_at
              ? new Date(row.created_at).toLocaleString()
              : "Unknown"
          )}</td>
        </tr>
      `).join("")
    : '<tr><td colspan="4" class="empty">No threat records yet.</td></tr>';

  return rows;
}



async function refreshThreatIntelligence() {
  try {
    const response = await request("/api/threat-intelligence/history");

    const rows = Array.isArray(response)
      ? response
      : response.value || response.results || [];

    const body = $("threatHistoryBody");

    body.innerHTML = rows.length
      ? rows.map(row => `
          <tr>
            <td>${escapeHtml(row.record_id.slice(0, 12))}...</td>
            <td>${row.total_events}</td>
            <td>${row.patterns_detected}</td>
            <td>${escapeHtml(
              row.created_at
                ? new Date(row.created_at).toLocaleString()
                : "Unknown"
            )}</td>
          </tr>
        `).join("")
      : '<tr><td colspan="4">No threat records yet.</td></tr>';

    if (rows.length && rows[0].results) {
      renderThreatIntelligence(rows[0].results);
    }
  } catch (error) {
    console.error("Threat intelligence refresh failed:", error);
  }
}



// M3 analysis form
const threatIntelligenceForm = $("threatIntelligenceForm");

if (threatIntelligenceForm) {
  threatIntelligenceForm.addEventListener(
    "submit",
    async event => {
      event.preventDefault();

      try {
        const rawEvents = $("threatEvents").value.trim();

        let events;

        try {
          events = JSON.parse(rawEvents);
        } catch {
          throw new Error("Enter valid JSON for the security events.");
        }

        if (!Array.isArray(events) || events.length === 0) {
          throw new Error(
            "Submit a non-empty JSON array of security events."
          );
        }

        setFeedback(
          "threatIntelligenceFeedback",
          "Analyzing security events..."
        );

        const result = await request(
          "/api/threat-intelligence/analyze",
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json"
            },
            body: JSON.stringify({ events })
          }
        );

        renderThreatIntelligence(result);

        setFeedback(
          "threatIntelligenceFeedback",
          `Analysis completed · ${result.total_events} events · ${result.patterns_detected} patterns detected.`,
          "success"
        );

        await refreshThreatIntelligence();

      } catch (error) {
        setFeedback(
          "threatIntelligenceFeedback",
          error.message,
          "error"
        );
      }
    }
  );
}


// M3 history refresh button
const threatHistoryRefreshBtn =
  $("threatHistoryRefreshBtn");

if (threatHistoryRefreshBtn) {
  threatHistoryRefreshBtn.addEventListener(
    "click",
    () => refreshThreatIntelligence()
  );
}


// =====================================
// DASHBOARD REFRESH
// =====================================

async function refresh() {
  await Promise.all([
    loadHealth(),
    loadBaselines(),
    loadHistory(),
    refreshReliability(),
    refreshThreatIntelligence(),
    refreshAttackChain()
  ]);
}

$("refreshBtn").addEventListener("click", () => {
  refresh().catch(error => console.error(error));
});

refresh().catch(error => {
  $("connection").textContent = "Unavailable";
  console.error("Could not load dashboard:", error);
});



// =====================================
// M4 - ATTACK CHAIN INTELLIGENCE
// =====================================


// Render attack-chain analysis results
function renderAttackChainResult(result) {
const chains = result.attack_chains || [];

$("attackEventCount").textContent =
result.total_events ?? result.events_analyzed ?? 0;

$("attackChainCount").textContent =
result.chains_detected ?? chains.length;

$("attackStageCount").textContent = chains.length
? Math.max(...chains.map(chain => Number(chain.stage_count || 0)))
: 0;

$("attackResultTag").textContent = chains.length
? `${chains.length} chains detected`
: "No chains detected";

$("attackResultTag").className =
`tag ${chains.length ? "bad" : "good"}`;

const container = $("attackChainResults");

container.innerHTML = chains.length
? chains.map((chain, index) => `
<article class="panel">
<div class="panel-heading">
<h3>Attack Sequence ${index + 1}</h3>
<span class="tag bad">
${Number(chain.stage_count)} stages
</span>
</div>

<p><strong>Source IP:</strong>
${escapeHtml(chain.source_ip)}
</p>

<p><strong>Event Count:</strong>
${Number(chain.event_count)}
</p>

<p><strong>Start:</strong>
${escapeHtml(chain.start_time)}
</p>

<p><strong>End:</strong>
${escapeHtml(chain.end_time)}
</p>

<h3>Attack Timeline</h3>

<div class="attack-stage-list">
${(chain.timeline || []).map((event, i) => `
<div class="attack-stage">
<span class="attack-stage-number">${i + 1}</span>

<div>
<strong>
${escapeHtml(
String(event.stage).replaceAll("_", " ")
)}
</strong>

<p>
${escapeHtml(event.event_type)}
· ${escapeHtml(event.severity)}
</p>

<small>${escapeHtml(event.timestamp)}</small>
</div>
</div>
`).join("")}
</div>

<p class="muted">
${escapeHtml(chain.interpretation || "")}
</p>
</article>
`).join("")
: '<p class="empty">No multi-stage attack chains detected.</p>';
}

// Load attack-chain history
async function loadAttackChainHistory() {
const rows = await request("/api/attack-chains/history");


$("attackChainHistoryBody").innerHTML = rows.length
  ? rows.map(row => `
      <tr>
        <td>${escapeHtml(row.record_id.slice(0, 12))}...</td>
        <td>${Number(row.total_events)}</td>
        <td>${Number(row.chains_detected)}</td>
        <td>
          ${escapeHtml(
            row.created_at
              ? new Date(row.created_at).toLocaleString()
              : "Unknown"
          )}
        </td>
      </tr>
    `).join("")
  : `
      <tr>
        <td colspan="4" class="empty">
          No attack-chain history yet.
        </td>
      </tr>
    `;

return rows;
}


// Refresh history and display the latest analysis
async function refreshAttackChain() {
try {
const rows = await loadAttackChainHistory();

if (rows.length > 0 && rows[0].results) {
renderAttackChainResult({
...rows[0].results,
total_events: rows[0].total_events
});
}
} catch (error) {
console.error(
"Could not load attack-chain history:",
error
);
}
}

// Attack-chain analysis form
const attackChainForm = $("attackChainForm");

if (attackChainForm) {
attackChainForm.addEventListener("submit", async event => {
event.preventDefault();

try {
const rawEvents = $("attackChainEvents").value.trim();
const events = JSON.parse(rawEvents);

if (!Array.isArray(events) || events.length === 0) {
throw new Error("Submit a non-empty event array.");
}

setFeedback(
"attackChainFeedback",
"Analyzing attack sequences..."
);

const result = await request("/api/attack-chains/analyze", {
method: "POST",
headers: {
"Content-Type": "application/json"
},
body: JSON.stringify({ events })
});

renderAttackChainResult({
...result,
total_events: events.length
});

setFeedback(
"attackChainFeedback",
`Analysis completed · ${events.length} events · ${result.chains_detected} chains detected.`,
);

await refreshAttackChain();

} catch (error) {
setFeedback(
"attackChainFeedback",
error.message,
"error"
);
}
});
}

// Attack-chain history refresh button
const attackChainRefreshBtn = $("attackChainRefreshBtn");

if (attackChainRefreshBtn) {
attackChainRefreshBtn.addEventListener(
"click",
() => refreshAttackChain()
);
}


// =====================================
// M5 - UNIFIED SECURITY INTELLIGENCE
// =====================================

function setText(id, value, fallback = "—") {
  const node = $(id);

  if (node) {
    node.textContent =
      value === null || value === undefined || value === ""
        ? fallback
        : String(value);
  }
}

function safeDate(value) {
  if (!value) return "Unknown";

  const date = new Date(value);

  return Number.isNaN(date.getTime())
    ? String(value)
    : date.toLocaleString();
}


// M5.1 SECURITY OVERVIEW

async function loadSecurityOverview() {
  const data = await request("/api/security/overview");

  const totals = data.totals || {};
  const latest = data.latest || {};

  setText("secBaselineTotal", totals.baselines);
  setText("secDriftTotal", totals.drift_analyses);
  setText("secReliabilityTotal", totals.reliability_evaluations);
  setText("secThreatTotal", totals.threat_analyses);
  setText("secAttackTotal", totals.attack_chain_analyses);

  setText("securityOverviewStatus", "Live");

  const items = [
    ["Drift", latest.drift],
    ["Reliability", latest.reliability],
    ["Threat Intelligence", latest.threat_intelligence],
    ["Attack Chains", latest.attack_chains]
  ];

  $("securityLatest").innerHTML = items.map(([name, item]) => `
    <article class="stat">
      <span>${escapeHtml(name)}</span>
      <strong>
        ${item ? escapeHtml(JSON.stringify(item).slice(0, 100)) : "No data"}
      </strong>
      <small>
        ${item && item.created_at
          ? escapeHtml(safeDate(item.created_at))
          : "No latest record"}
      </small>
    </article>
  `).join("");
}


// M5.2 SECURITY POSTURE

async function loadSecurityPosture() {
  const data = await request("/api/security/posture");

  setText(
    "postureScore",
    data.overall_score == null
      ? "—"
      : `${Number(data.overall_score).toFixed(1)}/100`
  );

  setText("postureRating", data.rating);

  setText(
    "postureWeight",
    `${data.available_weight}/${data.total_weight}`
  );

  const components = data.components || {};

  $("postureComponents").innerHTML =
    Object.entries(components).map(([name, item]) => `
      <article class="stat">
        <span>${escapeHtml(name.replaceAll("_", " "))}</span>
        <strong>${Number(item.score).toFixed(1)}/100</strong>
        <small>${escapeHtml(item.details || "")}</small>
      </article>
    `).join("");

  setText(
    "postureMethodology",
    data.methodology
  );
}


// M5.3 SEVERITY ANALYTICS

async function loadSecurityAnalytics() {
  const data = await request("/api/security/analytics");

  const distribution = data.severity_distribution || {};

  setText("severityCritical", distribution.CRITICAL ?? 0);
  setText("severityHigh", distribution.HIGH ?? 0);
  setText("severityTotal", data.total_severity_observations ?? 0);
  setText("severityPatterns", data.threat_patterns_detected ?? 0);
  setText("severityChains", data.attack_chains_detected ?? 0);

  const sources = data.sources || {};

  $("severityBreakdown").innerHTML =
    Object.entries(sources).map(([name, values]) => `
      <article class="stat">
        <span>${escapeHtml(name.replaceAll("_", " "))}</span>
        <strong>
          Critical: ${Number(values.CRITICAL || 0)}
          · High: ${Number(values.HIGH || 0)}
        </strong>
        <small>
          Medium: ${Number(values.MEDIUM || 0)}
          · Low: ${Number(values.LOW || 0)}
        </small>
      </article>
    `).join("");

  setText("severityNote", data.note);
}


// M5.4 SECURITY TIMELINE

async function loadSecurityTimeline() {
  const data = await request("/api/security/timeline");

  const rows = Array.isArray(data.timeline)
    ? data.timeline
    : [];

  setText(
    "timelineTotal",
    `${data.total_events ?? rows.length} events`
  );

  $("securityTimelineBody").innerHTML = rows.length
    ? rows.map(item => `
      <tr>
        <td>${escapeHtml(safeDate(item.timestamp))}</td>
        <td>
          <span class="tag bad">
            ${escapeHtml(item.severity || "UNKNOWN")}
          </span>
        </td>
        <td>${escapeHtml(item.category || "—")}</td>
        <td>${escapeHtml(item.event || "—")}</td>
        <td>${escapeHtml(item.source_ip || "—")}</td>
        <td>${escapeHtml(item.description || "—")}</td>
      </tr>
    `).join("")
    : `
      <tr>
        <td colspan="6" class="empty">
          No timeline observations available.
        </td>
      </tr>
    `;

  setText("timelineNote", data.note);
}


// M5.5 PRIORITIZED SECURITY ALERTS

async function loadSecurityAlerts() {
  const data = await request("/api/security/alerts");

  const alerts = Array.isArray(data.alerts)
    ? data.alerts
    : [];

  setText("alertTotal", data.total_alerts ?? alerts.length);
  setText("alertCritical", data.critical_alerts ?? 0);
  setText("alertHigh", data.high_alerts ?? 0);

  setText(
    "alertQueueStatus",
    alerts.length ? "Open Findings" : "No Alerts"
  );

  $("securityAlertsList").innerHTML = alerts.length
    ? alerts.map(alert => `
      <article class="panel">

        <div class="panel-heading">
          <div>
            <p class="eyebrow">
              ${escapeHtml(alert.alert_id)}
              · ${escapeHtml(alert.category)}
            </p>

            <h3>
              ${escapeHtml(
                String(alert.event || "").replaceAll("_", " ")
              )}
            </h3>
          </div>

          <span class="tag bad">
            ${escapeHtml(alert.priority)}
          </span>
        </div>

        <p>
          ${escapeHtml(alert.description || "")}
        </p>

        <p class="muted">
          <strong>Source:</strong>
          ${escapeHtml(alert.source_ip || "Not specified")}
        </p>

        <p class="muted">
          <strong>Time:</strong>
          ${escapeHtml(safeDate(alert.timestamp))}
        </p>

        <p>
          <strong>Status:</strong>
          ${escapeHtml(alert.status || "OPEN")}
        </p>

        <h4>Recommended Actions</h4>

        <ul>
          ${(Array.isArray(alert.recommended_actions)
            ? alert.recommended_actions
            : []
          ).map(action => `
            <li>${escapeHtml(action)}</li>
          `).join("")}
        </ul>

      </article>
    `).join("")
    : '<p class="empty">No prioritized alerts available.</p>';

  setText("alertsNote", data.note);
}


// M5 COMPLETE REFRESH

async function refreshSecurityIntelligence() {
  const tasks = [
    loadSecurityOverview(),
    loadSecurityPosture(),
    loadSecurityAnalytics(),
    loadSecurityTimeline(),
    loadSecurityAlerts()
  ];

  const results = await Promise.allSettled(tasks);

  results.forEach((result, index) => {
    if (result.status === "rejected") {
      console.error(
        `M5 module ${index + 1} failed:`,
        result.reason
      );
    }
  });
}