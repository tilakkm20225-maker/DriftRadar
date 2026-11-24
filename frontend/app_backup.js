
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
}



async function refreshThreatIntelligence() {
  try {
    const rows = await loadThreatIntelligenceHistory();

    if (rows.length > 0 && rows[0].results) {
      renderThreatIntelligence(rows[0].results);
    }
  } catch (error) {
    console.error(
      "Could not load threat intelligence history:",
      error
    );
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
