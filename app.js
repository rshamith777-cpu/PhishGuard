/**
 * PhishGuard Frontend Controller
 * Strictly offline, text-based heuristic UI controller.
 * Zero external calls to inspected URLs. Uses textContent for untrusted data.
 */

document.addEventListener("DOMContentLoaded", () => {
  // Navigation Tab Switching
  const navBtns = document.querySelectorAll(".nav-btn");
  const tabContents = document.querySelectorAll(".tab-content");
  const brandLink = document.getElementById("brand-link");

  function switchTab(targetId) {
    navBtns.forEach((btn) => {
      btn.classList.toggle("active", btn.getAttribute("data-tab") === targetId);
    });
    tabContents.forEach((tab) => {
      tab.classList.toggle("active", tab.id === targetId);
    });
    if (targetId === "tab-reports") {
      loadHistory();
    }
  }

  navBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      switchTab(btn.getAttribute("data-tab"));
    });
  });

  if (brandLink) {
    brandLink.addEventListener("click", (e) => {
      e.preventDefault();
      switchTab("tab-inspector");
    });
  }

  // --- TAB 1: SINGLE URL INSPECTOR ---
  const urlInput = document.getElementById("url-input");
  const btnAnalyze = document.getElementById("btn-analyze");
  const btnClear = document.getElementById("btn-clear");
  const samplePills = document.querySelectorAll(".sample-pills .pill-btn");

  const resultsCard = document.getElementById("results-card");
  const resultIdTime = document.getElementById("result-id-time");
  const resultBadgeContainer = document.getElementById("result-badge-container");
  const resultUrlDisplay = document.getElementById("result-url-display");
  const resultCountDisplay = document.getElementById("result-count-display");
  const resultSummaryText = document.getElementById("result-summary-text");
  const findingsTbody = document.getElementById("findings-tbody");
  const safeStepsList = document.getElementById("safe-steps-list");

  const btnCopyResult = document.getElementById("btn-copy-result");
  const btnExportJson = document.getElementById("btn-export-json");
  const btnExportHtml = document.getElementById("btn-export-html");

  let currentResult = null;

  // Quick Sample shortcuts
  samplePills.forEach((pill) => {
    pill.addEventListener("click", () => {
      urlInput.value = pill.getAttribute("data-sample");
      analyzeSingleUrl(urlInput.value.trim());
    });
  });

  btnClear.addEventListener("click", () => {
    urlInput.value = "";
    resultsCard.style.display = "none";
    currentResult = null;
  });

  btnAnalyze.addEventListener("click", () => {
    const val = urlInput.value.trim();
    if (!val) {
      alert("Please enter a URL to inspect.");
      return;
    }
    analyzeSingleUrl(val);
  });

  urlInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      const val = urlInput.value.trim();
      if (val) analyzeSingleUrl(val);
    }
  });

  async function analyzeSingleUrl(targetUrl) {
    btnAnalyze.disabled = true;
    btnAnalyze.textContent = "INSPECTING...";

    try {
      let data = null;
      try {
        const response = await fetch("/api/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: targetUrl }),
        });

        if (response.ok) {
          data = await response.json();
        }
      } catch (netErr) {
        // Fallback to local deterministic engine if serverless API is unavailable
      }

      if (!data && typeof clientAnalyzeUrl === "function") {
        data = clientAnalyzeUrl(targetUrl);
      }

      if (!data) {
        throw new Error("Unable to analyze URL at this time.");
      }

      currentResult = data;
      saveLocalHistory(data);
      renderSingleResult(data);
    } catch (err) {
      alert("Error: " + err.message);
    } finally {
      btnAnalyze.disabled = false;
      btnAnalyze.textContent = "ANALYSE URL →";
    }
  }

  function renderSingleResult(result) {
    resultsCard.style.display = "block";
    resultIdTime.textContent = `ID: ${result.analysis_id} | ${result.timestamp}`;

    // Security: Use textContent for user supplied URL
    resultUrlDisplay.textContent = result.url;
    resultCountDisplay.textContent = result.indicator_count;

    // Badge styling
    resultBadgeContainer.innerHTML = "";
    const badge = document.createElement("div");
    badge.className = "result-badge";
    if (result.indicator_count === 0) {
      badge.classList.add("badge-clear");
      badge.textContent = "NO LISTED WARNING SIGNS";
    } else if (result.indicator_count <= 2) {
      badge.classList.add("badge-review");
      badge.textContent = "REVIEW";
    } else {
      badge.classList.add("badge-elevated");
      badge.textContent = "ELEVATED REVIEW";
    }
    resultBadgeContainer.appendChild(badge);

    // Summary Text
    resultSummaryText.textContent = result.limitations;

    // Update indicator total display
    const totalChecksCount = (result.findings && result.findings.length) || 12;
    resultCountDisplay.textContent = result.indicator_count;
    const countDisplayParent = resultCountDisplay.parentElement;
    if (countDisplayParent) {
      countDisplayParent.innerHTML = `<strong>Indicators Flagged:</strong> <span style="font-weight: 800;">${result.indicator_count}</span> / ${totalChecksCount}`;
    }

    // Render Findings Rows safely
    findingsTbody.innerHTML = "";
    if (result.findings && result.findings.length > 0) {
      result.findings.forEach((finding) => {
        const tr = document.createElement("tr");

        const tdName = document.createElement("td");
        tdName.style.fontWeight = "700";
        tdName.textContent = finding.name;
        tr.appendChild(tdName);

        const tdState = document.createElement("td");
        tdState.style.textAlign = "center";
        const flag = document.createElement("span");
        flag.className = `status-flag ${finding.detected ? "flagged" : "clear"}`;
        flag.textContent = finding.detected ? "FLAGGED" : "CLEAR";
        tdState.appendChild(flag);
        tr.appendChild(tdState);

        const tdWhy = document.createElement("td");
        const whyDiv = document.createElement("div");
        whyDiv.textContent = finding.why_it_matters;
        tdWhy.appendChild(whyDiv);
        if (finding.detected && finding.evidence) {
          const evDiv = document.createElement("div");
          evDiv.style.fontFamily = "var(--font-mono)";
          evDiv.style.fontSize = "12px";
          evDiv.style.marginTop = "6px";
          evDiv.style.background = "#f0ece1";
          evDiv.style.padding = "4px 8px";
          evDiv.style.border = "1px solid var(--border-color)";
          evDiv.textContent = `Evidence: ${finding.evidence}`;
          tdWhy.appendChild(evDiv);
        }
        tr.appendChild(tdWhy);

        const tdLim = document.createElement("td");
        tdLim.style.fontSize = "13px";
        tdLim.style.color = "var(--text-secondary)";
        tdLim.textContent = finding.limitations;
        tr.appendChild(tdLim);

        const tdAgent = document.createElement("td");
        tdAgent.style.fontFamily = "var(--font-mono)";
        tdAgent.style.fontSize = "12px";
        tdAgent.textContent = finding.agent_name;
        tr.appendChild(tdAgent);

        findingsTbody.appendChild(tr);
      });
    }

    // Safe Steps
    safeStepsList.innerHTML = "";
    result.safe_next_steps.forEach((step) => {
      const li = document.createElement("li");
      li.textContent = step;
      safeStepsList.appendChild(li);
    });

    resultsCard.scrollIntoView({ behavior: "smooth" });
  }

  // Result Actions
  btnCopyResult.addEventListener("click", () => {
    if (!currentResult) return;
    const summary = `PHISHGUARD ANALYSIS REPORT\nID: ${currentResult.analysis_id}\nURL: ${currentResult.url}\nClassification: ${currentResult.classification}\nIndicators Detected: ${currentResult.indicator_count}/6`;
    navigator.clipboard.writeText(summary).then(() => {
      alert("Summary copied to clipboard!");
    });
  });

  btnExportJson.addEventListener("click", () => {
    if (!currentResult) return;
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentResult, null, 2));
    const dlAnchor = document.createElement("a");
    dlAnchor.setAttribute("href", dataStr);
    dlAnchor.setAttribute("download", `phishguard_${currentResult.analysis_id}.json`);
    dlAnchor.click();
  });

  btnExportHtml.addEventListener("click", async () => {
    if (!currentResult) return;
    try {
      const response = await fetch("/api/export-html", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: currentResult.url }),
      });
      const htmlText = await response.text();
      const blob = new Blob([htmlText], { type: "text/html" });
      const url = URL.createObjectURL(blob);
      const dlAnchor = document.createElement("a");
      dlAnchor.href = url;
      dlAnchor.download = `phishguard_report_${currentResult.analysis_id}.html`;
      dlAnchor.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      alert("Failed to export HTML report: " + e.message);
    }
  });

  // --- TAB 2: BATCH ANALYSIS ---
  const batchInput = document.getElementById("batch-input");
  const btnBatchAnalyze = document.getElementById("btn-batch-analyze");
  const btnBatchClear = document.getElementById("btn-batch-clear");
  const btnBatchLoadSamples = document.getElementById("btn-batch-load-samples");
  const batchResultsCard = document.getElementById("batch-results-card");
  const batchStatsSummary = document.getElementById("batch-stats-summary");
  const batchTbody = document.getElementById("batch-tbody");
  const btnBatchCsv = document.getElementById("btn-batch-csv");
  const btnBatchJson = document.getElementById("btn-batch-json");

  let currentBatchData = null;

  btnBatchLoadSamples.addEventListener("click", () => {
    batchInput.value = [
      "https://www.example.com/login",
      "http://192.0.2.10/account",
      "http://example.com@sample.invalid/login",
      "https://a.b.c.d.e.example.invalid/path",
      "https://xn--example.invalid/",
    ].join("\n");
  });

  btnBatchClear.addEventListener("click", () => {
    batchInput.value = "";
    batchResultsCard.style.display = "none";
    currentBatchData = null;
  });

  btnBatchAnalyze.addEventListener("click", async () => {
    const rawLines = batchInput.value.split("\n").map((l) => l.trim()).filter((l) => l.length > 0);
    if (rawLines.length === 0) {
      alert("Please provide at least one URL for batch inspection.");
      return;
    }
    if (rawLines.length > 50) {
      alert("Maximum 50 URLs allowed per batch request.");
      return;
    }

    btnBatchAnalyze.disabled = true;
    btnBatchAnalyze.textContent = "INSPECTING BATCH...";

    try {
      let data = null;
      try {
        const response = await fetch("/api/analyze-batch", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ urls: rawLines }),
        });
        if (response.ok) {
          data = await response.json();
        }
      } catch (netErr) {}

      if (!data && typeof clientAnalyzeUrl === "function") {
        const batchResults = rawLines.map(u => clientAnalyzeUrl(u));
        data = {
          total_inputs: batchResults.length,
          successful_count: batchResults.length,
          with_indicators_count: batchResults.filter(r => r.indicator_count > 0).length,
          results: batchResults
        };
      }

      if (!data) throw new Error("Batch request failed");
      currentBatchData = data;
      if (data.results) {
        data.results.forEach(r => saveLocalHistory(r));
      }
      renderBatchResults(data);
    } catch (err) {
      alert("Error: " + err.message);
    } finally {
      btnBatchAnalyze.disabled = false;
      btnBatchAnalyze.textContent = "ANALYSE BATCH →";
    }
  });

  function renderBatchResults(batchSummary) {
    batchResultsCard.style.display = "block";
    batchStatsSummary.textContent = `Total Inputs: ${batchSummary.total_inputs} | Successfully Analysed: ${batchSummary.successful_count} | With Indicators Flagged: ${batchSummary.with_indicators_count}`;

    batchTbody.innerHTML = "";
    batchSummary.results.forEach((r) => {
      const tr = document.createElement("tr");

      const tdId = document.createElement("td");
      tdId.style.fontFamily = "var(--font-mono)";
      tdId.textContent = r.analysis_id;
      tr.appendChild(tdId);

      const tdUrl = document.createElement("td");
      tdUrl.style.fontFamily = "var(--font-mono)";
      tdUrl.style.wordBreak = "break-all";
      tdUrl.textContent = r.url;
      tr.appendChild(tdUrl);

      const tdCount = document.createElement("td");
      tdCount.style.textAlign = "center";
      tdCount.style.fontWeight = "700";
      const totalChecks = (r.findings && r.findings.length) || 12;
      tdCount.textContent = `${r.indicator_count} / ${totalChecks}`;
      tr.appendChild(tdCount);

      const tdClass = document.createElement("td");
      const badge = document.createElement("span");
      badge.className = "status-flag";
      if (r.indicator_count === 0) {
        badge.classList.add("clear");
        badge.textContent = "NO WARNINGS";
      } else if (r.indicator_count <= 2) {
        badge.style.background = "var(--accent-yellow)";
        badge.textContent = "REVIEW";
      } else {
        badge.classList.add("flagged");
        badge.textContent = "ELEVATED";
      }
      tdClass.appendChild(badge);
      tr.appendChild(tdClass);

      const tdFlags = document.createElement("td");
      const detectedNames = r.findings.filter((f) => f.detected).map((f) => f.name);
      tdFlags.textContent = detectedNames.length > 0 ? detectedNames.join(", ") : "None";
      tr.appendChild(tdFlags);

      batchTbody.appendChild(tr);
    });
  }

  btnBatchJson.addEventListener("click", () => {
    if (!currentBatchData) return;
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentBatchData, null, 2));
    const dl = document.createElement("a");
    dl.href = dataStr;
    dl.download = `phishguard_batch_${Date.now()}.json`;
    dl.click();
  });

  btnBatchCsv.addEventListener("click", () => {
    if (!currentBatchData) return;
    let csv = "Analysis ID,Target URL,Indicator Count,Classification,Detected Flags\n";
    currentBatchData.results.forEach((r) => {
      const flags = r.findings.filter((f) => f.detected).map((f) => f.name).join("; ") || "None";
      csv += `"${r.analysis_id}","${r.url.replace(/"/g, '""')}","${r.indicator_count}","${r.classification}","${flags}"\n`;
    });
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const dl = document.createElement("a");
    dl.href = url;
    dl.download = `phishguard_batch_${Date.now()}.csv`;
    dl.click();
    URL.revokeObjectURL(url);
  });

  // --- TAB 3: AUDIT HISTORY ---
  const historyTbody = document.getElementById("history-tbody");
  const btnClearHistory = document.getElementById("btn-clear-history");

  function saveLocalHistory(item) {
    try {
      const existing = JSON.parse(localStorage.getItem("phishguard_history") || "[]");
      existing.unshift({
        analysis_id: item.analysis_id,
        timestamp: item.timestamp,
        sanitized_url: item.sanitized_url || item.url,
        indicator_count: item.indicator_count,
        classification: item.classification
      });
      // Keep up to 50 most recent inspections
      localStorage.setItem("phishguard_history", JSON.stringify(existing.slice(0, 50)));
    } catch (e) {}
  }

  async function loadHistory() {
    let list = [];
    try {
      const res = await fetch("/api/history");
      if (res.ok) {
        list = await res.json();
      }
    } catch (e) {}

    // Seamless fallback to browser localStorage if serverless has no persistent filesystem
    if (!list || list.length === 0) {
      try {
        list = JSON.parse(localStorage.getItem("phishguard_history") || "[]");
      } catch (e) {
        list = [];
      }
    }

    historyTbody.innerHTML = "";
    if (!list || list.length === 0) {
      historyTbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--text-secondary);padding:20px;">No local inspection logs found. Inspect a URL to see history!</td></tr>`;
      return;
    }

    list.forEach((item) => {
      const tr = document.createElement("tr");

      const tdId = document.createElement("td");
      tdId.style.fontFamily = "var(--font-mono)";
      tdId.textContent = item.analysis_id;
      tr.appendChild(tdId);

      const tdTime = document.createElement("td");
      tdTime.style.fontSize = "13px";
      tdTime.textContent = item.timestamp;
      tr.appendChild(tdTime);

      const tdSan = document.createElement("td");
      tdSan.style.fontFamily = "var(--font-mono)";
      tdSan.style.wordBreak = "break-all";
      tdSan.textContent = item.sanitized_url;
      tr.appendChild(tdSan);

      const tdCount = document.createElement("td");
      tdCount.style.textAlign = "center";
      tdCount.style.fontWeight = "700";
      tdCount.textContent = item.indicator_count;
      tr.appendChild(tdCount);

      const tdClass = document.createElement("td");
      const badge = document.createElement("span");
      badge.className = "status-flag";
      if (item.indicator_count === 0) {
        badge.classList.add("clear");
        badge.textContent = "CLEAR";
      } else if (item.indicator_count <= 2) {
        badge.style.background = "var(--accent-yellow)";
        badge.textContent = "REVIEW";
      } else {
        badge.classList.add("flagged");
        badge.textContent = "ELEVATED";
      }
      tdClass.appendChild(badge);
      tr.appendChild(tdClass);

      historyTbody.appendChild(tr);
    });
  }

  btnClearHistory.addEventListener("click", async () => {
    if (confirm("Clear local audit logs?")) {
      try {
        await fetch("/api/clear-history", { method: "POST" });
      } catch (e) {}
      localStorage.removeItem("phishguard_history");
      loadHistory();
    }
  });
});

