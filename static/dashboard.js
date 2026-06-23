/**
 * dashboard.js — PyShield Dashboard
 * WebSocket client + Chart.js rendering
 */

const LEVEL_COLORS = {
    CLEAN: "#00e676",
    LOW: "#2979ff",
    MEDIUM: "#ffab00",
    HIGH: "#ff7043",
    CRITICAL: "#ff1744",
    UNKNOWN: "#6b7280",
};

const DONUT_PALETTE = [
    "#00e676",
    "#2979ff",
    "#ffab00",
    "#ff7043",
    "#ff1744",
    "#00bcd4",
    "#ce93d8",
    "#80cbc4",
];

const MAX_TREND_POINTS = 60;
const MAX_FEED_ROWS = 50;

let gaugeChart = null;
let trendChart = null;
let donutChart = null;

const gaugeScore = document.getElementById("gauge-score");
const gaugeLevel = document.getElementById("gauge-level");
const connDot = document.getElementById("conn-dot");
const connLabel = document.getElementById("conn-label");
const lastUpdate = document.getElementById("last-update");
const alertBanner = document.getElementById("alert-banner");
const bannerText = document.getElementById("banner-text");
const feedBody = document.getElementById("feed-body");
const donutLegend = document.getElementById("donut-legend");

// ── Gauge ─────────────────────────────────────────────────────────────────────
function initGauge() {
    const ctx = document.getElementById("gaugeChart").getContext("2d");
    gaugeChart = new Chart(ctx, {
        type: "doughnut",
        data: {
            datasets: [
                {
                    data: [0, 100],
                    backgroundColor: ["#00e676", "#1e2426"],
                    borderWidth: 0,
                    circumference: 180,
                    rotation: 270,
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "75%",
            plugins: {
                legend: { display: false },
                tooltip: { enabled: false },
            },
            animation: { duration: 600 },
        },
    });
}

function updateGauge(score, level) {
    const color = LEVEL_COLORS[level] || LEVEL_COLORS.UNKNOWN;
    const capped = Math.min(score, 100);
    gaugeChart.data.datasets[0].data = [capped, 100 - capped];
    gaugeChart.data.datasets[0].backgroundColor = [color, "#1e2426"];
    gaugeChart.update();
    gaugeScore.textContent = score;
    gaugeScore.className = "gauge-score level-" + level.toLowerCase();
    gaugeLevel.textContent = level;
}

// ── Trend ─────────────────────────────────────────────────────────────────────
function initTrend(history) {
    const ctx = document.getElementById("trendChart").getContext("2d");
    const labels = history.map((p) => formatTime(p.recorded_at));
    const scores = history.map((p) => p.risk_score);
    trendChart = new Chart(ctx, {
        type: "line",
        data: {
            labels,
            datasets: [
                {
                    label: "Risk Score",
                    data: scores,
                    borderColor: "#00e676",
                    backgroundColor: "rgba(0,230,118,0.06)",
                    borderWidth: 1.5,
                    pointRadius: 2,
                    pointBackgroundColor: "#00e676",
                    tension: 0.3,
                    fill: true,
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 400 },
            scales: {
                x: {
                    ticks: {
                        color: "#6b7280",
                        font: { size: 10 },
                        maxTicksLimit: 8,
                    },
                    grid: { color: "#1f2325" },
                },
                y: {
                    min: 0,
                    ticks: { color: "#6b7280", font: { size: 10 } },
                    grid: { color: "#1f2325" },
                },
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: "#1a1d1e",
                    borderColor: "#2a2e30",
                    borderWidth: 1,
                    titleColor: "#9aa0a6",
                    bodyColor: "#e8eaed",
                },
            },
        },
    });
}

function appendTrendPoint(ts, score) {
    const labels = trendChart.data.labels;
    const data = trendChart.data.datasets[0].data;
    labels.push(formatTime(ts));
    data.push(score);
    if (labels.length > MAX_TREND_POINTS) {
        labels.shift();
        data.shift();
    }
    trendChart.update();
}

// ── Donut ─────────────────────────────────────────────────────────────────────
function initDonut(eventCounts) {
    const ctx = document.getElementById("donutChart").getContext("2d");
    const { labels, values, colors } = buildDonutData(eventCounts);
    donutChart = new Chart(ctx, {
        type: "doughnut",
        data: {
            labels,
            datasets: [
                {
                    data: values,
                    backgroundColor: colors,
                    borderWidth: 0,
                    hoverOffset: 4,
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "65%",
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: "#1a1d1e",
                    borderColor: "#2a2e30",
                    borderWidth: 1,
                    titleColor: "#9aa0a6",
                    bodyColor: "#e8eaed",
                    callbacks: {
                        label: (ctx) => " " + ctx.label + ": " + ctx.parsed,
                    },
                },
            },
        },
    });
    renderDonutLegend(labels, colors);
}

function updateDonut(eventCounts) {
    const { labels, values, colors } = buildDonutData(eventCounts);
    donutChart.data.labels = labels;
    donutChart.data.datasets[0].data = values;
    donutChart.data.datasets[0].backgroundColor = colors;
    donutChart.update();
    renderDonutLegend(labels, colors);
}

function buildDonutData(eventCounts) {
    const entries = Object.entries(eventCounts);
    if (entries.length === 0)
        return { labels: ["No events"], values: [1], colors: ["#2a2e30"] };
    const labels = entries.map(([k]) => k);
    const values = entries.map(([, v]) => v);
    const colors = labels.map(
        (_, i) => DONUT_PALETTE[i % DONUT_PALETTE.length],
    );
    return { labels, values, colors };
}

function renderDonutLegend(labels, colors) {
    donutLegend.innerHTML = "";
    labels.forEach((label, i) => {
        const item = document.createElement("div");
        item.className = "donut-legend-item";
        item.innerHTML =
            '<span class="donut-legend-dot" style="background:' +
            colors[i] +
            '"></span>' +
            '<span title="' +
            label +
            '">' +
            truncate(label, 18) +
            "</span>";
        donutLegend.appendChild(item);
    });
}

// ── Banner ────────────────────────────────────────────────────────────────────
function updateBanner(triggeredEvents, summary) {
    const corr = triggeredEvents.filter((e) =>
        e.startsWith("CORRELATION_ALERT"),
    );
    if (corr.length > 0) {
        const critLines = summary.filter((l) => l.includes("CRITICAL"));
        bannerText.textContent =
            critLines.length > 0
                ? critLines[0].replace(/^[^\w\d]+/, "").trim()
                : "Correlation alert: " + corr.join(", ");
        alertBanner.classList.remove("hidden");
    } else {
        alertBanner.classList.add("hidden");
    }
}

// ── Feed ──────────────────────────────────────────────────────────────────────
function appendFeedRows(data) {
    const time = formatTime(data.timestamp || data.recorded_at);
    const level = data.risk_level || "UNKNOWN";
    const events = data.triggered_events || [];
    const summary = data.summary || [];

    if (events.length === 0 && summary.length === 0) {
        prependRow(time, "no events", level, false);
        return;
    }

    // Summary lines first — they contain the human-readable detail
    // e.g. "14 failed login attempts" or "Open ports found: [22, 80]"
    summary.forEach(function (line) {
        var clean = line
            .replace(/^[\s\u2022\ufe0f\u26a0\u2728\ud83d\udd25]+/, "")
            .trim();
        prependRow(time, clean, level, true);
    });

    // Then raw event names as secondary context
    events.forEach(function (evt) {
        prependRow(time, evt, level, false);
    });

    trimFeed();
}

function prependRow(time, text, level, isDetail) {
    var empty = feedBody.querySelector(".feed-empty");
    if (empty) empty.closest("tr").remove();

    var tr = document.createElement("tr");
    var textColor = isDetail ? "#e8eaed" : "#6b7280";
    var prefix = isDetail
        ? ""
        : '<span style="color:#2a2e30;margin-right:4px">&#x25B8;</span>';

    tr.innerHTML =
        '<td style="color:#6b7280;white-space:nowrap;font-size:11px">' +
        time +
        "</td>" +
        '<td style="color:' +
        textColor +
        '">' +
        prefix +
        escapeHtml(text) +
        "</td>" +
        '<td><span class="badge badge-' +
        level.toLowerCase() +
        '">' +
        level +
        "</span></td>";

    feedBody.insertBefore(tr, feedBody.firstChild);
}

function trimFeed() {
    while (feedBody.rows.length > MAX_FEED_ROWS)
        feedBody.removeChild(feedBody.lastChild);
}

// ── Status ────────────────────────────────────────────────────────────────────
function setConnected(state) {
    connDot.className = "conn-dot " + (state ? "connected" : "disconnected");
    connLabel.textContent = state ? "Live" : "Disconnected";
}

function setLastUpdate(ts) {
    lastUpdate.textContent = "Updated " + formatTime(ts);
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function formatTime(s) {
    try {
        var d = new Date(s.replace(" ", "T"));
        return d.toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
        });
    } catch (e) {
        return s;
    }
}

function truncate(str, n) {
    return str.length > n ? str.slice(0, n) + "\u2026" : str;
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────
async function bootstrap() {
    initGauge();
    initTrend([]);
    initDonut({});

    try {
        var hRes = await fetch("/api/history");
        if (hRes.ok) {
            var history = await hRes.json();
            if (history.length > 0) {
                trendChart.data.labels = history.map((p) =>
                    formatTime(p.recorded_at),
                );
                trendChart.data.datasets[0].data = history.map(
                    (p) => p.risk_score,
                );
                trendChart.update();
            }
        }
    } catch (e) {
        console.warn("history:", e);
    }

    try {
        var lRes = await fetch("/api/latest");
        if (lRes.ok && lRes.status !== 204) {
            var latest = await lRes.json();
            updateGauge(latest.risk_score, latest.risk_level);
            updateBanner(latest.triggered_events || [], latest.summary || []);
            appendFeedRows(latest);
            setLastUpdate(latest.recorded_at);
        }
    } catch (e) {
        console.warn("latest:", e);
    }

    try {
        var eRes = await fetch("/api/event-counts");
        if (eRes.ok) {
            updateDonut(await eRes.json());
        }
    } catch (e) {
        console.warn("event-counts:", e);
    }

    var socket = io();
    socket.on("connect", function () {
        setConnected(true);
    });
    socket.on("disconnect", function () {
        setConnected(false);
    });
    socket.on("siem_update", function (data) {
        updateGauge(data.total_risk_score, data.risk_level);
        appendTrendPoint(data.timestamp, data.total_risk_score);
        updateDonut(data.event_counts || {});
        updateBanner(data.triggered_events || [], data.summary || []);
        appendFeedRows(data);
        setLastUpdate(data.timestamp);
    });
}

document.addEventListener("DOMContentLoaded", bootstrap);

// ── Sensor controls ───────────────────────────────────────────────────────────
async function triggerSensor(name) {
    var btn = document.getElementById("btn-" + name);
    var dot = document.getElementById("dot-" + name);
    var meta = document.getElementById("meta-" + name);

    if (btn) {
        btn.disabled = true;
    }
    if (dot) {
        dot.className = "sensor-dot running";
    }
    if (meta) {
        meta.textContent = "running...";
    }

    try {
        var res = await fetch("/api/run/" + name, { method: "POST" });
        var data = await res.json();

        if (data.ok) {
            if (dot) {
                dot.className = "sensor-dot ok";
            }
            if (meta) {
                meta.textContent = "triggered";
            }

            // Auto re-evaluate SIEM 2s after sensor finishes
            // (gives the sensor thread time to write its JSON)
            if (name !== "siem") {
                setTimeout(function () {
                    fetch("/api/run/siem", { method: "POST" });
                }, 2000);
            }
        } else {
            if (dot) {
                dot.className = "sensor-dot error";
            }
            if (meta) {
                meta.textContent = data.message || "failed";
            }
        }
    } catch (e) {
        if (dot) {
            dot.className = "sensor-dot error";
        }
        if (meta) {
            meta.textContent = "request failed";
        }
    } finally {
        if (btn) {
            setTimeout(function () {
                btn.disabled = false;
                if (dot && dot.className.includes("ok")) {
                    dot.className = "sensor-dot ok";
                }
            }, 3000);
        }
    }
}

// Poll sensor status every 15s to update last-run times
async function refreshSensorStatus() {
    try {
        var res = await fetch("/api/sensor-status");
        if (!res.ok) return;
        var status = await res.json();

        Object.entries(status).forEach(function (entry) {
            var name = entry[0];
            var info = entry[1];
            var dot = document.getElementById("dot-" + name);
            var meta = document.getElementById("meta-" + name);
            var btn = document.getElementById("btn-" + name);

            if (!meta) return;

            if (info.running) {
                if (dot) dot.className = "sensor-dot running";
                if (btn) btn.disabled = true;
                meta.textContent = "running...";
            } else {
                if (btn) btn.disabled = false;
                if (info.last_result === "ok") {
                    if (dot) dot.className = "sensor-dot ok";
                } else if (info.last_result.startsWith("error")) {
                    if (dot) dot.className = "sensor-dot error";
                }
                if (info.last_run) {
                    meta.textContent = "last: " + formatTime(info.last_run);
                } else {
                    meta.textContent = "never run";
                }
            }
        });
    } catch (e) {
        /* silent */
    }
}

setInterval(refreshSensorStatus, 15000);
