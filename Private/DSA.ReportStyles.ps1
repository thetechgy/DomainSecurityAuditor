<#
.SYNOPSIS
    Provide CSS styles for the HTML compliance report.
.DESCRIPTION
    Returns the report stylesheet as a here-string, defining colors, layout, and interactive affordances.
#>
function Get-DSAReportStyles {
    @"
:root {
    --color-bg: #f5f7fa;
    --color-surface: #ffffff;
    --color-surface-alt: #f8fafc;
    --color-surface-subtle: #f9fafb;
    --color-text: #1f2937;
    --color-text-strong: #111827;
    --color-muted: #4b5563;
    --color-muted-light: #6b7280;
    --color-muted-lightest: #9ca3af;
    --color-border: #e5e7eb;
    --color-border-light: #f3f4f6;

    /* PASS - Forest Green (colorblind-friendly) */
    --color-pass: #059669;
    --color-pass-bg: #d1fae5;
    --color-pass-text: #064e3b;

    /* FAIL - Vibrant Vermillion (colorblind-friendly) */
    --color-fail: #dc2626;
    --color-fail-bg: #fee2e2;
    --color-fail-text: #7f1d1d;

    /* WARNING - Bright Yellow (colorblind-friendly) */
    --color-warn: #eab308;
    --color-warn-bg: #fef9c3;
    --color-warn-text: #713f12;

    /* INFO - Bright Blue (colorblind-friendly) */
    --color-info: #3b82f6;
    --color-info-bg: #dbeafe;
    --color-info-text: #1e40af;

    --color-focus: #2563eb;
    --color-focus-light: #ffffff;
    --color-header: #1e293b;
    --color-recommendation-bg: #f0f9ff;
    --color-recommendation-border: #0284c7;
    --color-recommendation-label: #0c4a6e;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', 'Helvetica Neue', sans-serif;
    line-height: 1.6;
    color: var(--color-text);
    background-color: var(--color-bg);
    font-size: 16px;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
}
.skip-link {
    position: absolute;
    top: -100px;
    left: 50%;
    transform: translateX(-50%);
    background: var(--color-text-strong);
    color: var(--color-surface);
    padding: 12px 24px;
    border-radius: 0 0 8px 8px;
    text-decoration: none;
    font-weight: 700;
    z-index: 1000;
    transition: top 0.2s ease;
}
.skip-link:focus {
    top: 0;
    outline: 3px solid var(--color-focus);
    outline-offset: 2px;
}
.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}
.header {
    background: var(--color-header);
    color: white;
    padding: 32px;
    border-radius: 12px;
    margin-bottom: 30px;
    box-shadow: 0 4px 15px rgba(0,0,0,0.12);
}
.header h1 {
    font-size: clamp(1.75rem, 3vw + 1rem, 2.6rem);
    font-weight: 700;
    letter-spacing: -0.02em;
    margin-bottom: 12px;
}
.header .meta {
    opacity: 0.95;
    font-size: 1.05rem;
}
.summary-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
}
.filter-summary {
    margin-top: 8px;
    color: var(--color-muted);
    font-size: 0.95rem;
    font-weight: 600;
}
.section-controls {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 10px;
    margin: 0 0 14px;
}
.section-toggle {
    border: 1px solid var(--color-border);
    background: var(--color-surface);
    color: var(--color-text-strong);
    padding: 8px 12px;
    border-radius: 10px;
    font-weight: 700;
    cursor: pointer;
    transition: background-color 0.2s ease, box-shadow 0.2s ease, transform 0.2s ease;
}
.section-toggle:hover { background: var(--color-border-light); transform: translateY(-1px); box-shadow: 0 1px 4px rgba(0,0,0,0.06); }
.section-toggle:active { transform: translateY(0); }
.section-toggle[aria-pressed=\"true\"] {
    background: var(--color-info-bg);
    color: var(--color-info-text);
    border-color: var(--color-info);
    box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.15);
}
.back-to-top-wrapper {
    display: flex;
    justify-content: flex-end;
    margin-top: 16px;
}
.back-to-top {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 8px 12px;
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: 10px;
    color: var(--color-info-text);
    font-weight: 700;
    text-decoration: none;
    box-shadow: 0 1px 4px rgba(0,0,0,0.06);
    transition: background-color 0.2s ease, transform 0.2s ease, box-shadow 0.2s ease;
}
.back-to-top:hover { background: var(--color-border-light); transform: translateY(-1px); box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
.card {
    background: var(--color-surface);
    padding: 24px;
    border-radius: 12px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.08);
    transition: transform 0.2s ease, box-shadow 0.2s ease;
}
.card:hover { transform: translateY(-2px); }
*:focus-visible {
    outline: 3px solid var(--color-focus);
    outline-offset: 3px;
    box-shadow: 0 0 0 6px rgba(37, 99, 235, 0.1);
}
.card:focus-visible {
    outline: 3px solid var(--color-focus);
    outline-offset: 4px;
    box-shadow: 0 0 0 8px rgba(37, 99, 235, 0.15), 0 4px 20px rgba(0, 0, 0, 0.15);
}
.protocol-header:focus-visible {
    outline: 3px solid var(--color-focus);
    outline-offset: 4px;
    box-shadow: 0 0 0 8px rgba(37, 99, 235, 0.15);
}
.header .card:focus-visible {
    outline-color: var(--color-focus-light);
}
.card-header { display: flex; align-items: center; margin-bottom: 12px; }
.card-icon {
    width: 48px;
    height: 48px;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    margin-right: 16px;
    font-weight: 800;
    color: white;
    font-size: 1.3rem;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}
.card-title { font-size: 1.1rem; font-weight: 600; color: var(--color-text-strong); }
.card-value {
    font-size: 2.1rem;
    font-weight: 700;
    margin-bottom: 6px;
}
.card-subtitle { color: var(--color-muted); font-size: 1rem; }
.card-icon.passed { background-color: var(--color-pass); }
.card-value.passed { color: var(--color-pass); }
.card-icon.failed { background-color: var(--color-fail); }
.card-value.failed { color: var(--color-fail); }
.card-icon.warning { background-color: var(--color-warn); }
.card-value.warning { color: var(--color-warn); }
.card-icon.info { background-color: var(--color-info); }
.card-value.info { color: var(--color-info); }
.card.filter-card {
    cursor: pointer;
    transition: box-shadow 0.2s ease, transform 0.2s ease;
}
.card.filter-card.active { box-shadow: 0 0 0 3px rgba(37,99,235,0.5); transform: translateY(-2px); }
.domain-results {
    background: var(--color-surface);
    border-radius: 12px;
    box-shadow: 0 2px 12px rgba(0,0,0,0.08);
    margin-bottom: 30px;
    overflow: hidden;
}
.domain-results.status-pass {
    border-left: 4px solid var(--color-pass);
}
.domain-results.status-fail {
    border-left: 4px solid var(--color-fail);
}
.domain-results.status-warning {
    border-left: 4px solid var(--color-warn);
}
.domain-empty {
    padding: 24px;
    color: var(--color-muted-light);
    font-style: italic;
    border-top: 1px solid var(--color-border-light);
}
.domain-header {
    background: var(--color-surface-alt);
    padding: 22px;
    border-bottom: 1px solid var(--color-border);
}
.domain-title {
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.domain-name { font-size: 1.5rem; font-weight: 700; letter-spacing: -0.01em; color: var(--color-text-strong); }
.domain-meta { margin-top: 12px; color: var(--color-muted); font-size: 0.98rem; }
.domain-status {
    padding: 8px 18px;
    border-radius: 999px;
    font-weight: 700;
    font-size: 0.95rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}
.domain-status.passed { background-color: var(--color-pass-bg); color: var(--color-pass); border: 2px solid var(--color-pass); }
.domain-status.failed { background-color: var(--color-fail-bg); color: var(--color-fail); border: 2px solid var(--color-fail); }
.domain-status.warning { background-color: var(--color-warn-bg); color: var(--color-warn); border: 2px solid var(--color-warn); }
.protocol-section {
    border-bottom: 1px solid var(--color-border);
    position: relative;
}
.protocol-section::before {
    content: '';
    position: absolute;
    left: 0;
    top: 0;
    bottom: 0;
    width: 4px;
    background: transparent;
    transition: background-color 0.2s ease;
}
.protocol-section.expanded::before {
    background: var(--color-info);
}
.protocol-header {
    background: var(--color-surface-subtle);
    padding: 18px 24px;
    cursor: pointer;
    user-select: none;
    display: flex;
    align-items: center;
    justify-content: space-between;
    transition: background-color 0.2s ease, transform 0.2s ease;
}
.protocol-header:hover {
    background: var(--color-border-light);
    transform: translateX(2px);
}
.protocol-name { font-weight: 700; font-size: 1.05rem; color: var(--color-text-strong); }
.protocol-status { display: flex; align-items: center; gap: 12px; font-size: 0.95rem; color: var(--color-muted); }
.protocol-count { font-weight: 600; color: var(--color-text-strong); }
.chevron {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 22px;
    height: 22px;
    border-radius: 50%;
    background: var(--color-border);
    color: var(--color-text-strong);
    font-size: 0.75rem;
    transition: transform 0.2s ease, background-color 0.2s ease, color 0.2s ease;
}
.protocol-section.expanded .chevron {
    transform: rotate(90deg);
    background: var(--color-info-bg);
    color: var(--color-info-text);
}
.status-badge {
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 0.9rem;
    font-weight: 700;
    text-transform: uppercase;
    display: inline-flex;
    align-items: center;
    gap: 6px;
}
.status-badge.passed {
    background-color: var(--color-pass-bg);
    color: var(--color-pass);
    border-bottom: 2px solid var(--color-pass);
    background-image: linear-gradient(135deg, rgba(255, 255, 255, 0.15) 25%, transparent 25%, transparent 50%, rgba(255, 255, 255, 0.15) 50%, rgba(255, 255, 255, 0.15) 75%, transparent 75%, transparent);
    background-size: 8px 8px;
}
.status-badge.failed {
    background-color: var(--color-fail-bg);
    color: var(--color-fail);
    border-bottom: 2px solid var(--color-fail);
    background-image: radial-gradient(circle, rgba(255, 255, 255, 0.2) 1px, transparent 1px);
    background-size: 6px 6px;
}
.status-badge.warning {
    background-color: var(--color-warn-bg);
    color: var(--color-warn);
    border-bottom: 2px solid var(--color-warn);
    background-image: repeating-linear-gradient(45deg, transparent, transparent 4px, rgba(255, 255, 255, 0.15) 4px, rgba(255, 255, 255, 0.15) 8px);
}
.status-badge.info { background-color: var(--color-info-bg); color: var(--color-info-text); border-bottom: 2px solid var(--color-info); }
.protocol-details { display: none; padding: 0; }
.protocol-details.expanded { display: block; }
.test-result {
    padding: 18px 24px;
    border-top: 1px solid var(--color-border-light);
}
.test-result:last-child { border-bottom: none; }
.test-header { display: flex; align-items: flex-start; gap: 16px; }
.test-icon {
    width: 36px;
    height: 36px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.1rem;
    font-weight: 700;
    color: white;
    flex-shrink: 0;
    box-shadow: 0 3px 8px rgba(0,0,0,0.15);
    position: relative;
}
.test-icon::after {
    content: '';
    position: absolute;
    inset: -4px;
    border-radius: 50%;
    border: 2px solid currentColor;
    opacity: 0.2;
}
.test-icon.passed {
    background-color: var(--color-pass);
    background-image: linear-gradient(135deg, rgba(255, 255, 255, 0.15) 25%, transparent 25%, transparent 50%, rgba(255, 255, 255, 0.15) 50%, rgba(255, 255, 255, 0.15) 75%, transparent 75%, transparent);
    background-size: 8px 8px;
}
.test-icon.failed {
    background-color: var(--color-fail);
    background-image: radial-gradient(circle, rgba(255, 255, 255, 0.2) 1px, transparent 1px);
    background-size: 6px 6px;
}
.test-icon.warning {
    background-color: var(--color-warn);
    background-image: repeating-linear-gradient(45deg, transparent, transparent 4px, rgba(255, 255, 255, 0.15) 4px, rgba(255, 255, 255, 0.15) 8px);
}
.test-icon.info { background-color: var(--color-info); }
.test-content { flex: 1; display: flex; flex-direction: column; gap: 10px; }
.test-title-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.test-name { font-weight: 700; color: var(--color-text-strong); font-size: 1rem; }
.test-message { color: var(--color-muted); font-size: 0.97rem; }
.status-pill {
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 0.85rem;
    text-transform: uppercase;
    font-weight: 700;
    letter-spacing: 0.025em;
}
.status-pill.passed {
    background-color: var(--color-pass-bg);
    color: var(--color-pass);
    border-bottom: 2px solid var(--color-pass);
    background-image: linear-gradient(135deg, rgba(255, 255, 255, 0.15) 25%, transparent 25%, transparent 50%, rgba(255, 255, 255, 0.15) 50%, rgba(255, 255, 255, 0.15) 75%, transparent 75%, transparent);
    background-size: 8px 8px;
}
.status-pill.failed {
    background-color: var(--color-fail-bg);
    color: var(--color-fail);
    border-bottom: 2px solid var(--color-fail);
    background-image: radial-gradient(circle, rgba(255, 255, 255, 0.2) 1px, transparent 1px);
    background-size: 6px 6px;
}
.status-pill.warning {
    background-color: var(--color-warn-bg);
    color: var(--color-warn);
    border-bottom: 2px solid var(--color-warn);
    background-image: repeating-linear-gradient(45deg, transparent, transparent 4px, rgba(255, 255, 255, 0.15) 4px, rgba(255, 255, 255, 0.15) 8px);
}
.status-pill.info { background-color: var(--color-info-bg); color: var(--color-info-text); border-bottom: 2px solid var(--color-info); }
.details-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 16px;
}
.detail-item {
    background: var(--color-surface-subtle);
    padding: 14px;
    border-radius: 8px;
    border-left: 3px solid var(--color-border);
    transition: border-color 0.2s ease;
}
.detail-item:hover {
    border-left-color: var(--color-info);
}
.detail-label {
    font-size: 0.8rem;
    color: var(--color-muted);
    text-transform: uppercase;
    letter-spacing: 0.075em;
    font-weight: 600;
    margin-bottom: 6px;
}
.detail-value {
    font-weight: 700;
    color: var(--color-text-strong);
    word-break: break-word;
    overflow-wrap: anywhere;
}
.test-recommendation {
    background: var(--color-recommendation-bg);
    padding: 12px;
    border-radius: 8px;
    border-left: 4px solid var(--color-recommendation-border);
}
.test-recommendation .label {
    font-weight: 700;
    color: var(--color-recommendation-label);
    margin-bottom: 4px;
}
.test-recommendation .text { color: var(--color-text); }
.test-references {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
}
.dkim-selectors {
    margin-top: 12px;
    padding: 10px 12px;
    border-radius: 8px;
    background: var(--color-surface-subtle);
    border: 1px solid var(--color-border);
}
.dkim-selectors-title {
    font-weight: 700;
    color: var(--color-text-strong);
    margin-bottom: 8px;
    font-size: 0.95rem;
}
.dkim-selector-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 8px;
}
.selector-card {
    background: var(--color-surface);
    border: 1px solid var(--color-border);
    border-radius: 8px;
    padding: 10px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.04);
}
.selector-card.passed { border-color: var(--color-pass); }
.selector-card.failed { border-color: var(--color-fail); }
.selector-name { font-weight: 700; color: var(--color-text-strong); }
.selector-status { font-weight: 700; margin-top: 2px; text-transform: uppercase; font-size: 0.8rem; }
.selector-status.passed { color: var(--color-pass); }
.selector-status.failed { color: var(--color-fail); }
.selector-meta { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; color: var(--color-muted); font-size: 0.9rem; }
.selector-warning { color: var(--color-warn); font-weight: 700; }
.reference-link {
    display: inline-block;
    padding: 6px 12px;
    border-radius: 999px;
    background: var(--color-border);
    color: var(--color-text-strong);
    text-decoration: none;
    font-size: 0.9rem;
    font-weight: 700;
    transition: background-color 0.2s ease, color 0.2s ease;
}
.reference-link:hover {
    background: #d1d5db;
    color: var(--color-text-strong);
}
.reference-link.reference-link--static {
    cursor: default;
    background: var(--color-border-light);
    color: var(--color-muted-light);
}
.footer {
    background: var(--color-surface);
    padding: 24px;
    border-radius: 12px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.08);
    text-align: center;
    color: var(--color-muted-light);
    margin: 40px auto 0;
    max-width: 960px;
}
.footer p {
    margin-bottom: 8px;
}
.footer-secondary {
    margin-top: 10px;
    font-size: 0.95rem;
}
.value-none { color: var(--color-muted-lightest); font-style: italic; }
.value-positive { color: var(--color-pass); font-weight: 700; }
.value-negative { color: var(--color-fail); font-weight: 700; }
.sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border-width: 0;
}
@media print {
    body {
        background: white;
        font-size: 12pt;
    }
    .header {
        background: white !important;
        color: black !important;
        border: 2px solid black;
    }
    .skip-link,
    .section-toggle,
    .back-to-top,
    .filter-card {
        display: none !important;
    }
    .protocol-section {
        page-break-inside: avoid;
    }
    .protocol-details {
        display: block !important;
    }
    .status-badge.passed::before { content: "[PASS] "; }
    .status-badge.failed::before { content: "[FAIL] "; }
    .status-badge.warning::before { content: "[WARN] "; }
    .card {
        border: 1px solid #333;
    }
}
@media (max-width: 640px) {
    .domain-title { flex-direction: column; align-items: flex-start; gap: 10px; }
    .summary-cards { grid-template-columns: 1fr; }
    .section-controls { flex-direction: column; align-items: flex-start; }
    .section-toggle { width: 100%; text-align: center; }
    .back-to-top-wrapper { justify-content: center; }
    .test-title-row { flex-direction: column; align-items: flex-start; gap: 6px; }
    .protocol-header { padding: 16px; }
}
@media (prefers-reduced-motion: reduce) {
    * { transition: none !important; animation-duration: 0.01ms !important; }
    .card:hover { transform: none; }
    .chevron { transform: none !important; }
}
"@
}
