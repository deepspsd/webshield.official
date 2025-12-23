/**
 * WebShield LLM-Enhanced Scan Report Display
 * Adds prominent LLM risk assessment banner and enhanced visualizations
 */

// Inject LLM Risk Assessment Banner
function addLLMRiskBanner(result, details) {
    const llmWrapper = details.llm_analysis;
    if (!llmWrapper) return '';

    // Backend wraps payload as: detection_details.llm_analysis = { status, llm_analysis: { ... } }
    const llmData = llmWrapper.llm_analysis || llmWrapper;

    const engineLevel = (result && result.threat_level) ? String(result.threat_level).toLowerCase() : 'unknown';
    const llmLevel = (llmData && llmData.llm_risk_level) ? String(llmData.llm_risk_level).toLowerCase() : 'unknown';

    const order = { unknown: 0, low: 1, 'low-medium': 2, medium: 3, high: 4 };
    const safeLevel = (lvl) => (order[lvl] !== undefined ? lvl : 'unknown');
    const displayedLevel = (order[safeLevel(llmLevel)] >= order[safeLevel(engineLevel)]) ? safeLevel(llmLevel) : safeLevel(engineLevel);

    const confidence = (llmData && llmData.llm_confidence) || 0;
    const method = (llmData && llmData.assessment_method) || 'Unknown';

    // Determine colors based on risk level
    let bgGradient, borderColor, textColor, riskText, riskIcon;

    if (displayedLevel === 'high') {
        bgGradient = 'linear-gradient(135deg, rgba(239, 68, 68, 0.15), rgba(220, 38, 38, 0.1))';
        borderColor = '#ef4444';
        textColor = '#ef4444';
        riskText = 'HIGH RISK';
        riskIcon = '🔴';
    } else if (displayedLevel === 'medium' || displayedLevel === 'low-medium') {
        bgGradient = 'linear-gradient(135deg, rgba(245, 158, 11, 0.15), rgba(217, 119, 6, 0.1))';
        borderColor = '#f59e0b';
        textColor = '#f59e0b';
        riskText = displayedLevel === 'medium' ? 'MEDIUM RISK' : 'LOW-MEDIUM RISK';
        riskIcon = '🟡';
    } else {
        bgGradient = 'linear-gradient(135deg, rgba(16, 185, 129, 0.15), rgba(5, 150, 105, 0.1))';
        borderColor = '#10b981';
        textColor = '#10b981';
        riskText = 'LOW RISK';
        riskIcon = '🟢';
    }

    return `
        <div style="background: ${bgGradient}; border: 2px solid ${borderColor}; border-radius: 0.75rem; padding: 1rem; margin-bottom: 1rem; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
                <div style="font-weight: 700; font-size: 1.1rem; color: ${textColor};">
                    🤖 AI Risk Assessment: ${riskIcon} ${riskText}
                </div>
                ${confidence > 0 ? `
                <div style="font-weight: 600; font-size: 0.95rem; color: hsl(var(--foreground));">
                    Confidence: ${Math.round(confidence * 100)}%
                </div>
                ` : ''}
            </div>
            <div style="font-size: 0.85rem; color: hsl(var(--muted-foreground));">
                Assessment Method: ${method} (engine verdict: ${engineLevel})
            </div>
        </div>
    `;
}

// Enhanced displayResults function with LLM banner
window.displayResultsWithLLM = function (result) {
    const container = document.querySelector('.container');

    if (!container) {
        console.error('Container not found in displayResults');
        return;
    }

    // Handle boolean/integer values safely
    const isMalicious = result.is_malicious === true || result.is_malicious === 1;
    const safe = !isMalicious;
    const statusClass = safe ? 'status-safe' : result.threat_level === 'high' ? 'status-danger' : 'status-warning';

    // Safely extract nested objects with fallbacks
    const details = result.detection_details || {};
    const urlAnalysis = details.url_analysis || {};
    const sslAnalysis = details.ssl_analysis || {};
    const contentAnalysis = details.content_analysis || {};
    const mlUsed = (urlAnalysis.ml_enabled === true || urlAnalysis.ml_enabled === 1) || (contentAnalysis.ml_enabled === true || contentAnalysis.ml_enabled === 1);
    const sslHasError = !!(sslAnalysis && (sslAnalysis.error));
    const sslValidText = sslHasError ? 'Unknown' : ((result.ssl_valid === true || result.ssl_valid === 1) ? 'Valid' : 'Invalid');
    const vtAnalysis = details.virustotal_analysis || {};

    // Generate LLM banner HTML
    const llmBanner = addLLMRiskBanner(result, details);

    // Build the HTML content with LLM banner inserted
    const html = `
        <div class="header">
            <div class="logo-icon">🛡️</div>
            <div class="logo-text">WebShield</div>
            <h1 class="title" style="margin-left: auto;">📝 Scan Report</h1>
        </div>
        
        <div class="left-panel">
            <div class="status-url-container">
                <div class="status-badge ${statusClass}">
                    ${safe ? '✅ Low Risk 🟢' : result.threat_level === 'medium' ? '⚠️ Medium Risk 🟡' : '❌ High Risk 🔴'}
                </div>
                
                <div class="url-display">
                    <div class="url-label">URL:</div>
                    <div class="url-value">${result.url || 'Unknown URL'}</div>
                </div>
            </div>
            
            ${llmBanner}
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">${result.malicious_count || 0}</div>
                    <div class="stat-label">Malicious</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${result.suspicious_count || 0}</div>
                    <div class="stat-label">Suspicious</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${result.total_engines || 0}</div>
                    <div class="stat-label">Engines</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${sslValidText}</div>
                    <div class="stat-label">SSL</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${mlUsed ? 'Yes' : 'No'}</div>
                    <div class="stat-label">ML Used</div>
                </div>
                ${mlUsed && details.ml_analysis ? `
                <div class="stat-card">
                    <div class="stat-value">${Math.round((details.ml_analysis.ml_confidence || 0) * 100)}%</div>
                    <div class="stat-label">ML Confidence</div>
                </div>
                ` : ''}
                ${details.llm_analysis && details.llm_analysis.llm_confidence ? `
                <div class="stat-card" style="border: 2px solid #3b82f6;">
                    <div class="stat-value" style="color: #3b82f6;">${Math.round(details.llm_analysis.llm_confidence * 100)}%</div>
                    <div class="stat-label">🤖 LLM Confidence</div>
                </div>
                ` : ''}
            </div>
        </div>
        
        <div class="right-panel">
            ${generateRightPanelContent(result, details, urlAnalysis, sslAnalysis, contentAnalysis, vtAnalysis, mlUsed, sslHasError)}
        </div>
        
        <div class="button-container">
            <a href="index.html" class="back-button">← Home</a>
            <button onclick="exportToPDF()" class="back-button" style="background: linear-gradient(135deg, #00f2fe, #4facfe); border: none; cursor: pointer;">
                📄 PDF
            </button>
            <button onclick="exportToCSV()" class="back-button" style="background: linear-gradient(135deg, #4CAF50, #45a049); border: none; cursor: pointer;">
                📊 CSV
            </button>
            <button onclick="shareReport()" class="back-button" style="background: linear-gradient(135deg, #FF9800, #F57C00); border: none; cursor: pointer;">
                🔗 Share
            </button>
        </div>
    `;

    // Set the HTML content
    container.innerHTML = html;

    // Store result for export functions
    window.currentScanResult = result;

    // Render charts
    setTimeout(() => {
        renderThreatScoreChart(result, details);
        renderDetectionChart(result);
        if (details.llm_analysis) {
            renderLLMConfidenceChart(details.llm_analysis);
        }
    }, 100);
};

// Generate right panel content (moved to separate function for clarity)
function generateRightPanelContent(result, details, urlAnalysis, sslAnalysis, contentAnalysis, vtAnalysis, mlUsed, sslHasError) {
    // This will contain all the analysis sections
    // For now, return a placeholder - we'll enhance this in the next step
    return `
        <div class="analysis-section">
            <h2 class="section-title">🔗 URL Analysis</h2>
            <div class="analysis-card">
                <div class="analysis-item">
                    <span class="analysis-label">Domain:</span>
                    <span class="analysis-value">${urlAnalysis.domain || 'N/A'}</span>
                </div>
                <div class="analysis-item">
                    <span class="analysis-label">Suspicious Score:</span>
                    <span class="analysis-value">${urlAnalysis.suspicious_score !== undefined ? urlAnalysis.suspicious_score : 'N/A'}</span>
                </div>
                <div class="analysis-item">
                    <span class="analysis-label">Suspicious:</span>
                    <span class="analysis-value">${(urlAnalysis.is_suspicious === true || urlAnalysis.is_suspicious === 1) ? 'Yes' : 'No'}</span>
                </div>
            </div>
        </div>
        <!-- More sections will be added here -->
    `;
}

// New: LLM Confidence Chart
function renderLLMConfidenceChart(llmAnalysis) {
    const canvas = document.getElementById('llmConfidenceChart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');

    const urlConf = llmAnalysis.url_classification?.confidence || 0;
    const contentConf = llmAnalysis.content_classification?.confidence || 0;
    const overallConf = llmAnalysis.llm_confidence || 0;

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['URL Classification', 'Content Classification', 'Overall Assessment'],
            datasets: [{
                data: [urlConf * 100, contentConf * 100, overallConf * 100],
                backgroundColor: [
                    'rgba(59, 130, 246, 0.8)',
                    'rgba(16, 185, 129, 0.8)',
                    'rgba(245, 158, 11, 0.8)'
                ],
                borderColor: [
                    'rgba(59, 130, 246, 1)',
                    'rgba(16, 185, 129, 1)',
                    'rgba(245, 158, 11, 1)'
                ],
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: 'hsl(220, 15%, 96%)',
                        padding: 15,
                        font: {
                            size: 12
                        }
                    }
                },
                title: {
                    display: true,
                    text: '🤖 LLM Confidence Breakdown',
                    color: 'hsl(220, 15%, 96%)',
                    font: {
                        size: 16,
                        weight: 'bold'
                    }
                }
            }
        }
    });
}

console.log('✅ LLM-Enhanced Scan Report Display loaded');
