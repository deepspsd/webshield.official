/**
 * WebShield Scan Report Enhancements v2.0 - Complete User Education & Visualizations
 * 
 * Features:
 * - Risk Gauge Chart (Visual risk meter)
 * - Threat Score Breakdown (Bar Chart)
 * - Detection Distribution (Doughnut Chart)
 * - Comprehensive User Education Module
 * - ML Analysis Section
 * - "Best Action" Recommendations
 * - Security Glossary with tooltips
 */

// ==================== MAIN ENHANCEMENT FUNCTION ====================
function ensureScoreBreakdown(result, details) {
    if (!details || typeof details !== 'object') {
        console.warn('⚠️ No detection_details object - cannot ensure score breakdown');
        return;
    }

    if (!details.score_breakdown || typeof details.score_breakdown !== 'object') {
        details.score_breakdown = {};
    }

    const breakdown = details.score_breakdown;
    const hasAny = ['total_score', 'virustotal', 'ml', 'url', 'content', 'ssl'].some(k => breakdown[k] !== undefined && breakdown[k] !== null);

    // If backend provided scores, use them directly
    if (hasAny) {
        console.log('✅ Using backend-calculated scores from score_breakdown');
        return;
    }

    // FALLBACK: Backend didn't provide score_breakdown, calculate from raw data
    console.warn('⚠️ Backend score_breakdown missing - calculating scores from raw data (FALLBACK MODE)');
    console.warn('⚠️ This should NOT happen in production - check backend scan.py');

    const urlAnalysis = details.url_analysis || {};
    const contentAnalysis = details.content_analysis || {};
    const sslAnalysis = details.ssl_analysis || {};
    const mlAnalysis = details.ml_analysis || {};
    const vtAnalysis = details.virustotal_analysis || {};

    const vtTotal = Number(result.total_engines ?? vtAnalysis.total_engines ?? 0) || 0;
    const vtFlagged = (Number(result.malicious_count ?? vtAnalysis.malicious_count ?? 0) || 0) + (Number(result.suspicious_count ?? vtAnalysis.suspicious_count ?? 0) || 0);
    const vtAvailable = vtTotal > 0 && !vtAnalysis.fallback_mode && !vtAnalysis.data_unavailable;
    const vtScore = vtAvailable ? Math.max(0, Math.min(100, (Number(result.malicious_count || 0) * 10) + (Number(result.suspicious_count || 0) * 5))) : 0;

    const urlScore = Math.max(0, Math.min(100, Number(urlAnalysis.suspicious_score ?? 0) || 0));
    const contentScore = Math.max(0, Math.min(100, Number(contentAnalysis.phishing_score ?? 0) || 0));
    const sslScore = Math.max(0, Math.min(100, Number(sslAnalysis.threat_score ?? 0) || 0));

    const mlAvailable = !!(mlAnalysis && mlAnalysis.ml_enabled);
    const mlConfidence = Math.max(0, Math.min(1, Number(mlAnalysis.ml_confidence ?? 0) || 0));
    const mlSummary = (mlAnalysis && typeof mlAnalysis === 'object') ? (mlAnalysis.ml_analysis_summary || {}) : {};
    const mlFlaggedSuspicious = !!(
        (mlSummary.url && mlSummary.url.prediction) ||
        (mlSummary.content && mlSummary.content.prediction)
    );
    // IMPORTANT: ML confidence is not a risk score. Only count ML towards risk when it flags suspicious.
    const mlScore = (mlAvailable && mlFlaggedSuspicious) ? Math.max(0, Math.min(100, mlConfidence * 100)) : 0;

    const total = Math.max(0, Math.min(100, Math.round((0.45 * vtScore) + (0.40 * mlScore) + (0.10 * Math.max(urlScore, contentScore)) + (0.05 * sslScore))));

    breakdown.total_score = total;
    breakdown.virustotal = vtScore;
    breakdown.ml = mlScore;
    breakdown.url = urlScore;
    breakdown.content = contentScore;
    breakdown.ssl = sslScore;
    breakdown._frontend_calculated = true;  // Flag that we calculated this, not backend

    console.warn('📊 Frontend fallback scores:', breakdown);

    details.data_quality = details.data_quality || {};
    details.data_quality.virustotal_available = vtAvailable;
    details.data_quality.ml_available = mlAvailable;
    details.data_quality.vt_flagged = vtFlagged;
}

// ==================== CHART INSTANCE MANAGEMENT ====================
// Global chart instance registry to prevent memory leaks and stale data
window.__webshieldCharts = window.__webshieldCharts || {};

/**
 * Destroys all existing chart instances to ensure fresh data display
 */
function destroyAllCharts() {
    console.log('🧹 Destroying all existing chart instances...');
    Object.keys(window.__webshieldCharts).forEach(key => {
        if (window.__webshieldCharts[key]) {
            try {
                window.__webshieldCharts[key].destroy();
                console.log(`  ✅ Destroyed chart: ${key}`);
            } catch (e) {
                console.warn(`  ⚠️ Error destroying chart ${key}:`, e);
            }
            delete window.__webshieldCharts[key];
        }
    });
    window.__webshieldCharts = {};
    console.log('✅ All charts destroyed');
}

/**
 * Creates a fresh chart instance, destroying any existing instance with the same key
 * @param {string} canvasId - DOM ID of the canvas element
 * @param {string} chartKey - Unique key for this chart instance
 * @param {object} chartConfig - Chart.js configuration object
 * @returns {Chart} The newly created chart instance
 */
function createFreshChart(canvasId, chartKey, chartConfig) {
    // Destroy existing chart with this key
    if (window.__webshieldCharts[chartKey]) {
        try {
            window.__webshieldCharts[chartKey].destroy();
            console.log(`🔄 Destroyed existing chart: ${chartKey}`);
        } catch (e) {
            console.warn(`⚠️ Error destroying ${chartKey}:`, e);
        }
        delete window.__webshieldCharts[chartKey];
    }

    // Get canvas and clear it
    const canvas = document.getElementById(canvasId);
    if (!canvas) {
        console.error(`❌ Canvas not found: ${canvasId}`);
        return null;
    }

    // Clear canvas completely
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Create fresh chart
    const chart = new Chart(ctx, chartConfig);
    window.__webshieldCharts[chartKey] = chart;
    console.log(`✅ Created fresh chart: ${chartKey}`);

    return chart;
}

function enhanceScanReportWithCharts(result, details) {
    console.log('🎨 Enhancing scan report with charts, education, and analysis...');
    console.log('📊 Scan Data:', result);
    console.log('📊 Detection Details:', details);

    // Log data freshness
    const scanTime = result.scan_timestamp ? new Date(result.scan_timestamp) : null;
    if (scanTime) {
        const ageSeconds = (Date.now() - scanTime) / 1000;
        console.log(`⏰ Scan age: ${ageSeconds.toFixed(1)}s`);
        if (ageSeconds > 60) {
            console.warn(`⚠️ Scan data is ${Math.floor(ageSeconds / 60)}m old - may not be fresh`);
        }
    }

    // CRITICAL: Destroy ALL existing charts before rendering new ones
    destroyAllCharts();

    const rightPanel = document.querySelector('.right-panel');
    if (!rightPanel) {
        console.error('Right panel not found');
        return;
    }

    // Find sections to insert before
    const sections = rightPanel.querySelectorAll('.analysis-section');
    let insertPoint = sections.length > 0 ? sections[0] : null;

    // Create and insert Chart Sections (collapsed by default)
    const chartSectionsHTML = createChartSections(result, details);
    if (insertPoint) {
        insertPoint.insertAdjacentHTML('beforebegin', chartSectionsHTML);
    } else {
        rightPanel.insertAdjacentHTML('afterbegin', chartSectionsHTML);
    }

    // Create and insert LLM Analysis Section
    if (details.llm_analysis) {
        console.log('📊 LLM Analysis data found:', details.llm_analysis);
        const llmHTML = createLLMAnalysisSection(details.llm_analysis, result);
        const chartSection = document.getElementById('charts-section');
        if (chartSection) {
            chartSection.insertAdjacentHTML('afterend', llmHTML);
        } else {
            rightPanel.insertAdjacentHTML('afterbegin', llmHTML);
        }
    }

    // Create and insert Security Glossary (collapsed by default)
    const glossaryHTML = createSecurityGlossary();
    rightPanel.insertAdjacentHTML('beforeend', glossaryHTML);

    // Render charts only when user expands the panel (avoids rendering into hidden/collapsed containers)
    const chartsDetails = document.getElementById('charts-details');
    if (chartsDetails) {
        const renderIfNeeded = () => {
            if (!chartsDetails.open) return;
            if (chartsDetails.dataset.rendered === 'true') return;
            chartsDetails.dataset.rendered = 'true';

            console.log('🎨 Rendering charts on expand...');
            ensureScoreBreakdown(result, details);
            renderRiskGaugeChart(result, details);
            renderThreatScoreChart(result, details);
        };

        chartsDetails.addEventListener('toggle', renderIfNeeded);
    }

    console.log('✅ Report enhancement complete');
}

// ==================== USER EDUCATION SECTION ====================
function createUserEducationSection(result, details) {
    const isMalicious = result.is_malicious === true || result.is_malicious === 1;
    const threatLevel = result.threat_level || 'unknown';
    const llmAnalysis = details.llm_analysis || {};
    const explanation = llmAnalysis.explanation || {};

    // Determine risk color and icon
    let riskColor, riskIcon, riskTitle;
    if (threatLevel === 'high') {
        riskColor = '#ef4444';
        riskIcon = '🔴';
        riskTitle = 'High Risk Detected';
    } else if (threatLevel === 'medium') {
        riskColor = '#f59e0b';
        riskIcon = '🟡';
        riskTitle = 'Moderate Risk Detected';
    } else if (threatLevel === 'unknown') {
        riskColor = '#94a3b8';
        riskIcon = '⚪';
        riskTitle = 'Insufficient Data';
    } else {
        riskColor = '#10b981';
        riskIcon = '🟢';
        riskTitle = 'Low Risk - Appears Safe';
    }

    // Build "What This Means For You" content
    const riskSummary = explanation.risk_summary ||
        (threatLevel === 'unknown'
            ? 'We could not retrieve enough real-time data (VirusTotal/ML) to make a confident risk call. Please review the component results below.'
            : ((isMalicious || threatLevel === 'medium' || threatLevel === 'high')
                ? 'This website shows signs that may indicate security risks. Review the details below before proceeding.'
                : 'This website appears to be safe based on our analysis. No major security concerns were detected.'));

    // Build threat-specific explanations
    const threatExplanations = buildThreatExplanations(result, details);

    return `
        <div class="analysis-section" id="user-education-section" style="margin-bottom: 1.5rem;">
            <h2 class="section-title" style="display: flex; align-items: center; gap: 0.5rem;">
                📚 What This Means For You
            </h2>
            <div class="analysis-card" style="background: linear-gradient(135deg, hsl(var(--card)), ${riskColor}15); border: 2px solid ${riskColor}40; padding: 1.5rem; border-radius: 1rem;">
                
                <!-- Risk Status Header -->
                <div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 1.25rem; padding-bottom: 1rem; border-bottom: 1px solid hsl(var(--border));">
                    <div style="font-size: 2.5rem;">${riskIcon}</div>
                    <div>
                        <div style="font-size: 1.25rem; font-weight: 700; color: ${riskColor};">${riskTitle}</div>
                        <div style="font-size: 0.95rem; color: hsl(var(--muted-foreground));">Security Assessment Complete</div>
                    </div>
                </div>

                <!-- Plain Language Summary -->
                <div style="background: hsl(var(--muted)); padding: 1rem; border-radius: 0.75rem; margin-bottom: 1.25rem;">
                    <div style="font-weight: 600; color: hsl(var(--foreground)); margin-bottom: 0.5rem;">
                        💡 In Simple Terms:
                    </div>
                    <p style="color: hsl(var(--foreground)); line-height: 1.7; margin: 0; font-size: 0.95rem;">
                        ${escapeHtml(riskSummary)}
                    </p>
                </div>

                <!-- Threat-Specific Explanations -->
                ${threatExplanations.length > 0 ? `
                <div style="margin-bottom: 1.25rem;">
                    <div style="font-weight: 600; color: hsl(var(--foreground)); margin-bottom: 0.75rem;">
                        🔍 What We Found:
                    </div>
                    <ul style="margin: 0; padding-left: 1.5rem; line-height: 1.9; color: hsl(var(--foreground));">
                        ${threatExplanations.map(exp => `<li style="margin-bottom: 0.5rem;">${escapeHtml(exp)}</li>`).join('')}
                    </ul>
                </div>
                ` : ''}

                <!-- Risk Level Explanation -->
                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.75rem;">
                    <div style="padding: 0.75rem; text-align: center; border-radius: 0.5rem; background: ${threatLevel === 'low' ? '#10b981' : 'hsl(var(--muted))'}20; border: 1px solid ${threatLevel === 'low' ? '#10b981' : 'hsl(var(--border))'};">
                        <div style="font-weight: 600; color: ${threatLevel === 'low' ? '#10b981' : 'hsl(var(--muted-foreground))'};font-size: 0.85rem;">🟢 Low Risk</div>
                        <div style="font-size: 0.75rem; color: hsl(var(--muted-foreground)); margin-top: 0.25rem;">Safe to browse</div>
                    </div>
                    <div style="padding: 0.75rem; text-align: center; border-radius: 0.5rem; background: ${threatLevel === 'medium' ? '#f59e0b' : 'hsl(var(--muted))'}20; border: 1px solid ${threatLevel === 'medium' ? '#f59e0b' : 'hsl(var(--border))'};">
                        <div style="font-weight: 600; color: ${threatLevel === 'medium' ? '#f59e0b' : 'hsl(var(--muted-foreground))'};font-size: 0.85rem;">🟡 Medium Risk</div>
                        <div style="font-size: 0.75rem; color: hsl(var(--muted-foreground)); margin-top: 0.25rem;">Proceed cautiously</div>
                    </div>
                    <div style="padding: 0.75rem; text-align: center; border-radius: 0.5rem; background: ${threatLevel === 'high' ? '#ef4444' : 'hsl(var(--muted))'}20; border: 1px solid ${threatLevel === 'high' ? '#ef4444' : 'hsl(var(--border))'};">
                        <div style="font-weight: 600; color: ${threatLevel === 'high' ? '#ef4444' : 'hsl(var(--muted-foreground))'};font-size: 0.85rem;">🔴 High Risk</div>
                        <div style="font-size: 0.75rem; color: hsl(var(--muted-foreground)); margin-top: 0.25rem;">Avoid this site</div>
                    </div>
                </div>
            </div>
            </details>
        </div>
    `;
}

// ==================== BEST ACTION SECTION ====================
function createBestActionSection(result, details) {
    const isMalicious = result.is_malicious === true || result.is_malicious === 1;
    const threatLevel = result.threat_level || 'unknown';
    const llmAnalysis = details.llm_analysis || {};
    const explanation = llmAnalysis.explanation || {};

    // Determine recommended action
    let actionBg, actionBorder, actionIcon, actionTitle, actionSteps;

    if (threatLevel === 'high') {
        actionBg = 'linear-gradient(135deg, rgba(239, 68, 68, 0.15), rgba(220, 38, 38, 0.1))';
        actionBorder = '#ef4444';
        actionIcon = '⛔';
        actionTitle = 'RECOMMENDED: Do NOT Proceed';
        actionSteps = [
            'Close this website immediately',
            'Do not enter any passwords, credit card numbers, or personal information',
            'If you already entered credentials, change your password immediately',
            'Enable two-factor authentication on affected accounts',
            'Report this site to your IT security team or web browser'
        ];
    } else if (threatLevel === 'medium') {
        actionBg = 'linear-gradient(135deg, rgba(245, 158, 11, 0.15), rgba(217, 119, 6, 0.1))';
        actionBorder = '#f59e0b';
        actionIcon = '⚠️';
        actionTitle = 'RECOMMENDED: Proceed With Caution';
        actionSteps = [
            'Verify the URL is spelled correctly (look for typos)',
            'Check for the padlock icon in your browser address bar',
            'Avoid entering sensitive information unless absolutely necessary',
            'Use a password manager instead of typing passwords manually',
            'Consider using a disposable email if signing up'
        ];
    } else if (threatLevel === 'unknown') {
        actionBg = 'linear-gradient(135deg, rgba(148, 163, 184, 0.15), rgba(100, 116, 139, 0.1))';
        actionBorder = '#94a3b8';
        actionIcon = '❔';
        actionTitle = 'RECOMMENDED: Verify Before You Trust';
        actionSteps = [
            'We could not retrieve enough real-time signals to classify this confidently',
            'Double-check the domain spelling and HTTPS padlock before proceeding',
            'Avoid entering passwords or payment details until you verify legitimacy',
            'Try re-running the scan (VirusTotal/ML may be temporarily unavailable)',
            'If this is work-related, ask your IT/security team'
        ];
    } else {
        actionBg = 'linear-gradient(135deg, rgba(16, 185, 129, 0.15), rgba(5, 150, 105, 0.1))';
        actionBorder = '#10b981';
        actionIcon = '✅';
        actionTitle = 'RECOMMENDED: Safe to Browse';
        actionSteps = [
            'Website appears legitimate - you can proceed normally',
            'Always verify you\'re on the correct domain before logging in',
            'Use unique, strong passwords for each account',
            'Keep your browser and security software updated',
            'Report any suspicious behavior if you notice anything odd'
        ];
    }

    // Add AI-specific recommendation if available
    const aiRecommendation = explanation.recommended_action || '';

    return `
        <div class="analysis-section" id="best-action-section" style="margin-bottom: 1.5rem;">
            <h2 class="section-title">🎯 Best Action To Take</h2>
            <div style="background: ${actionBg}; border: 2px solid ${actionBorder}; border-radius: 1rem; padding: 1.5rem;">
                
                <!-- Action Header -->
                <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem;">
                    <span style="font-size: 1.75rem;">${actionIcon}</span>
                    <span style="font-size: 1.1rem; font-weight: 700; color: ${actionBorder};">${actionTitle}</span>
                </div>

                <!-- Action Steps -->
                <div style="background: hsl(var(--card) / 0.5); padding: 1rem; border-radius: 0.75rem; margin-bottom: 1rem;">
                    <div style="font-weight: 600; color: hsl(var(--foreground)); margin-bottom: 0.75rem; font-size: 0.95rem;">
                        📋 Steps to Follow:
                    </div>
                    <ol style="margin: 0; padding-left: 1.5rem; line-height: 1.9; color: hsl(var(--foreground));">
                        ${actionSteps.map(step => `<li style="margin-bottom: 0.35rem;">${escapeHtml(step)}</li>`).join('')}
                    </ol>
                </div>

                ${aiRecommendation ? `
                <!-- AI Recommendation -->
                <div style="background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.3); padding: 1rem; border-radius: 0.75rem;">
                    <div style="font-weight: 600; color: #3b82f6; margin-bottom: 0.5rem; font-size: 0.9rem;">
                        🤖 AI Security Advisor Says:
                    </div>
                    <p style="color: hsl(var(--foreground)); margin: 0; font-size: 0.9rem; line-height: 1.6;">
                        ${escapeHtml(aiRecommendation)}
                    </p>
                </div>
                ` : ''}
            </div>
        </div>
    `;
}

// ==================== CHART SECTIONS ====================
function createChartSections(result, details) {
    return `
        <div class="analysis-section" id="charts-section" style="margin-bottom: 1.5rem;">
            <details id="charts-details" style="background: transparent;">
                <summary class="section-title" style="cursor:pointer; list-style: none;">📊 Visual Analysis Dashboard</summary>
            
            <!-- Risk Gauge -->
            <div style="display: grid; grid-template-columns: 1fr; gap: 1rem; margin-bottom: 1rem;">
                <div style="background: hsl(var(--muted)); border-radius: 0.75rem; padding: 1rem;">
                    <div style="font-weight: 600; color: hsl(var(--foreground)); margin-bottom: 0.75rem; text-align: center;">Overall Risk Score</div>
                    <div style="height: 180px; display: flex; align-items: center; justify-content: center;">
                        <canvas id="riskGaugeChart"></canvas>
                    </div>
                </div>
            </div>

            <!-- Threat Score Breakdown -->
            <div style="background: hsl(var(--muted)); border-radius: 0.75rem; padding: 1rem;">
                <div style="font-weight: 600; color: hsl(var(--foreground)); margin-bottom: 0.75rem; text-align: center;">Threat Score by Component</div>
                <div style="height: 220px;">
                    <canvas id="threatScoreChart"></canvas>
                </div>
            </div>
            </details>
        </div>
    `;
}

// ==================== ML ANALYSIS SECTION ====================
function createMLAnalysisSection(details) {
    const mlAnalysis = details && typeof details === 'object' ? details.ml_analysis : null;
    if (!mlAnalysis || !mlAnalysis.ml_enabled) {
        return '';
    }

    const modelsUsed = mlAnalysis.ml_models_used || [];
    const confidence = mlAnalysis.ml_confidence || 0;
    const summary = mlAnalysis.ml_analysis_summary || {};

    const urlAnalysis = (details && typeof details === 'object') ? (details.url_analysis || {}) : {};
    const finalUrlScore = Math.max(0, Math.min(100, Number(urlAnalysis.suspicious_score ?? 0) || 0));
    const finalUrlSuspicious = !!urlAnalysis.is_suspicious;
    const mlThreatProb = Math.max(0, Math.min(1, Number(urlAnalysis.ml_threat_probability ?? 0) || 0));
    const mlConf = Math.max(0, Math.min(1, Number(urlAnalysis.ml_confidence ?? confidence) || 0));

    const finalVerdictLabel = finalUrlSuspicious ? '⚠️ Final Verdict: Suspicious' : '✅ Final Verdict: Clean';
    const finalVerdictColor = finalUrlSuspicious ? '#ef4444' : '#10b981';

    return `
        <div class="analysis-section" id="ml-analysis-section" style="margin-bottom: 1.5rem;">
            <h2 class="section-title">🧠 Machine Learning Analysis</h2>
            <div class="analysis-card" style="background: linear-gradient(135deg, hsl(var(--card)), rgba(147, 51, 234, 0.1)); border: 1px solid rgba(147, 51, 234, 0.3); padding: 1.25rem; border-radius: 0.75rem;">
                
                <!-- ML Status Header -->
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1rem; padding-bottom: 0.75rem; border-bottom: 1px solid hsl(var(--border));">
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <span style="font-size: 1.25rem;">🤖</span>
                        <span style="font-weight: 600; color: #9333ea;">ML Models Active</span>
                    </div>
                    <div style="background: rgba(147, 51, 234, 0.2); padding: 0.35rem 0.75rem; border-radius: 1rem;">
                        <span style="font-weight: 600; color: #9333ea;">${Math.round(mlConf * 100)}% Model Confidence</span>
                    </div>
                </div>

                <!-- Final Verdict (URL) -->
                <div style="display:flex; align-items:center; justify-content:space-between; gap: 0.75rem; margin-bottom: 1rem;">
                    <div style="font-weight: 600; color: ${finalVerdictColor};">${finalVerdictLabel}</div>
                    <div style="display:flex; gap: 0.5rem; flex-wrap: wrap; justify-content:flex-end;">
                        <span style="background: hsl(var(--muted)); padding: 0.35rem 0.75rem; border-radius: 1rem; font-size: 0.8rem; color: hsl(var(--foreground));">
                            URL Score: ${finalUrlScore}/100
                        </span>
                        <span style="background: hsl(var(--muted)); padding: 0.35rem 0.75rem; border-radius: 1rem; font-size: 0.8rem; color: hsl(var(--foreground));">
                            URL Model Threat Prob: ${Math.round(mlThreatProb * 100)}%
                        </span>
                    </div>
                </div>

                <!-- Models Used -->
                <div style="margin-bottom: 1rem;">
                    <div style="font-weight: 600; color: hsl(var(--muted-foreground)); font-size: 0.85rem; margin-bottom: 0.5rem;">Models Used:</div>
                    <div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">
                        ${modelsUsed.map(model => `
                            <span style="background: hsl(var(--muted)); padding: 0.35rem 0.75rem; border-radius: 1rem; font-size: 0.8rem; color: hsl(var(--foreground));">
                                ✓ ${escapeHtml(model)}
                            </span>
                        `).join('')}
                    </div>
                </div>

                <!-- Analysis Details -->
                ${Object.keys(summary).length > 0 ? `
                <div style="display: grid; gap: 0.75rem;">
                    ${Object.entries(summary).map(([key, data]) => `
                        <div style="background: hsl(var(--muted)); padding: 0.75rem; border-radius: 0.5rem;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <span style="font-weight: 500; color: hsl(var(--foreground)); font-size: 0.9rem;">${escapeHtml(data.model || key)}</span>
                                <span style="font-weight: 600; color: hsl(var(--muted-foreground)); font-size: 0.85rem;">
                                    Model confidence: ${Math.round((data.confidence || 0) * 100)}%
                                </span>
                            </div>
                            <div style="display:flex; justify-content:space-between; align-items:center; margin-top:0.35rem;">
                                <span style="font-size: 0.8rem; color: ${data.prediction ? '#ef4444' : '#10b981'}; font-weight:600;">
                                    ${data.prediction ? 'Model says: Suspicious' : 'Model says: Clean'}
                                </span>
                                ${key === 'url' ? `<span style="font-size: 0.8rem; color: hsl(var(--muted-foreground));">Threat prob: ${Math.round(mlThreatProb * 100)}%</span>` : ''}
                            </div>
                            ${data.features_analyzed ? `<div style="font-size: 0.75rem; color: hsl(var(--muted-foreground)); margin-top: 0.25rem;">${data.features_analyzed} features analyzed</div>` : ''}
                        </div>
                    `).join('')}
                </div>
                ` : ''}
            </div>
        </div>
    `;
}

// ==================== LLM ANALYSIS SECTION ====================
function createLLMAnalysisSection(llmAnalysis, result) {
    console.log('Creating LLM section with data:', llmAnalysis);

    const llmData = llmAnalysis.llm_analysis || llmAnalysis;
    if (!llmData) {
        console.log('No LLM data to display');
        return '';
    }

    let html = `
        <div class="analysis-section" id="llm-analysis-section" style="margin-bottom: 1.5rem;">
            <h2 class="section-title">🤖 AI-Powered Deep Analysis</h2>
            <div class="analysis-card" style="background: linear-gradient(135deg, hsl(var(--card)), rgba(59, 130, 246, 0.1)); border: 2px solid rgba(59, 130, 246, 0.3); padding: 1.5rem; border-radius: 0.75rem;">
    `;

    const engineLevel = (result && result.threat_level) ? String(result.threat_level).toLowerCase() : 'unknown';

    // Expert Explanation
    const explanationRaw = llmData.explanation || {};
    const explanation = normalizeLLMExplanation(explanationRaw);
    if (explanation.explanation) {
        const summaryText = explanation.risk_summary ? String(explanation.risk_summary) : '';
        const mayContradict = (engineLevel === 'high' || engineLevel === 'medium') && /\blow\s+risk\b/i.test(summaryText);
        html += `
            <div style="margin-bottom: 1.25rem; padding: 1rem; background: hsl(var(--muted)); border-radius: 0.75rem; border-left: 4px solid #3b82f6;">
                <div style="font-weight: 700; color: #3b82f6; margin-bottom: 0.5rem; font-size: 0.95rem;">
                    🔬 Expert AI Analysis
                </div>
                <p style="color: hsl(var(--foreground)); line-height: 1.7; font-size: 0.9rem; margin: 0;">
                    ${escapeHtml(explanation.explanation)}
                </p>
                <div style="margin-top: 0.75rem; padding-top: 0.75rem; border-top: 1px solid hsl(var(--border));">
                    <div style="font-weight: 600; color: hsl(var(--muted-foreground)); font-size: 0.85rem; margin-bottom: 0.35rem;">Engine Verdict</div>
                    <div style="color: hsl(var(--foreground)); font-size: 0.9rem; line-height: 1.6;">
                        ${escapeHtml(engineLevel)}
                    </div>
                </div>
                ${explanation.risk_summary ? `
                <div style="margin-top: 0.75rem; padding-top: 0.75rem; border-top: 1px solid hsl(var(--border));">
                    <div style="font-weight: 600; color: hsl(var(--muted-foreground)); font-size: 0.85rem; margin-bottom: 0.35rem;">Summary</div>
                    <div style="color: hsl(var(--foreground)); font-size: 0.9rem; line-height: 1.6;">${escapeHtml(explanation.risk_summary)}</div>
                    ${mayContradict ? `
                    <div style="margin-top: 0.5rem; color: hsl(var(--muted-foreground)); font-size: 0.8rem; line-height: 1.5;">
                        Note: this is an AI-generated narrative summary. The risk level above is based on VirusTotal/ML signals.
                    </div>
                    ` : ''}
                </div>
                ` : ''}
            </div>
        `;
    }

    // Risk Factors
    if (explanation.threat_factors && explanation.threat_factors.length > 0) {
        html += `
            <div style="margin-bottom: 1rem; padding: 1rem; background: rgba(239, 68, 68, 0.1); border-radius: 0.75rem; border-left: 4px solid #ef4444;">
                <div style="font-weight: 700; color: #ef4444; margin-bottom: 0.5rem; font-size: 0.95rem;">
                    ⚠️ Risk Factors Identified
                </div>
                <ul style="margin: 0; padding-left: 1.5rem; color: hsl(var(--foreground)); line-height: 1.8;">
                    ${explanation.threat_factors.map(factor => `<li style="margin-bottom: 0.35rem;">${escapeHtml(factor)}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    // Safety Indicators
    if (explanation.safety_factors && explanation.safety_factors.length > 0) {
        html += `
            <div style="margin-bottom: 1rem; padding: 1rem; background: rgba(16, 185, 129, 0.1); border-radius: 0.75rem; border-left: 4px solid #10b981;">
                <div style="font-weight: 700; color: #10b981; margin-bottom: 0.5rem; font-size: 0.95rem;">
                    ✅ Safety Indicators Found
                </div>
                <ul style="margin: 0; padding-left: 1.5rem; color: hsl(var(--foreground)); line-height: 1.8;">
                    ${explanation.safety_factors.map(factor => `<li style="margin-bottom: 0.35rem;">${escapeHtml(factor)}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    // Classification Results
    if (llmData.url_classification || llmData.content_classification) {
        html += `<div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; margin-top: 1rem;">`;

        if (llmData.url_classification) {
            const urlClass = llmData.url_classification;
            const isMal = urlClass.is_malicious;
            html += `
                <div style="padding: 1rem; background: hsl(var(--muted)); border-radius: 0.5rem; border: 1px solid ${isMal ? '#ef4444' : '#10b981'}40;">
                    <div style="font-weight: 600; color: hsl(var(--foreground)); margin-bottom: 0.5rem; font-size: 0.85rem;">🔗 URL Classification</div>
                    <div style="font-size: 1.1rem; font-weight: 700; color: ${isMal ? '#ef4444' : '#10b981'};">
                        ${urlClass.label || (isMal ? 'Malicious' : 'Benign')}
                    </div>
                    <div style="font-size: 0.8rem; color: hsl(var(--muted-foreground)); margin-top: 0.25rem;">
                        ${Math.round((urlClass.confidence || 0) * 100)}% confidence
                    </div>
                </div>
            `;
        }

        if (llmData.content_classification) {
            const contentClass = llmData.content_classification;
            const isPhish = contentClass.is_phishing;
            html += `
                <div style="padding: 1rem; background: hsl(var(--muted)); border-radius: 0.5rem; border: 1px solid ${isPhish ? '#ef4444' : '#10b981'}40;">
                    <div style="font-weight: 600; color: hsl(var(--foreground)); margin-bottom: 0.5rem; font-size: 0.85rem;">📄 Content Classification</div>
                    <div style="font-size: 1.1rem; font-weight: 700; color: ${isPhish ? '#ef4444' : '#10b981'};">
                        ${contentClass.label || (isPhish ? 'Phishing' : 'Legitimate')}
                    </div>
                    <div style="font-size: 0.8rem; color: hsl(var(--muted-foreground)); margin-top: 0.25rem;">
                        ${Math.round((contentClass.confidence || 0) * 100)}% confidence
                    </div>
                </div>
            `;
        }

        html += `</div>`;
    }

    html += `</div></div>`;
    return html;
}

function createSecurityGlossary() {
    const terms = [
        { term: 'Phishing', definition: 'Fraudulent attempts to obtain sensitive information by disguising as a trustworthy entity' },
        { term: 'SSL/TLS', definition: 'Encryption protocols that secure data transmitted between your browser and websites' },
        { term: 'Domain Reputation', definition: 'Assessment of how trustworthy a website domain is based on historical data' },
        { term: 'Malware', definition: 'Software designed to harm, exploit, or gain unauthorized access to computer systems' },
        { term: 'Social Engineering', definition: 'Manipulation techniques used to trick people into revealing sensitive information' },
        { term: 'HTTPS', definition: 'Secure version of HTTP that encrypts data between your browser and the website' },
        { term: 'Certificate', definition: 'Digital document that verifies a website\'s identity and enables encrypted connections' },
        { term: 'Threat Level', definition: 'Classification of risk: low, medium, or high based on multiple security signals' }
    ];

    return `
        <div class="analysis-section" id="security-glossary" style="margin-bottom: 1.5rem;">
            <details id="glossary-details" style="background: transparent;">
                <summary class="section-title" style="cursor:pointer; list-style: none;">📚 Security Glossary</summary>
                <div class="analysis-card" style="background: hsl(var(--muted));">
                    <div style="display: grid; gap: 0.75rem;">
                        ${terms.map(t => `
                            <div style="padding: 0.75rem; background: hsl(var(--card)); border-radius: 0.5rem; border: 1px solid hsl(var(--border));">
                                <div style="font-weight: 600; color: hsl(var(--foreground)); margin-bottom: 0.25rem;">${escapeHtml(t.term)}</div>
                                <div style="font-size: 0.85rem; color: hsl(var(--muted-foreground)); line-height: 1.5;">${escapeHtml(t.definition)}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </details>
        </div>
    `;
}

// ==================== HELPER FUNCTIONS ====================
function buildThreatExplanations(result, details) {
    const explanations = [];

    const urlAnalysis = details.url_analysis || {};
    const sslAnalysis = details.ssl_analysis || {};
    const contentAnalysis = details.content_analysis || {};
    const vtAnalysis = details.virustotal_analysis || {};

    // URL issues
    const urlIssues = urlAnalysis.detected_issues || [];
    if (urlIssues.length > 0) {
        explanations.push(`URL pattern analysis found: ${urlIssues.slice(0, 2).join(', ')}`);
    }

    // SSL issues
    if (sslAnalysis.status === 'no_https') {
        explanations.push('This site does NOT use HTTPS encryption - your data is not secure');
    } else if (sslAnalysis.valid === false) {
        explanations.push('SSL certificate is invalid or has issues');
    } else if (sslAnalysis.valid === true) {
        explanations.push('Valid SSL certificate - connection is encrypted ✓');
    }

    // Content issues
    const contentIndicators = contentAnalysis.detected_indicators || [];
    if (contentIndicators.length > 0) {
        explanations.push(`Page content contains suspicious elements: ${contentIndicators.slice(0, 2).join(', ')}`);
    }

    return explanations;
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function normalizeLLMExplanation(explanation) {
    const exp = (typeof explanation === 'string')
        ? { explanation }
        : (explanation && typeof explanation === 'object')
            ? { ...explanation }
            : {};
    const text = (typeof exp.explanation === 'string') ? exp.explanation : '';
    if (!text) return exp;

    const parsed = tryParseEmbeddedJson(text);
    if (parsed && typeof parsed === 'object') {
        if (typeof parsed.explanation === 'string') exp.explanation = parsed.explanation;
        if (typeof parsed.risk_summary === 'string') exp.risk_summary = parsed.risk_summary;
        if (Array.isArray(parsed.threat_factors)) exp.threat_factors = parsed.threat_factors;
        if (Array.isArray(parsed.safety_factors)) exp.safety_factors = parsed.safety_factors;
        if (typeof parsed.recommended_action === 'string') exp.recommended_action = parsed.recommended_action;
    }
    if (typeof exp.explanation === 'string') {
        exp.explanation = exp.explanation.replace(/^\s*\.json\s*/i, '').trim();
    }
    return exp;
}

function tryParseEmbeddedJson(text) {
    if (typeof text !== 'string') return null;
    let s = text.trim();

    if (s.startsWith('```')) {
        s = s.replace(/^```[a-zA-Z0-9_-]*\s*/m, '');
        s = s.replace(/\s*```\s*$/m, '');
        s = s.trim();
    }

    s = s.replace(/^\s*\.json\s*/i, '').trim();

    if (!s.startsWith('{')) {
        const start = s.indexOf('{');
        const end = s.lastIndexOf('}');
        if (start >= 0 && end > start) s = s.slice(start, end + 1).trim();
    }

    if (!s.startsWith('{') || !s.endsWith('}')) return null;
    try {
        return JSON.parse(s);
    } catch (e) {
        return null;
    }
}

// ==================== CHART RENDERING ====================
function renderRiskGaugeChart(result, details) {
    const canvas = document.getElementById('riskGaugeChart');
    if (!canvas) {
        console.warn('Risk gauge chart canvas not found');
        return;
    }

    const scoreBreakdown = details.score_breakdown || {};
    const totalScore = Math.min(100, Math.max(0, scoreBreakdown.total_score || 0));

    console.log(`📊 Rendering Risk Gauge: ${totalScore}/100`);

    // Determine color based on score
    let gaugeColor;
    if (totalScore >= 70) {
        gaugeColor = '#ef4444'; // Red - High risk
    } else if (totalScore >= 40) {
        gaugeColor = '#f59e0b'; // Amber - Medium risk
    } else {
        gaugeColor = '#10b981'; // Green - Low risk
    }

    // Create fresh chart using new chart management system
    const chart = createFreshChart('riskGaugeChart', 'riskGauge', {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [totalScore, 100 - totalScore],
                backgroundColor: [gaugeColor, 'rgba(255, 255, 255, 0.1)'],
                borderWidth: 0,
                circumference: 180,
                rotation: 270
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '75%',
            plugins: {
                legend: { display: false },
                tooltip: { enabled: false }
            }
        },
        plugins: [{
            id: 'gaugeText',
            afterDraw: (chart) => {
                const ctx = chart.ctx;
                const centerX = chart.width / 2;
                const centerY = chart.height - 20;

                ctx.save();
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.font = 'bold 28px system-ui';
                ctx.fillStyle = gaugeColor;
                ctx.fillText(totalScore, centerX, centerY - 10);
                ctx.font = '12px system-ui';
                ctx.fillStyle = 'rgba(255, 255, 255, 0.7)';
                ctx.fillText('Risk Score', centerX, centerY + 15);
                ctx.restore();
            }
        }]
    });

    if (chart) {
        console.log('✅ Risk gauge chart rendered successfully');
    } else {
        console.error('❌ Failed to render risk gauge chart');
    }
}

function renderThreatScoreChart(result, details) {
    const canvas = document.getElementById('threatScoreChart');
    if (!canvas) {
        console.warn('Threat score chart canvas not found');
        return;
    }

    const breakdown = details.score_breakdown || {};

    // Include LLM score alongside other detection engines
    const vtScore = Number(breakdown.virustotal ?? 0) || 0;
    const mlScore = Number(breakdown.ml ?? 0) || 0;
    const llmScore = Number(breakdown.llm ?? 0) || 0;
    const urlScore = Number(breakdown.url ?? 0) || 0;
    const contentScore = Number(breakdown.content ?? 0) || 0;
    const sslScore = Number(breakdown.ssl ?? 0) || 0;

    console.log('📊 Rendering Threat Scores:', {
        VT: vtScore,
        ML: mlScore,
        LLM: llmScore,
        URL: urlScore,
        Content: contentScore,
        SSL: sslScore
    });

    // Create fresh chart using new chart management system
    const chart = createFreshChart('threatScoreChart', 'threatScore', {
        type: 'bar',
        data: {
            labels: ['VirusTotal', 'ML', 'LLM', 'URL', 'Content', 'SSL'],
            datasets: [{
                label: 'Risk Score',
                data: [vtScore, mlScore, llmScore, urlScore, contentScore, sslScore],
                backgroundColor: [
                    'rgba(59, 130, 246, 0.85)',   // VirusTotal - Blue
                    'rgba(147, 51, 234, 0.85)',  // ML - Purple
                    'rgba(6, 182, 212, 0.85)',   // LLM - Cyan (distinctive)
                    'rgba(16, 185, 129, 0.85)',  // URL - Green
                    'rgba(245, 158, 11, 0.85)',  // Content - Amber
                    'rgba(239, 68, 68, 0.85)'    // SSL - Red
                ],
                borderColor: [
                    'rgba(59, 130, 246, 1)',
                    'rgba(147, 51, 234, 1)',
                    'rgba(6, 182, 212, 1)',
                    'rgba(16, 185, 129, 1)',
                    'rgba(245, 158, 11, 1)',
                    'rgba(239, 68, 68, 1)'
                ],
                borderWidth: 2,
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    padding: 12,
                    callbacks: {
                        label: (context) => `Risk: ${context.parsed.y}/100`
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    ticks: { color: 'rgba(255, 255, 255, 0.6)', font: { size: 10 } },
                    grid: { color: 'rgba(255, 255, 255, 0.1)' }
                },
                x: {
                    ticks: { color: 'rgba(255, 255, 255, 0.6)', font: { size: 10 } },
                    grid: { display: false }
                }
            }
        }
    });

    if (chart) {
        console.log('✅ Threat score chart rendered successfully');
    } else {
        console.error('❌ Failed to render threat score chart');
    }
}

// Export function to global scope
window.enhanceScanReportWithCharts = enhanceScanReportWithCharts;

console.log('📊 Scan report enhancements v3.0 loaded successfully - Fresh chart instances guaranteed');
