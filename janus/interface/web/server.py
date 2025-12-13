# janus/interface/web/server.py
"""
Janus Web Dashboard - Full-Featured Security Platform.
Includes: BOLA Scan, CVE Lookup, Shadow API, GraphQL, JWT, Mass Assignment.
"""

from fastapi import FastAPI, Request, Form, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from typing import Optional
import os
import sys
import json
from datetime import datetime

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))

from janus.core.engine import JanusEngine, ScanReport
from janus.core.database import JanusDatabase
from janus.recon.cve_lookup import CVELookup
from janus.recon.shadow import ShadowAPIDetector
from janus.attack.graphql import GraphQLAttacker
from janus.core.jwt_attacks import JWTAttacker
from janus.core.mass_assignment import MassAssignmentTester
from janus.core.reporting import HTMLReportGenerator
# Phase 5 & 6 modules
from janus.attack.bfla import BFLAScanner
from janus.analysis.pii_scanner import PIIScanner
from janus.attack.race_condition import RaceConditionTester
from janus.core.stealth import GhostWalker, StealthConfig
from janus.core.hivemind import HiveMind
from janus.reporting.sarif import SARIFReporter

app = FastAPI(
    title="Janus Security Scanner",
    description="Complete API Security Platform - BOLA, CVE, Shadow API, GraphQL, JWT, Mass Assignment",
    version="2.0.0"
)

# Store scan results
scan_results = {}


def get_dashboard_html(tokens: list) -> str:
    """Generate the full-featured dashboard HTML."""
    
    token_options = "".join([f'<option value="{t}">{t[:40]}...</option>' for t in tokens])
    
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Janus Security Scanner</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script>
            tailwind.config = {{
                darkMode: 'class',
                theme: {{
                    extend: {{
                        colors: {{
                            janus: {{
                                bg: '#0a0a12',
                                card: '#12121c',
                                accent: '#e94560',
                                blue: '#4361ee',
                                green: '#06d6a0',
                                purple: '#9d4edd'
                            }}
                        }}
                    }}
                }}
            }}
        </script>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;600;700&display=swap');
            body {{ font-family: 'Inter', sans-serif; }}
            .mono {{ font-family: 'JetBrains Mono', monospace; }}
            .glow {{ box-shadow: 0 0 30px rgba(233, 69, 96, 0.2); }}
            .glow-blue {{ box-shadow: 0 0 30px rgba(67, 97, 238, 0.2); }}
            .glow-green {{ box-shadow: 0 0 30px rgba(6, 214, 160, 0.2); }}
            .glow-purple {{ box-shadow: 0 0 30px rgba(157, 78, 221, 0.2); }}
            .tab-active {{ border-bottom: 2px solid #e94560; color: #e94560; }}
            .spinner {{ animation: spin 1s linear infinite; }}
            @keyframes spin {{ 100% {{ transform: rotate(360deg); }} }}
        </style>
    </head>
    <body class="bg-janus-bg text-gray-100 min-h-screen">
        <!-- Header -->
        <header class="border-b border-gray-800 bg-janus-card/80 backdrop-blur-lg sticky top-0 z-50">
            <div class="container mx-auto px-6 py-4 flex items-center justify-between">
                <div class="flex items-center gap-4">
                    <h1 class="text-2xl font-bold">
                        <span class="text-janus-accent">🔱 JANUS</span>
                        <span class="text-gray-500 text-sm font-normal ml-2">Security Platform v2.0</span>
                    </h1>
                </div>
                <div class="flex items-center gap-4 text-sm">
                    <span class="flex items-center gap-2 text-green-400">
                        <span class="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
                        All Systems Online
                    </span>
                    <span class="text-gray-500">|</span>
                    <span class="text-gray-400">{len(tokens)} Tokens Learned</span>
                </div>
            </div>
        </header>

        <main class="container mx-auto px-6 py-6">
            <!-- Navigation Tabs -->
            <div class="flex gap-1 mb-6 border-b border-gray-800">
                <button onclick="showTab('bola')" id="tab-bola" class="px-6 py-3 text-sm font-medium tab-active">
                    🔥 BOLA Scan
                </button>
                <button onclick="showTab('cve')" id="tab-cve" class="px-6 py-3 text-sm font-medium text-gray-400 hover:text-gray-200">
                    🔍 CVE Lookup
                </button>
                <button onclick="showTab('shadow')" id="tab-shadow" class="px-6 py-3 text-sm font-medium text-gray-400 hover:text-gray-200">
                    👻 Shadow API
                </button>
                <button onclick="showTab('graphql')" id="tab-graphql" class="px-6 py-3 text-sm font-medium text-gray-400 hover:text-gray-200">
                    💥 GraphQL
                </button>
                <button onclick="showTab('jwt')" id="tab-jwt" class="px-6 py-3 text-sm font-medium text-gray-400 hover:text-gray-200">
                    🔐 JWT Attack
                </button>
                <button onclick="showTab('mass')" id="tab-mass" class="px-6 py-3 text-sm font-medium text-gray-400 hover:text-gray-200">
                    📝 Mass Assignment
                </button>
                <button onclick="showTab('bfla')" id="tab-bfla" class="px-6 py-3 text-sm font-medium text-gray-400 hover:text-gray-200">
                    🔓 BFLA
                </button>
                <button onclick="showTab('pii')" id="tab-pii" class="px-6 py-3 text-sm font-medium text-gray-400 hover:text-gray-200">
                    🔍 PII Scan
                </button>
                <button onclick="showTab('race')" id="tab-race" class="px-6 py-3 text-sm font-medium text-gray-400 hover:text-gray-200">
                    ⚡ Race Cond.
                </button>
                <button onclick="showTab('stealth')" id="tab-stealth" class="px-6 py-3 text-sm font-medium text-gray-400 hover:text-gray-200">
                    👻 Stealth
                </button>
                <button onclick="showTab('team')" id="tab-team" class="px-6 py-3 text-sm font-medium text-gray-400 hover:text-gray-200">
                    🐝 Hive-Mind
                </button>
            </div>

            <!-- Tab Content Container -->
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <!-- Left Panel: Forms -->
                <div class="lg:col-span-1">
                    <!-- BOLA Tab -->
                    <div id="panel-bola" class="bg-janus-card rounded-xl p-6 border border-gray-800 glow">
                        <h2 class="text-lg font-semibold mb-4">🔥 BOLA/IDOR Scanner</h2>
                        <form id="bolaForm" class="space-y-4">
                            <div>
                                <label class="block text-sm text-gray-400 mb-1">Target API URL</label>
                                <input type="text" name="host" value="http://localhost:5000" 
                                       class="w-full px-3 py-2 bg-janus-bg border border-gray-700 rounded-lg mono text-sm">
                            </div>
                            <div>
                                <label class="block text-sm text-gray-400 mb-1">Victim Token</label>
                                <select name="victim_token" class="w-full px-3 py-2 bg-janus-bg border border-gray-700 rounded-lg mono text-sm">
                                    {token_options}
                                </select>
                            </div>
                            <div>
                                <label class="block text-sm text-gray-400 mb-1">Attacker Token</label>
                                <select name="attacker_token" class="w-full px-3 py-2 bg-janus-bg border border-gray-700 rounded-lg mono text-sm">
                                    {token_options}
                                </select>
                            </div>
                            <button type="submit" class="w-full py-3 bg-janus-accent hover:bg-red-600 rounded-lg font-semibold transition-all">
                                🚀 Launch BOLA Scan
                            </button>
                        </form>
                    </div>

                    <!-- CVE Tab -->
                    <div id="panel-cve" class="bg-janus-card rounded-xl p-6 border border-gray-800 glow-blue hidden">
                        <h2 class="text-lg font-semibold mb-4">🔍 CVE Lookup</h2>
                        <form id="cveForm" class="space-y-4">
                            <div>
                                <label class="block text-sm text-gray-400 mb-1">Target URL</label>
                                <input type="text" name="url" value="http://localhost:5000" 
                                       class="w-full px-3 py-2 bg-janus-bg border border-gray-700 rounded-lg mono text-sm">
                            </div>
                            <div>
                                <label class="block text-sm text-gray-400 mb-1">Technology (optional)</label>
                                <input type="text" name="tech" placeholder="e.g., nginx, Django, Flask" 
                                       class="w-full px-3 py-2 bg-janus-bg border border-gray-700 rounded-lg mono text-sm">
                            </div>
                            <div>
                                <label class="block text-sm text-gray-400 mb-1">Version (optional)</label>
                                <input type="text" name="version" placeholder="e.g., 1.18.0" 
                                       class="w-full px-3 py-2 bg-janus-bg border border-gray-700 rounded-lg mono text-sm">
                            </div>
                            <button type="submit" class="w-full py-3 bg-janus-blue hover:bg-blue-600 rounded-lg font-semibold transition-all">
                                🔍 Check CVEs
                            </button>
                        </form>
                    </div>

                    <!-- Shadow API Tab -->
                    <div id="panel-shadow" class="bg-janus-card rounded-xl p-6 border border-gray-800 glow-green hidden">
                        <h2 class="text-lg font-semibold mb-4">👻 Shadow API Detector</h2>
                        <form id="shadowForm" class="space-y-4">
                            <div>
                                <label class="block text-sm text-gray-400 mb-1">OpenAPI Spec (optional)</label>
                                <textarea name="openapi_spec" rows="4" placeholder="Paste OpenAPI JSON here or leave empty..."
                                          class="w-full px-3 py-2 bg-janus-bg border border-gray-700 rounded-lg mono text-sm"></textarea>
                            </div>
                            <button type="submit" class="w-full py-3 bg-janus-green hover:bg-green-600 rounded-lg font-semibold text-black transition-all">
                                👻 Detect Shadow APIs
                            </button>
                        </form>
                    </div>

                    <!-- GraphQL Tab -->
                    <div id="panel-graphql" class="bg-janus-card rounded-xl p-6 border border-gray-800 glow-purple hidden">
                        <h2 class="text-lg font-semibold mb-4">💥 GraphQL Attacker</h2>
                        <form id="graphqlForm" class="space-y-4">
                            <div>
                                <label class="block text-sm text-gray-400 mb-1">GraphQL Endpoint</label>
                                <input type="text" name="url" placeholder="https://api.target.com/graphql" 
                                       class="w-full px-3 py-2 bg-janus-bg border border-gray-700 rounded-lg mono text-sm">
                            </div>
                            <div>
                                <label class="block text-sm text-gray-400 mb-1">Auth Token (optional)</label>
                                <input type="text" name="token" placeholder="Bearer token..." 
                                       class="w-full px-3 py-2 bg-janus-bg border border-gray-700 rounded-lg mono text-sm">
                            </div>
                            <div class="flex items-center gap-2">
                                <input type="checkbox" name="full_scan" id="fullScan" checked class="rounded">
                                <label for="fullScan" class="text-sm text-gray-400">Full Scan (includes DoS tests)</label>
                            </div>
                            <button type="submit" class="w-full py-3 bg-janus-purple hover:bg-purple-600 rounded-lg font-semibold transition-all">
                                💥 Attack GraphQL
                            </button>
                        </form>
                    </div>

                    <!-- JWT Tab -->
                    <div id="panel-jwt" class="bg-janus-card rounded-xl p-6 border border-gray-800 glow hidden">
                        <h2 class="text-lg font-semibold mb-4">🔐 JWT Attacker</h2>
                        <form id="jwtForm" class="space-y-4">
                            <div>
                                <label class="block text-sm text-gray-400 mb-1">JWT Token</label>
                                <textarea name="token" rows="3" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                                          class="w-full px-3 py-2 bg-janus-bg border border-gray-700 rounded-lg mono text-sm"></textarea>
                            </div>
                            <div class="grid grid-cols-2 gap-2">
                                <label class="flex items-center gap-2 text-sm text-gray-400">
                                    <input type="checkbox" name="alg_none" checked class="rounded"> alg:none
                                </label>
                                <label class="flex items-center gap-2 text-sm text-gray-400">
                                    <input type="checkbox" name="weak_secret" checked class="rounded"> Weak Secret
                                </label>
                            </div>
                            <button type="submit" class="w-full py-3 bg-janus-accent hover:bg-red-600 rounded-lg font-semibold transition-all">
                                🔐 Attack JWT
                            </button>
                        </form>
                    </div>

                    <!-- Mass Assignment Tab -->
                    <div id="panel-mass" class="bg-janus-card rounded-xl p-6 border border-gray-800 glow-blue hidden">
                        <h2 class="text-lg font-semibold mb-4">📝 Mass Assignment</h2>
                        <form id="massForm" class="space-y-4">
                            <div>
                                <label class="block text-sm text-gray-400 mb-1">Endpoint URL</label>
                                <input type="text" name="endpoint" value="http://localhost:5000/api/profile/10" 
                                       class="w-full px-3 py-2 bg-janus-bg border border-gray-700 rounded-lg mono text-sm">
                            </div>
                            <div>
                                <label class="block text-sm text-gray-400 mb-1">Auth Token</label>
                                <input type="text" name="token" value="token_alice_123" 
                                       class="w-full px-3 py-2 bg-janus-bg border border-gray-700 rounded-lg mono text-sm">
                            </div>
                            <div>
                                <label class="block text-sm text-gray-400 mb-1">HTTP Method</label>
                                <select name="method" class="w-full px-3 py-2 bg-janus-bg border border-gray-700 rounded-lg text-sm">
                                    <option value="PUT">PUT</option>
                                    <option value="PATCH">PATCH</option>
                                    <option value="POST">POST</option>
                                </select>
                            </div>
                            <button type="submit" class="w-full py-3 bg-janus-blue hover:bg-blue-600 rounded-lg font-semibold transition-all">
                                📝 Test Mass Assignment
                            </button>
                        </form>
                    </div>

                    <!-- BFLA Tab (New) -->
                    <div id="panel-bfla" class="bg-janus-card rounded-xl p-6 border border-gray-800 glow hidden">
                        <h2 class="text-lg font-semibold mb-4">🔓 BFLA Scanner</h2>
                        <form id="bflaForm" class="space-y-4">
                            <div>
                                <label class="block text-sm text-gray-400 mb-1">Target Host</label>
                                <input type="text" name="host" value="http://localhost:5000" 
                                       class="w-full px-3 py-2 bg-janus-bg border border-gray-700 rounded-lg mono text-sm">
                            </div>
                             <div>
                                <label class="block text-sm text-gray-400 mb-1">Low Privilege Token</label>
                                <input type="text" name="low_token" value="token_bob_456" 
                                       class="w-full px-3 py-2 bg-janus-bg border border-gray-700 rounded-lg mono text-sm">
                            </div>
                            <button type="submit" class="w-full py-3 bg-janus-accent hover:bg-red-600 rounded-lg font-semibold transition-all">
                                🔓 Scan for BFLA
                            </button>
                        </form>
                    </div>

                    <!-- PII Scanner Tab (New) -->
                    <div id="panel-pii" class="bg-janus-card rounded-xl p-6 border border-gray-800 glow-blue hidden">
                        <h2 class="text-lg font-semibold mb-4">🔍 PII & Secrets Scanner</h2>
                        <form id="piiForm" class="space-y-4">
                            <div>
                                <label class="block text-sm text-gray-400 mb-1">Target URL</label>
                                <input type="text" name="url" value="http://localhost:5000/api/debug/user/10" 
                                       class="w-full px-3 py-2 bg-janus-bg border border-gray-700 rounded-lg mono text-sm">
                            </div>
                             <div>
                                <label class="block text-sm text-gray-400 mb-1">Auth Token (Optional)</label>
                                <input type="text" name="token" 
                                       class="w-full px-3 py-2 bg-janus-bg border border-gray-700 rounded-lg mono text-sm">
                            </div>
                            <button type="submit" class="w-full py-3 bg-janus-blue hover:bg-blue-600 rounded-lg font-semibold transition-all">
                                🔍 Scan for PII
                            </button>
                        </form>
                    </div>

                    <!-- Race Condition Tab (New) -->
                    <div id="panel-race" class="bg-janus-card rounded-xl p-6 border border-gray-800 glow-purple hidden">
                        <h2 class="text-lg font-semibold mb-4">⚡ Race Condition</h2>
                        <form id="raceForm" class="space-y-4">
                            <div>
                                <label class="block text-sm text-gray-400 mb-1">Target Endpoint</label>
                                <input type="text" name="url" value="http://localhost:5000/api/wallet/withdraw" 
                                       class="w-full px-3 py-2 bg-janus-bg border border-gray-700 rounded-lg mono text-sm">
                            </div>
                             <div>
                                <label class="block text-sm text-gray-400 mb-1">Auth Token</label>
                                <input type="text" name="token" value="token_alice_123" 
                                       class="w-full px-3 py-2 bg-janus-bg border border-gray-700 rounded-lg mono text-sm">
                            </div>
                            <div class="grid grid-cols-2 gap-4">
                                <div>
                                    <label class="block text-sm text-gray-400 mb-1">Threads</label>
                                    <input type="number" name="threads" value="10" 
                                           class="w-full px-3 py-2 bg-janus-bg border border-gray-700 rounded-lg mono text-sm">
                                </div>
                                <div>
                                    <label class="block text-sm text-gray-400 mb-1">Amount</label>
                                    <input type="number" name="amount" value="20" 
                                           class="w-full px-3 py-2 bg-janus-bg border border-gray-700 rounded-lg mono text-sm">
                                </div>
                            </div>
                            <button type="submit" class="w-full py-3 bg-janus-purple hover:bg-purple-600 rounded-lg font-semibold transition-all">
                                ⚡ Test Race Condition
                            </button>
                        </form>
                    </div>

                    <!-- Stealth Tab (New) -->
                    <div id="panel-stealth" class="bg-janus-card rounded-xl p-6 border border-gray-800 glow-green hidden">
                        <h2 class="text-lg font-semibold mb-4">👻 Stealth Configuration</h2>
                        <div class="space-y-4 text-sm text-gray-300">
                            <p>Test WAF evasion capabilities including header rotation and Tor connectivity.</p>
                            <button onclick="testStealth()" class="w-full py-3 bg-janus-green hover:bg-green-600 rounded-lg font-semibold transition-all text-white">
                                👻 Test Configuration
                            </button>
                            <div id="stealthStatus" class="hidden space-y-2 mt-4 p-4 bg-janus-bg rounded-lg border border-gray-700">
                                <!-- Status populated by JS -->
                            </div>
                        </div>
                    </div>

                    <!-- Team Tab (New) -->
                    <div id="panel-team" class="bg-janus-card rounded-xl p-6 border border-gray-800 glow-blue hidden">
                        <h2 class="text-lg font-semibold mb-4">🐝 Hive-Mind Team</h2>
                        <div class="space-y-4">
                            <div>
                                <label class="block text-sm text-gray-400 mb-1">Team ID</label>
                                <input type="text" id="teamId" value="default" 
                                       class="w-full px-3 py-2 bg-janus-bg border border-gray-700 rounded-lg mono text-sm">
                            </div>
                            <button onclick="checkTeamStatus()" class="w-full py-3 bg-janus-blue hover:bg-blue-600 rounded-lg font-semibold transition-all text-white">
                                🔄 Check Team Status
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Right Panel: Results -->
                <div class="lg:col-span-2">
                    <div class="bg-janus-card rounded-xl p-6 border border-gray-800 min-h-[500px]">
                        <div class="flex items-center justify-between mb-4">
                            <h2 class="text-lg font-semibold">📊 Results</h2>
                            <button onclick="generateReport()" class="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm">
                                📄 Generate HTML Report
                            </button>
                        </div>
                        <div id="resultsContent" class="space-y-4">
                            <div class="text-gray-500 text-center py-20">
                                Select a module and run a scan to see results here.
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </main>

        <script>
            // Tab switching
            function showTab(tabName) {{
                // Hide all panels
                document.querySelectorAll('[id^="panel-"]').forEach(p => p.classList.add('hidden'));
                // Reset all tabs
                document.querySelectorAll('[id^="tab-"]').forEach(t => {{
                    t.classList.remove('tab-active');
                    t.classList.add('text-gray-400');
                }});
                // Show selected
                document.getElementById('panel-' + tabName).classList.remove('hidden');
                document.getElementById('tab-' + tabName).classList.add('tab-active');
                document.getElementById('tab-' + tabName).classList.remove('text-gray-400');
            }}

            // BOLA Scan
            document.getElementById('bolaForm').addEventListener('submit', async (e) => {{
                e.preventDefault();
                const formData = new FormData(e.target);
                showLoading('Running BOLA scan...');
                try {{
                    const response = await fetch('/scan', {{ method: 'POST', body: formData }});
                    const data = await response.json();
                    displayBOLAResults(data.results);
                }} catch (error) {{
                    showError(error.message);
                }}
            }});

            // CVE Lookup
            document.getElementById('cveForm').addEventListener('submit', async (e) => {{
                e.preventDefault();
                const formData = new FormData(e.target);
                showLoading('Checking CVEs...');
                try {{
                    const response = await fetch('/api/cve', {{ method: 'POST', body: formData }});
                    const data = await response.json();
                    displayCVEResults(data);
                }} catch (error) {{
                    showError(error.message);
                }}
            }});

            // Shadow API
            document.getElementById('shadowForm').addEventListener('submit', async (e) => {{
                e.preventDefault();
                const formData = new FormData(e.target);
                showLoading('Detecting shadow APIs...');
                try {{
                    const response = await fetch('/api/shadow', {{ method: 'POST', body: formData }});
                    const data = await response.json();
                    displayShadowResults(data);
                }} catch (error) {{
                    showError(error.message);
                }}
            }});

            // GraphQL
            document.getElementById('graphqlForm').addEventListener('submit', async (e) => {{
                e.preventDefault();
                const formData = new FormData(e.target);
                showLoading('Attacking GraphQL endpoint...');
                try {{
                    const response = await fetch('/api/graphql', {{ method: 'POST', body: formData }});
                    const data = await response.json();
                    displayGraphQLResults(data);
                }} catch (error) {{
                    showError(error.message);
                }}
            }});

            // JWT
            document.getElementById('jwtForm').addEventListener('submit', async (e) => {{
                e.preventDefault();
                const formData = new FormData(e.target);
                showLoading('Analyzing JWT...');
                try {{
                    const response = await fetch('/api/jwt', {{ method: 'POST', body: formData }});
                    const data = await response.json();
                    displayJWTResults(data);
                }} catch (error) {{
                    showError(error.message);
                }}
            }});

            // Mass Assignment
            document.getElementById('massForm').addEventListener('submit', async (e) => {{
                e.preventDefault();
                const formData = new FormData(e.target);
                showLoading('Testing mass assignment...');
                try {{
                    const response = await fetch('/api/mass-assignment', {{ method: 'POST', body: formData }});
                    const data = await response.json();
                    displayMassResults(data);
                }} catch (error) {{
                    showError(error.message);
                }}
            }});

            function showLoading(msg) {{
                document.getElementById('resultsContent').innerHTML = `
                    <div class="text-center py-20">
                        <div class="inline-block w-8 h-8 border-4 border-janus-accent border-t-transparent rounded-full spinner"></div>
                        <p class="mt-4 text-gray-400">${{msg}}</p>
                    </div>
                `;
            }}

            function showError(msg) {{
                document.getElementById('resultsContent').innerHTML = `
                    <div class="bg-red-900/30 border border-red-700 rounded-lg p-4">
                        <p class="text-red-400">❌ Error: ${{msg}}</p>
                    </div>
                `;
            }}

            function displayBOLAResults(data) {{
                let html = `
                    <div class="grid grid-cols-4 gap-4 mb-6">
                        <div class="bg-janus-bg p-4 rounded-lg text-center">
                            <div class="text-2xl font-bold">${{data.total_endpoints}}</div>
                            <div class="text-xs text-gray-400">Tested</div>
                        </div>
                        <div class="bg-janus-bg p-4 rounded-lg text-center">
                            <div class="text-2xl font-bold text-red-500">${{data.vulnerabilities_found}}</div>
                            <div class="text-xs text-gray-400">Vulnerable</div>
                        </div>
                        <div class="bg-janus-bg p-4 rounded-lg text-center">
                            <div class="text-2xl font-bold text-green-500">${{data.secure_endpoints}}</div>
                            <div class="text-xs text-gray-400">Secure</div>
                        </div>
                        <div class="bg-janus-bg p-4 rounded-lg text-center">
                            <div class="text-2xl font-bold text-yellow-500">${{data.needs_review}}</div>
                            <div class="text-xs text-gray-400">Review</div>
                        </div>
                    </div>
                `;
                html += '<div class="space-y-3">';
                for (const f of data.findings) {{
                    const color = f.status === 'VULNERABLE' ? 'red' : f.status === 'BLOCKED' ? 'green' : 'yellow';
                    html += `
                        <div class="bg-janus-bg p-4 rounded-lg border-l-4 border-${{color}}-500">
                            <div class="flex justify-between mb-2">
                                <span class="mono text-sm">${{f.endpoint}}</span>
                                <span class="text-${{color}}-500 font-bold">${{f.status}}</span>
                            </div>
                            <div class="text-xs text-gray-400">${{f.evidence}}</div>
                            <div class="mt-2 text-xs">Confidence: ${{(f.confidence * 100).toFixed(0)}}% | Severity: ${{f.severity}}</div>
                        </div>
                    `;
                }}
                html += '</div>';
                document.getElementById('resultsContent').innerHTML = html;
            }}

            function displayCVEResults(data) {{
                if (data.technologies) {{
                    let html = '<div class="mb-4"><h3 class="font-semibold mb-2">Detected Technologies</h3><div class="space-y-2">';
                    for (const t of data.technologies) {{
                        html += `<div class="bg-janus-bg p-3 rounded-lg"><span class="text-blue-400">${{t.name}}</span> ${{t.version || '(unknown)'}}</div>`;
                    }}
                    html += '</div></div>';

                    if (data.cves && data.cves.length > 0) {{
                        html += '<h3 class="font-semibold mb-2 text-red-400">⚠️ Found CVEs</h3><div class="space-y-2">';
                        for (const c of data.cves) {{
                            const color = c.severity === 'CRITICAL' ? 'red' : 'yellow';
                            html += `
                                <div class="bg-janus-bg p-4 rounded-lg border-l-4 border-${{color}}-500">
                                    <div class="font-bold text-${{color}}-400">${{c.cve_id}} (CVSS: ${{c.cvss_score}})</div>
                                    <div class="text-sm text-gray-400 mt-1">${{c.description}}</div>
                                    ${{c.exploited_in_wild ? '<div class="text-red-500 text-xs mt-2">⚡ EXPLOITED IN WILD</div>' : ''}}
                                </div>
                            `;
                        }}
                        html += '</div>';
                    }} else {{
                        html += '<div class="text-green-400 text-center py-4">✓ No HIGH/CRITICAL CVEs found</div>';
                    }}
                    document.getElementById('resultsContent').innerHTML = html;
                }}
            }}

            function displayShadowResults(data) {{
                let html = `<div class="mb-4 text-sm text-gray-400">Observed: ${{data.total_observed}} | Documented: ${{data.total_documented}} | Shadow: ${{data.shadow_count}}</div>`;
                if (data.shadow_apis && data.shadow_apis.length > 0) {{
                    html += '<div class="space-y-2">';
                    for (const s of data.shadow_apis) {{
                        const color = s.risk_level === 'CRITICAL' ? 'red' : s.risk_level === 'HIGH' ? 'yellow' : 'blue';
                        html += `
                            <div class="bg-janus-bg p-4 rounded-lg border-l-4 border-${{color}}-500">
                                <div class="flex justify-between">
                                    <span class="mono">${{s.method}} ${{s.endpoint}}</span>
                                    <span class="text-${{color}}-400">${{s.risk_level}}</span>
                                </div>
                                <div class="text-xs text-gray-400 mt-1">${{s.reason}}</div>
                            </div>
                        `;
                    }}
                    html += '</div>';
                }} else {{
                    html += '<div class="text-green-400 text-center py-4">✓ All endpoints documented</div>';
                }}
                document.getElementById('resultsContent').innerHTML = html;
            }}

            function displayGraphQLResults(data) {{
                let html = '<div class="space-y-3">';
                for (const r of data.results) {{
                    const color = r.vulnerable ? 'red' : 'green';
                    html += `
                        <div class="bg-janus-bg p-4 rounded-lg border-l-4 border-${{color}}-500">
                            <div class="flex justify-between mb-2">
                                <span class="font-bold">${{r.attack_type}}</span>
                                <span class="text-${{color}}-400">${{r.vulnerable ? '🚨 VULNERABLE' : '✓ SECURE'}}</span>
                            </div>
                            <div class="text-sm text-gray-400">${{r.evidence}}</div>
                            ${{r.recommendation ? `<div class="text-xs text-yellow-400 mt-2">→ ${{r.recommendation}}</div>` : ''}}
                        </div>
                    `;
                }}
                html += '</div>';
                document.getElementById('resultsContent').innerHTML = html;
            }}

            function displayJWTResults(data) {{
                let html = `
                    <div class="bg-janus-bg p-4 rounded-lg mb-4">
                        <div class="grid grid-cols-2 gap-4">
                            <div><span class="text-gray-400">Algorithm:</span> <span class="text-blue-400">${{data.algorithm}}</span></div>
                            <div><span class="text-gray-400">Valid:</span> <span class="${{data.valid ? 'text-green-400' : 'text-red-400'}}">${{data.valid ? 'Yes' : 'No'}}</span></div>
                        </div>
                    </div>
                `;
                if (data.security_issues && data.security_issues.length > 0) {{
                    html += '<h3 class="font-semibold mb-2 text-yellow-400">⚠️ Security Issues</h3><ul class="list-disc list-inside space-y-1 mb-4">';
                    for (const issue of data.security_issues) {{
                        html += `<li class="text-sm text-gray-300">${{issue}}</li>`;
                    }}
                    html += '</ul>';
                }}
                if (data.attacks) {{
                    html += '<h3 class="font-semibold mb-2">Attack Results</h3><div class="space-y-2">';
                    for (const a of data.attacks) {{
                        const color = a.vulnerable ? 'red' : 'green';
                        html += `
                            <div class="bg-janus-bg p-3 rounded-lg border-l-4 border-${{color}}-500">
                                <span class="font-bold">${{a.attack_type}}</span>: 
                                <span class="text-${{color}}-400">${{a.vulnerable ? 'Vulnerable' : 'Secure'}}</span>
                                <div class="text-xs text-gray-400">${{a.evidence}}</div>
                            </div>
                        `;
                    }}
                    html += '</div>';
                }}
                document.getElementById('resultsContent').innerHTML = html;
            }}

            function displayMassResults(data) {{
                const color = data.vulnerable ? 'red' : 'green';
                let html = `
                    <div class="bg-janus-bg p-6 rounded-lg border-l-4 border-${{color}}-500 mb-4">
                        <div class="text-xl font-bold text-${{color}}-400 mb-2">${{data.vulnerable ? '🚨 VULNERABLE' : '✓ SECURE'}}</div>
                        <div class="text-sm text-gray-400">Response Status: ${{data.response_status}}</div>
                    </div>
                `;
                if (data.accepted_fields && data.accepted_fields.length > 0) {{
                    html += `
                        <div class="mb-4">
                            <h3 class="font-semibold mb-2 text-yellow-400">Accepted Fields</h3>
                            <div class="flex flex-wrap gap-2">
                `;
                    for (const f of data.accepted_fields) {{
                        html += `<span class="px-2 py-1 bg-yellow-900/50 text-yellow-300 rounded text-sm">${{f}}</span>`;
                    }}
                    html += '</div></div>';
                }}
                if (data.reflected_fields && data.reflected_fields.length > 0) {{
                    html += `
                        <div>
                            <h3 class="font-semibold mb-2 text-red-400">Reflected in Response (CRITICAL)</h3>
                            <div class="flex flex-wrap gap-2">
                `;
                    for (const f of data.reflected_fields) {{
                        html += `<span class="px-2 py-1 bg-red-900/50 text-red-300 rounded text-sm">${{f}}</span>`;
                    }}
                    html += '</div></div>';
                }}
                document.getElementById('resultsContent').innerHTML = html;
            }}


            // BFLA Scan
            document.getElementById('bflaForm').addEventListener('submit', async (e) => {{
                e.preventDefault();
                showLoading('Running BFLA Scan...');
                try {{
                    const response = await fetch('/api/bfla', {{ method: 'POST', body: new FormData(e.target) }});
                    const data = await response.json();
                    displayBFLAResults(data);
                }} catch (error) {{ showError(error.message); }}
            }});

            // PII Scan
            document.getElementById('piiForm').addEventListener('submit', async (e) => {{
                e.preventDefault();
                showLoading('Scanning for PII & Secrets...');
                try {{
                    const response = await fetch('/api/pii', {{ method: 'POST', body: new FormData(e.target) }});
                    const data = await response.json();
                    displayPIIResults(data);
                }} catch (error) {{ showError(error.message); }}
            }});

            // Race Condition Scan
            document.getElementById('raceForm').addEventListener('submit', async (e) => {{
                e.preventDefault();
                showLoading('Testing for Race Conditions...');
                try {{
                    const response = await fetch('/api/race', {{ method: 'POST', body: new FormData(e.target) }});
                    const data = await response.json();
                    displayRaceResults(data);
                }} catch (error) {{ showError(error.message); }}
            }});

            function displayBFLAResults(data) {{
                let html = `<div class="space-y-4">
                    <div class="flex items-center justify-between">
                        <h3 class="font-bold text-lg text-janus-accent">BFLA Scan Results</h3>
                        <span class="px-3 py-1 bg-red-900/50 text-red-200 rounded-full text-sm">${{data.vulnerable_count}} Vulnerable</span>
                    </div>
                `;
                
                data.findings.forEach(f => {{
                    html += `
                        <div class="bg-janus-bg p-4 rounded-lg border ${{f.vulnerable ? 'border-red-500' : 'border-green-500'}}">
                            <div class="flex justify-between items-start mb-2">
                                <div class="font-mono text-sm font-bold ${{f.vulnerable ? 'text-red-400' : 'text-green-400'}}">
                                    ${{f.method}} ${{f.endpoint}}
                                </div>
                                <span class="text-xs px-2 py-1 rounded bg-gray-800">${{f.severity}}</span>
                            </div>
                            <p class="text-sm text-gray-400">${{f.evidence}}</p>
                            ${{f.recommendation ? `<div class="mt-2 text-xs text-gray-500 border-t border-gray-700 pt-2">💡 ${{f.recommendation}}</div>` : ''}}
                        </div>
                    `;
                }});
                document.getElementById('resultsContent').innerHTML = html + '</div>';
            }}

            function displayPIIResults(data) {{
                let html = `<div class="space-y-4">
                    <div class="flex items-center justify-between">
                        <h3 class="font-bold text-lg text-blue-400">PII & Secrets Scan</h3>
                        <div class="flex gap-2">
                             <span class="px-3 py-1 bg-red-900/50 text-red-200 rounded-full text-sm">Risk: ${{data.risk_score}}/10</span>
                             <span class="px-3 py-1 bg-blue-900/50 text-blue-200 rounded-full text-sm">${{data.findings_count}} Findings</span>
                        </div>
                    </div>
                    ${{data.compliance_violations.length ? 
                        `<div class="bg-red-900/20 p-3 rounded text-red-300 text-sm">🚫 Violations: ${{data.compliance_violations.join(', ')}}</div>` : ''}}
                `;
                
                data.findings.forEach(f => {{
                    html += `
                        <div class="bg-janus-bg p-4 rounded-lg border border-gray-700">
                            <div class="flex justify-between mb-1">
                                <span class="font-bold text-yellow-400">${{f.data_type}}</span>
                                <span class="text-xs text-red-400 font-bold">${{f.severity}}</span>
                            </div>
                            <div class="text-xs font-mono text-gray-500 mb-2">Path: ${{f.field_path}}</div>
                            <p class="text-sm text-gray-400">${{f.evidence}}</p>
                        </div>
                    `;
                }});
                document.getElementById('resultsContent').innerHTML = html + '</div>';
            }}

            function displayRaceResults(data) {{
                const color = data.vulnerable ? 'text-red-500' : 'text-green-500';
                const status = data.vulnerable ? 'VULNERABLE' : 'SAFE';
                
                let html = `
                    <div class="bg-janus-bg p-6 rounded-xl border ${{data.vulnerable ? 'border-red-500' : 'border-green-500'}} text-center">
                        <div class="text-4xl mb-4">${{data.vulnerable ? '🚨' : '✅'}}</div>
                        <h3 class="text-2xl font-bold ${{color}} mb-2">${{status}}</h3>
                        <p class="text-gray-400 text-sm mb-6">${{data.evidence}}</p>
                        
                        <div class="grid grid-cols-3 gap-4 text-left">
                            <div class="bg-janus-card p-3 rounded">
                                <div class="text-xs text-gray-500">Success Rate</div>
                                <div class="font-mono font-bold">${{data.successful_requests}}/${{data.requests_sent}}</div>
                            </div>
                            <div class="bg-janus-card p-3 rounded">
                                <div class="text-xs text-gray-500">Timing Spread</div>
                                <div class="font-mono font-bold">${{data.timing_spread_ms.toFixed(2)}} ms</div>
                            </div>
                            <div class="bg-janus-card p-3 rounded">
                                <div class="text-xs text-gray-500">Severity</div>
                                <div class="font-mono font-bold ${{color}}">${{data.severity}}</div>
                            </div>
                        </div>
                        
                        ${{data.recommendation ? `
                        <div class="mt-6 text-left bg-gray-800/50 p-4 rounded border border-gray-700">
                            <h4 class="font-bold text-gray-300 mb-2">Recommendation</h4>
                            <p class="text-sm text-gray-400">${{data.recommendation}}</p>
                        </div>` : ''}}
                    </div>
                `;
                document.getElementById('resultsContent').innerHTML = html;
            }}


            function generateReport() {{
                fetch('/api/sarif', {{ method: 'POST' }})
                    .then(r => r.json())
                    .then(d => {{
                         alert('Generated SARIF report with ' + d.findings + ' findings!');
                         // Also trigger normal HTML report generation
                         fetch('/api/report').then(r => r.json()).then(res => window.open('/report/download', '_blank'));
                    }});
            }}

            function testStealth() {{
                fetch('/api/stealth')
                    .then(r => r.json())
                    .then(data => {{
                        const statusDiv = document.getElementById('stealthStatus');
                        statusDiv.classList.remove('hidden');
                        statusDiv.innerHTML = `
                            <div class="flex items-center gap-2">
                                <span class="text-green-400">●</span>
                                <span>Tor Available: ${{data.tor_available ? 'Yes' : 'No'}}</span>
                            </div>
                            <div class="mono text-xs text-gray-500 mt-2">
                                ${{JSON.stringify(data.headers, null, 2)}}
                            </div>
                        `;
                    }});
            }}

            function checkTeamStatus() {{
                const teamId = document.getElementById('teamId').value;
                fetch('/api/team?team_id=' + teamId)
                    .then(r => r.json())
                    .then(data => {{
                        const resultsContent = document.getElementById('resultsContent');
                        resultsContent.innerHTML = `
                            <h3 class="font-bold text-lg mb-4 text-blue-400">Team Status: ${{data.team_id}}</h3>
                            <div class="grid grid-cols-2 gap-4">
                                <div class="bg-janus-bg p-4 rounded-lg">
                                    <div class="text-gray-400 text-sm">Active Users</div>
                                    <div class="text-2xl font-bold">${{data.active_users}}</div>
                                </div>
                                <div class="bg-janus-bg p-4 rounded-lg">
                                    <div class="text-gray-400 text-sm">Total Findings</div>
                                    <div class="text-2xl font-bold text-red-400">${{data.total_findings}}</div>
                                </div>
                            </div>
                            <div class="mt-4 text-xs text-gray-500">
                                Connected as: ${{data.user}} <br>
                                Redis Status: ${{data.connected ? 'Online' : 'Offline (Local Mode)'}}
                            </div>
                        `;
                    }});
            }}
        </script>
    </body>
    </html>
    """


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Render the main dashboard."""
    db = JanusDatabase()
    tokens = db.get_all_tokens()
    return get_dashboard_html(tokens)


@app.post("/scan")
async def run_scan(
    host: str = Form(...),
    victim_token: str = Form(...),
    attacker_token: str = Form(...)
):
    """Execute a BOLA scan."""
    engine = JanusEngine()
    report = engine.launch_attack(victim_token, attacker_token, host)
    scan_results[report.scan_id] = report
    return {"status": "complete", "results": report.to_dict()}


@app.post("/api/cve")
async def check_cve(
    url: str = Form(...),
    tech: str = Form(""),
    version: str = Form("")
):
    """Check for CVEs."""
    lookup = CVELookup()
    
    if tech:
        cves = lookup.check_cve(tech, version if version else None)
        return {
            "technologies": [{"name": tech, "version": version}],
            "cves": [c.to_dict() for c in cves]
        }
    else:
        tech_detected, cves = lookup.scan_target(url)
        return {
            "technologies": [{"name": t.name, "version": t.version, "source": t.source} for t in tech_detected],
            "cves": [c.to_dict() for c in cves]
        }


@app.post("/api/shadow")
async def detect_shadow(openapi_spec: str = Form("")):
    """Detect shadow APIs."""
    detector = ShadowAPIDetector()
    
    if openapi_spec.strip():
        try:
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                f.write(openapi_spec)
                detector.load_openapi_spec(f.name)
        except:
            pass
    
    db = JanusDatabase()
    detector.load_from_database(db)
    shadow_apis = detector.detect_shadow_apis()
    
    return {
        "total_observed": len(detector.observed_endpoints),
        "total_documented": len(detector.documented_endpoints),
        "shadow_count": len(shadow_apis),
        "shadow_apis": [s.to_dict() for s in shadow_apis]
    }


@app.post("/api/graphql")
async def attack_graphql(
    url: str = Form(...),
    token: str = Form(""),
    full_scan: bool = Form(True)
):
    """Attack a GraphQL endpoint."""
    attacker = GraphQLAttacker()
    headers = {"Authorization": f"Bearer {token}"} if token else None
    results = attacker.scan_graphql(url, headers, full_scan)
    return {"results": [r.to_dict() for r in results]}


@app.post("/api/jwt")
async def analyze_jwt(
    token: str = Form(...),
    alg_none: bool = Form(True),
    weak_secret: bool = Form(True)
):
    """Analyze and attack a JWT."""
    attacker = JWTAttacker()
    analysis = attacker.analyze_jwt(token)
    
    attacks = []
    if alg_none:
        result = attacker.attack_alg_none(token)
        attacks.append(result.to_dict())
    if weak_secret:
        results = attacker.attack_weak_secret(token)
        attacks.extend([r.to_dict() for r in results])
    
    return {
        "algorithm": analysis.get("algorithm"),
        "valid": analysis.get("valid_structure"),
        "security_issues": analysis.get("security_issues", []),
        "claims": analysis.get("payload", {}),
        "attacks": attacks
    }


@app.post("/api/mass-assignment")
async def test_mass_assignment(
    endpoint: str = Form(...),
    token: str = Form(...),
    method: str = Form("PUT")
):
    """Test for mass assignment vulnerability."""
    tester = MassAssignmentTester()
    result = tester.test_mass_assignment(
        endpoint=endpoint,
        original_body={},
        token=token,
        method=method
    )
    return {
        "vulnerable": result.vulnerable,
        "response_status": result.response_status,
        "accepted_fields": result.accepted_fields,
        "reflected_fields": result.reflected_fields,
        "severity": result.severity
    }


@app.get("/api/report")
async def generate_report():
    """Generate an HTML report."""
    if not scan_results:
        return {"error": "No scans to report"}
    
    latest_scan = list(scan_results.values())[-1]
    generator = HTMLReportGenerator()
    html = generator.from_scan_report(latest_scan.to_dict())
    generator.save_report(html, "janus_web_report.html")
    return {"status": "generated", "file": "janus_web_report.html"}


@app.get("/report/download")
async def download_report():
    """Download the generated report."""
    report_path = "janus_web_report.html"
    if os.path.exists(report_path):
        return FileResponse(report_path, filename="janus_security_report.html")
    return JSONResponse(status_code=404, content={"error": "Report not found"})


@app.get("/api/tokens")
async def list_tokens():
    """API endpoint to list learned tokens."""
    db = JanusDatabase()
    tokens = db.get_all_tokens()
    return {"tokens": [{"token": t, "resources": len(db.get_learnings(t))} for t in tokens]}


# =============================================================================
# PHASE 5 & 6 API ENDPOINTS
# =============================================================================

@app.post("/api/bfla")
async def test_bfla(
    host: str = Form("http://localhost:5000"),
    low_token: str = Form(...),
    endpoints: str = Form(None)
):
    """Test for BFLA (Broken Function Level Authorization)."""
    scanner = BFLAScanner()
    
    if endpoints:
        endpoint_list = [e.strip() for e in endpoints.split(',')]
    else:
        endpoint_list = [
            '/api/admin/users',
            '/api/admin/config',
            '/api/admin/export',
            '/api/admin/dashboard',
            '/api/admin/settings',
        ]
    
    results = scanner.scan_endpoints(
        base_url=host,
        endpoints=endpoint_list,
        low_priv_token=low_token
    )
    
    return {
        "vulnerable_count": sum(1 for r in results if r.vulnerable),
        "total_tested": len(results),
        "findings": [r.to_dict() for r in results]
    }


@app.post("/api/pii")
async def scan_pii(
    url: str = Form(...),
    token: str = Form(None)
):
    """Scan for PII and sensitive data leaks."""
    import requests
    
    headers = {}
    if token:
        headers['Authorization'] = token
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        body = response.json()
    except Exception as e:
        return {"error": str(e)}
    
    scanner = PIIScanner(strict_mode=True)
    result = scanner.scan_response(body, url)
    
    return {
        "findings_count": len(result.findings),
        "risk_score": result.risk_score,
        "compliance_violations": result.compliance_violations,
        "findings": [f.to_dict() for f in result.findings]
    }


@app.post("/api/race")
async def test_race(
    url: str = Form(...),
    token: str = Form(...),
    amount: float = Form(20),
    threads: int = Form(10)
):
    """Test for race condition vulnerabilities."""
    tester = RaceConditionTester()
    result = tester.test_race_condition(
        endpoint=url,
        method="POST",
        body={"amount": amount},
        token=token,
        threads=threads
    )
    
    return {
        "vulnerable": result.vulnerable,
        "severity": result.severity,
        "requests_sent": result.requests_sent,
        "successful_requests": result.successful_requests,
        "timing_spread_ms": result.timing_spread_ms,
        "evidence": result.evidence,
        "recommendation": result.recommendation
    }


@app.get("/api/stealth")
async def test_stealth():
    """Test stealth mode configuration."""
    config = StealthConfig(enabled=True, min_delay=0.5, max_delay=2.0)
    ghost = GhostWalker(config)
    headers = ghost.get_stealth_headers("https://example.com")
    tor_available = ghost.check_tor()
    
    return {
        "headers": headers,
        "tor_available": tor_available,
        "jitter_range": f"{config.min_delay}s - {config.max_delay}s",
        "status": "ready"
    }


@app.get("/api/team")
async def team_status(team_id: str = "default"):
    """Get team collaboration status."""
    hive = HiveMind(team_id=team_id)
    connected = hive.connect()
    stats = hive.get_team_stats()
    hive.disconnect()
    
    return stats


@app.post("/api/sarif")
async def export_sarif():
    """Export scan results to SARIF format."""
    if not scan_results:
        return {"error": "No scans to export"}
    
    latest_scan = list(scan_results.values())[-1]
    reporter = SARIFReporter()
    reporter.from_scan_report(latest_scan.to_dict())
    reporter.save("janus_sarif.json")
    
    return {
        "status": "generated",
        "file": "janus_sarif.json",
        "findings": len(reporter.results)
    }


def run_server(host: str = "0.0.0.0", port: int = 8000):
    """Run the web server."""
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_server()
