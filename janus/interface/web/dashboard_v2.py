# janus/interface/web/dashboard_v2.py
"""
Janus Dashboard V2 - Modern Categorized Security Platform.

Features:
- Categorized sidebar navigation
- Improved UI/UX with gradients and animations
- All 15+ security modules
- Real-time scan results
"""


def get_modern_dashboard_html(tokens: list) -> str:
    """Generate the modern categorized dashboard HTML."""
    
    token_options = "".join([f'<option value="{t}">{t[:40]}...</option>' for t in tokens])
    
    return f'''
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Janus Security Platform</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.ico">
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {{
            darkMode: 'class',
            theme: {{
                extend: {{
                    colors: {{
                        dark: {{ 900: '#0d1117', 800: '#161b22', 700: '#21262d', 600: '#30363d' }},
                        accent: {{ DEFAULT: '#f43f5e', light: '#fb7185' }},
                        cyber: {{ blue: '#38bdf8', green: '#4ade80', purple: '#a78bfa', orange: '#fb923c' }}
                    }}
                }}
            }}
        }}
    </script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        body {{ font-family: 'Inter', sans-serif; }}
        .mono {{ font-family: 'JetBrains Mono', monospace; }}
        
        /* Sidebar styling */
        .sidebar-item {{ transition: all 0.2s; }}
        .sidebar-item:hover {{ background: rgba(248, 113, 113, 0.1); border-left-color: #f43f5e; }}
        .sidebar-item.active {{ background: rgba(248, 113, 113, 0.15); border-left-color: #f43f5e; color: #f43f5e; }}
        
        /* Category headers */
        .category-header {{ font-size: 0.65rem; letter-spacing: 0.1em; }}
        
        /* Card glow effects */
        .card-glow {{ box-shadow: 0 0 40px rgba(244, 63, 94, 0.1); }}
        .card-glow-blue {{ box-shadow: 0 0 40px rgba(56, 189, 248, 0.1); }}
        .card-glow-green {{ box-shadow: 0 0 40px rgba(74, 222, 128, 0.1); }}
        .card-glow-purple {{ box-shadow: 0 0 40px rgba(167, 139, 250, 0.1); }}
        
        /* Gradient backgrounds */
        .gradient-accent {{ background: linear-gradient(135deg, #f43f5e 0%, #ec4899 100%); }}
        .gradient-blue {{ background: linear-gradient(135deg, #38bdf8 0%, #6366f1 100%); }}
        .gradient-green {{ background: linear-gradient(135deg, #4ade80 0%, #22d3ee 100%); }}
        .gradient-purple {{ background: linear-gradient(135deg, #a78bfa 0%, #f472b6 100%); }}
        
        /* Animations */
        .pulse-glow {{ animation: pulse-glow 2s infinite; }}
        @keyframes pulse-glow {{ 
            0%, 100% {{ opacity: 1; }} 
            50% {{ opacity: 0.7; }}
        }}
        
        /* Scrollbar */
        ::-webkit-scrollbar {{ width: 8px; }}
        ::-webkit-scrollbar-track {{ background: #161b22; }}
        ::-webkit-scrollbar-thumb {{ background: #30363d; border-radius: 4px; }}
        ::-webkit-scrollbar-thumb:hover {{ background: #484f58; }}
        
        /* Button hover */
        .btn-primary {{ transition: all 0.3s; }}
        .btn-primary:hover {{ transform: translateY(-2px); box-shadow: 0 10px 20px rgba(244, 63, 94, 0.3); }}
    </style>
</head>
<body class="bg-dark-900 text-gray-100 min-h-screen flex">
    
    <!-- Sidebar -->
    <aside class="w-64 bg-dark-800 border-r border-dark-600 flex flex-col fixed h-full">
        <!-- Logo -->
        <div class="p-5 border-b border-dark-600">
            <div class="flex items-center gap-3">
                <div class="w-10 h-10 gradient-accent rounded-lg flex items-center justify-center text-xl">🔱</div>
                <div>
                    <h1 class="font-bold text-lg">JANUS</h1>
                    <p class="text-xs text-gray-500">Security Platform v3.0</p>
                </div>
            </div>
        </div>
        
        <!-- Navigation -->
        <nav class="flex-1 overflow-y-auto py-4">
            <!-- Auto Scan - Full Assessment -->
            <div class="px-4 mb-4">
                <h3 class="category-header text-gray-500 uppercase font-semibold mb-2 px-3">🎯 Full Scan</h3>
                <button onclick="showPanel('autoscan')" class="sidebar-item active w-full text-left px-3 py-2 rounded-lg text-sm border-l-2 border-transparent flex items-center gap-2 bg-gradient-to-r from-accent/20 to-transparent">
                    <span class="text-accent">🚀</span> <strong>Auto Scanner</strong>
                </button>
            </div>
            
            <!-- Authorization Category -->
            <div class="px-4 mb-4">
                <h3 class="category-header text-gray-500 uppercase font-semibold mb-2 px-3">🔐 Authorization</h3>
                <button onclick="showPanel('bola')" class="sidebar-item w-full text-left px-3 py-2 rounded-lg text-sm border-l-2 border-transparent flex items-center gap-2">
                    <span class="text-accent">⚡</span> BOLA/IDOR
                </button>
                <button onclick="showPanel('bfla')" class="sidebar-item w-full text-left px-3 py-2 rounded-lg text-sm border-l-2 border-transparent flex items-center gap-2">
                    <span class="text-cyber-purple">🔓</span> BFLA
                </button>
                <button onclick="showPanel('jwt')" class="sidebar-item w-full text-left px-3 py-2 rounded-lg text-sm border-l-2 border-transparent flex items-center gap-2">
                    <span class="text-cyber-blue">🔑</span> JWT Attacks
                </button>
                <button onclick="showPanel('mass')" class="sidebar-item w-full text-left px-3 py-2 rounded-lg text-sm border-l-2 border-transparent flex items-center gap-2">
                    <span class="text-cyber-orange">📝</span> Mass Assignment
                </button>
            </div>
            
            <!-- Injection Category -->
            <div class="px-4 mb-4">
                <h3 class="category-header text-gray-500 uppercase font-semibold mb-2 px-3">💉 Injection</h3>
                <button onclick="showPanel('sqli')" class="sidebar-item w-full text-left px-3 py-2 rounded-lg text-sm border-l-2 border-transparent flex items-center gap-2">
                    <span class="text-accent">🗄️</span> SQL Injection
                </button>
                <button onclick="showPanel('xss')" class="sidebar-item w-full text-left px-3 py-2 rounded-lg text-sm border-l-2 border-transparent flex items-center gap-2">
                    <span class="text-cyber-orange">💥</span> XSS
                </button>
                <button onclick="showPanel('ssrf')" class="sidebar-item w-full text-left px-3 py-2 rounded-lg text-sm border-l-2 border-transparent flex items-center gap-2">
                    <span class="text-cyber-blue">🌐</span> SSRF
                </button>
                <button onclick="showPanel('lfi')" class="sidebar-item w-full text-left px-3 py-2 rounded-lg text-sm border-l-2 border-transparent flex items-center gap-2">
                    <span class="text-cyber-green">📂</span> Path Traversal
                </button>
            </div>
            
            <!-- Config Analysis Category -->
            <div class="px-4 mb-4">
                <h3 class="category-header text-gray-500 uppercase font-semibold mb-2 px-3">⚙️ Configuration</h3>
                <button onclick="showPanel('headers')" class="sidebar-item w-full text-left px-3 py-2 rounded-lg text-sm border-l-2 border-transparent flex items-center gap-2">
                    <span class="text-cyber-green">🛡️</span> Security Headers
                </button>
                <button onclick="showPanel('cors')" class="sidebar-item w-full text-left px-3 py-2 rounded-lg text-sm border-l-2 border-transparent flex items-center gap-2">
                    <span class="text-cyber-purple">🔀</span> CORS
                </button>
                <button onclick="showPanel('redirect')" class="sidebar-item w-full text-left px-3 py-2 rounded-lg text-sm border-l-2 border-transparent flex items-center gap-2">
                    <span class="text-cyber-orange">↩️</span> Open Redirect
                </button>
                <button onclick="showPanel('ratelimit')" class="sidebar-item w-full text-left px-3 py-2 rounded-lg text-sm border-l-2 border-transparent flex items-center gap-2">
                    <span class="text-cyber-blue">⏱️</span> Rate Limiting
                </button>
            </div>
            
            <!-- Recon Category -->
            <div class="px-4 mb-4">
                <h3 class="category-header text-gray-500 uppercase font-semibold mb-2 px-3">🔍 Reconnaissance</h3>
                <button onclick="showPanel('files')" class="sidebar-item w-full text-left px-3 py-2 rounded-lg text-sm border-l-2 border-transparent flex items-center gap-2">
                    <span class="text-accent">📁</span> Sensitive Files
                </button>
                <button onclick="showPanel('fingerprint')" class="sidebar-item w-full text-left px-3 py-2 rounded-lg text-sm border-l-2 border-transparent flex items-center gap-2">
                    <span class="text-cyber-purple">🔬</span> Tech Fingerprint
                </button>
                <button onclick="showPanel('pii')" class="sidebar-item w-full text-left px-3 py-2 rounded-lg text-sm border-l-2 border-transparent flex items-center gap-2">
                    <span class="text-cyber-orange">👤</span> PII Scanner
                </button>
                <button onclick="showPanel('cve')" class="sidebar-item w-full text-left px-3 py-2 rounded-lg text-sm border-l-2 border-transparent flex items-center gap-2">
                    <span class="text-cyber-blue">📋</span> CVE Lookup
                </button>
            </div>
            
            <!-- Advanced Category -->
            <div class="px-4 mb-4">
                <h3 class="category-header text-gray-500 uppercase font-semibold mb-2 px-3">🚀 Advanced</h3>
                <button onclick="showPanel('race')" class="sidebar-item w-full text-left px-3 py-2 rounded-lg text-sm border-l-2 border-transparent flex items-center gap-2">
                    <span class="text-cyber-green">⚡</span> Race Condition
                </button>
                <button onclick="showPanel('graphql')" class="sidebar-item w-full text-left px-3 py-2 rounded-lg text-sm border-l-2 border-transparent flex items-center gap-2">
                    <span class="text-cyber-purple">💎</span> GraphQL
                </button>
            </div>
            
            <!-- Settings Category -->
            <div class="px-4">
                <h3 class="category-header text-gray-500 uppercase font-semibold mb-2 px-3">⚙️ Settings</h3>
                <button onclick="showPanel('settings')" class="sidebar-item w-full text-left px-3 py-2 rounded-lg text-sm border-l-2 border-transparent flex items-center gap-2">
                    <span class="text-gray-400">🔌</span> Proxy & Headers
                </button>
            </div>
        </nav>
        
        <!-- Status bar -->
        <div class="p-4 border-t border-dark-600 bg-dark-900/50">
            <div class="flex items-center gap-2 text-xs">
                <span class="w-2 h-2 bg-green-500 rounded-full pulse-glow"></span>
                <span class="text-gray-400">{len(tokens)} tokens learned</span>
            </div>
        </div>
    </aside>
    
    <!-- Main Content -->
    <main class="ml-64 flex-1 p-6">
        <!-- Header -->
        <header class="mb-6">
            <div class="flex items-center justify-between">
                <div>
                    <h2 id="panelTitle" class="text-2xl font-bold">BOLA/IDOR Scanner</h2>
                    <p id="panelDesc" class="text-gray-500 text-sm">Broken Object Level Authorization detection</p>
                </div>
                <button onclick="generateReport()" class="px-4 py-2 bg-dark-700 hover:bg-dark-600 rounded-lg text-sm flex items-center gap-2">
                    📄 Export Report
                </button>
            </div>
        </header>
        
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <!-- Left Panel: Scan Form -->
            <div class="lg:col-span-1">
                <!-- Auto Scan Panel -->
                <div id="panel-autoscan" class="bg-dark-800 rounded-2xl p-6 border border-dark-600 card-glow">
                    <div class="mb-4 p-3 bg-gradient-to-r from-accent/20 to-purple-500/20 rounded-xl border border-accent/30">
                        <h3 class="font-bold text-accent flex items-center gap-2">🎯 Full Security Assessment</h3>
                        <p class="text-xs text-gray-400 mt-1">Runs all applicable security tests automatically</p>
                    </div>
                    <form id="autoscanForm" class="space-y-4">
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Target URL *</label>
                            <input type="text" name="url" placeholder="https://example.com"
                                   class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm focus:border-accent focus:ring-1 focus:ring-accent outline-none transition-all">
                        </div>
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Parameter (for injection tests)</label>
                            <input type="text" name="param" placeholder="Optional: id, q, search, file"
                                   class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Auth Token (optional)</label>
                            <input type="text" name="token" placeholder="Bearer token or API key"
                                   class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        
                        <!-- Module Selection -->
                        <div class="p-3 bg-dark-900 rounded-xl border border-dark-600">
                            <label class="block text-sm text-gray-400 mb-2">Modules to Run</label>
                            <div class="grid grid-cols-2 gap-2 text-xs">
                                <label class="flex items-center gap-1"><input type="checkbox" name="modules" value="security_headers" checked> 🛡️ Headers</label>
                                <label class="flex items-center gap-1"><input type="checkbox" name="modules" value="cors" checked> 🔀 CORS</label>
                                <label class="flex items-center gap-1"><input type="checkbox" name="modules" value="sensitive_files" checked> 📁 Files</label>
                                <label class="flex items-center gap-1"><input type="checkbox" name="modules" value="fingerprint" checked> 🔬 Fingerprint</label>
                                <label class="flex items-center gap-1"><input type="checkbox" name="modules" value="open_redirect" checked> ↩️ Redirect</label>
                                <label class="flex items-center gap-1"><input type="checkbox" name="modules" value="rate_limit" checked> ⏱️ Rate Limit</label>
                                <label class="flex items-center gap-1"><input type="checkbox" name="modules" value="sqli"> 🗄️ SQLi</label>
                                <label class="flex items-center gap-1"><input type="checkbox" name="modules" value="xss"> 💥 XSS</label>
                                <label class="flex items-center gap-1"><input type="checkbox" name="modules" value="lfi"> 📂 LFI</label>
                            </div>
                            <p class="text-[10px] text-gray-500 mt-2">* Injection tests (SQLi, XSS, LFI) require a parameter</p>
                        </div>
                        
                        <button type="submit" class="btn-primary w-full py-4 gradient-accent rounded-xl font-bold text-white text-lg">
                            🚀 Start Full Scan
                        </button>
                    </form>
                </div>
                
                <!-- BOLA Panel -->
                <div id="panel-bola" class="bg-dark-800 rounded-2xl p-6 border border-dark-600 card-glow hidden">
                    <form id="bolaForm" class="space-y-4">
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Target API URL</label>
                            <input type="text" name="host" value="http://localhost:5000" 
                                   class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm focus:border-accent focus:ring-1 focus:ring-accent outline-none transition-all">
                        </div>
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Victim Token</label>
                            <select name="victim_token" class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                                {token_options}
                            </select>
                        </div>
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Attacker Token</label>
                            <select name="attacker_token" class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                                {token_options}
                            </select>
                        </div>
                        <button type="submit" class="btn-primary w-full py-3 gradient-accent rounded-xl font-semibold text-white">
                            🚀 Launch Scan
                        </button>
                    </form>
                </div>
                
                <!-- SQL Injection Panel -->
                <div id="panel-sqli" class="bg-dark-800 rounded-2xl p-6 border border-dark-600 card-glow hidden">
                    <form id="sqliForm" class="space-y-4">
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Target URL</label>
                            <input type="text" name="url" placeholder="https://example.com/search?q=test"
                                   class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Parameter to Test</label>
                            <input type="text" name="param" value="q"
                                   class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        <button type="submit" class="btn-primary w-full py-3 gradient-accent rounded-xl font-semibold text-white">
                            🗄️ Test SQL Injection
                        </button>
                    </form>
                </div>
                
                <!-- XSS Panel -->
                <div id="panel-xss" class="bg-dark-800 rounded-2xl p-6 border border-dark-600 card-glow-orange hidden">
                    <form id="xssForm" class="space-y-4">
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Target URL</label>
                            <input type="text" name="url" placeholder="https://example.com/page?name=test"
                                   class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Parameter to Test</label>
                            <input type="text" name="param" value="name"
                                   class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        <button type="submit" class="btn-primary w-full py-3 bg-gradient-to-r from-orange-500 to-red-500 rounded-xl font-semibold text-white">
                            💥 Test XSS
                        </button>
                    </form>
                </div>
                
                <!-- Security Headers Panel -->
                <div id="panel-headers" class="bg-dark-800 rounded-2xl p-6 border border-dark-600 card-glow-green hidden">
                    <form id="headersForm" class="space-y-4">
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Target URL</label>
                            <input type="text" name="url" placeholder="https://example.com"
                                   class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        <button type="submit" class="btn-primary w-full py-3 gradient-green rounded-xl font-semibold text-white">
                            🛡️ Analyze Headers
                        </button>
                    </form>
                </div>
                
                <!-- CORS Panel -->
                <div id="panel-cors" class="bg-dark-800 rounded-2xl p-6 border border-dark-600 card-glow-purple hidden">
                    <form id="corsForm" class="space-y-4">
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Target URL</label>
                            <input type="text" name="url" placeholder="https://api.example.com"
                                   class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        <button type="submit" class="btn-primary w-full py-3 gradient-purple rounded-xl font-semibold text-white">
                            🔀 Test CORS
                        </button>
                    </form>
                </div>
                
                <!-- Sensitive Files Panel -->
                <div id="panel-files" class="bg-dark-800 rounded-2xl p-6 border border-dark-600 card-glow hidden">
                    <form id="filesForm" class="space-y-4">
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Target Base URL</label>
                            <input type="text" name="url" placeholder="https://example.com"
                                   class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        <div class="flex items-center gap-2">
                            <input type="checkbox" id="quickScan" name="quick" class="rounded">
                            <label for="quickScan" class="text-sm text-gray-400">Quick scan (critical only)</label>
                        </div>
                        <button type="submit" class="btn-primary w-full py-3 gradient-accent rounded-xl font-semibold text-white">
                            📁 Scan Files
                        </button>
                    </form>
                </div>
                
                <!-- Fingerprint Panel -->
                <div id="panel-fingerprint" class="bg-dark-800 rounded-2xl p-6 border border-dark-600 card-glow-purple hidden">
                    <form id="fingerprintForm" class="space-y-4">
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Target URL</label>
                            <input type="text" name="url" placeholder="https://example.com"
                                   class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        <button type="submit" class="btn-primary w-full py-3 gradient-purple rounded-xl font-semibold text-white">
                            🔬 Fingerprint
                        </button>
                    </form>
                </div>
                
                <!-- SSRF Panel -->
                <div id="panel-ssrf" class="bg-dark-800 rounded-2xl p-6 border border-dark-600 card-glow-blue hidden">
                    <form id="ssrfForm" class="space-y-4">
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Target Endpoint</label>
                            <input type="text" name="endpoint" placeholder="https://api.example.com/fetch"
                                   class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">URL Parameter</label>
                            <input type="text" name="param" value="url"
                                   class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        <button type="submit" class="btn-primary w-full py-3 gradient-blue rounded-xl font-semibold text-white">
                            🌐 Test SSRF
                        </button>
                    </form>
                </div>
                
                <!-- LFI Panel -->
                <div id="panel-lfi" class="bg-dark-800 rounded-2xl p-6 border border-dark-600 card-glow-green hidden">
                    <form id="lfiForm" class="space-y-4">
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Target URL</label>
                            <input type="text" name="url" placeholder="https://example.com/view?file=test"
                                   class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">File Parameter</label>
                            <input type="text" name="param" value="file"
                                   class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Target OS</label>
                            <select name="os" class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl text-sm">
                                <option value="unix">Unix/Linux</option>
                                <option value="windows">Windows</option>
                            </select>
                        </div>
                        <button type="submit" class="btn-primary w-full py-3 gradient-green rounded-xl font-semibold text-white">
                            📂 Test Path Traversal
                        </button>
                    </form>
                </div>
                
                <!-- Settings Panel -->
                <div id="panel-settings" class="bg-dark-800 rounded-2xl p-6 border border-dark-600 hidden">
                    <form id="settingsForm" class="space-y-4">
                        <div class="p-4 bg-dark-900 rounded-xl border border-dark-600">
                            <h3 class="font-semibold text-sm mb-3 text-accent">🔌 Proxy Configuration</h3>
                            <input type="text" name="proxy" placeholder="http://proxy:8080 or socks5://127.0.0.1:9050"
                                   class="w-full px-4 py-3 bg-dark-800 border border-dark-600 rounded-xl mono text-sm mb-2">
                            <div class="flex items-center gap-2">
                                <input type="checkbox" id="useTor" name="use_tor">
                                <label for="useTor" class="text-sm text-gray-400">Use Tor</label>
                            </div>
                        </div>
                        <div class="p-4 bg-dark-900 rounded-xl border border-dark-600">
                            <h3 class="font-semibold text-sm mb-3 text-cyber-blue">📋 Custom Headers</h3>
                            <textarea name="headers" rows="3" placeholder="X-Custom-Header: value"
                                      class="w-full px-4 py-3 bg-dark-800 border border-dark-600 rounded-xl mono text-sm"></textarea>
                        </div>
                        <div class="flex gap-2">
                            <button type="submit" class="flex-1 py-3 gradient-accent rounded-xl font-semibold text-white">
                                💾 Save
                            </button>
                            <button type="button" onclick="testProxy()" class="flex-1 py-3 bg-dark-700 hover:bg-dark-600 rounded-xl font-semibold">
                                🧪 Test
                            </button>
                        </div>
                    </form>
                </div>
                
                <!-- Placeholder panels for other modules -->
                <div id="panel-bfla" class="bg-dark-800 rounded-2xl p-6 border border-dark-600 hidden">
                    <form id="bflaForm" class="space-y-4">
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Target Host</label>
                            <input type="text" name="host" value="http://localhost:5000" class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Low Privilege Token</label>
                            <input type="text" name="token" placeholder="User token" class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        <button type="submit" class="btn-primary w-full py-3 gradient-purple rounded-xl font-semibold text-white">🔓 Test BFLA</button>
                    </form>
                </div>
                
                <div id="panel-jwt" class="bg-dark-800 rounded-2xl p-6 border border-dark-600 card-glow-blue hidden">
                    <form id="jwtForm" class="space-y-4">
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">JWT Token</label>
                            <textarea name="token" rows="3" placeholder="eyJhbGciOiJIUzI1NiIs..." class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm"></textarea>
                        </div>
                        <button type="submit" class="btn-primary w-full py-3 gradient-blue rounded-xl font-semibold text-white">🔑 Analyze JWT</button>
                    </form>
                </div>
                
                <div id="panel-mass" class="bg-dark-800 rounded-2xl p-6 border border-dark-600 hidden">
                    <form id="massForm" class="space-y-4">
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Endpoint URL</label>
                            <input type="text" name="endpoint" placeholder="https://api.example.com/user" class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        <button type="submit" class="btn-primary w-full py-3 bg-gradient-to-r from-orange-500 to-amber-500 rounded-xl font-semibold text-white">📝 Test Mass Assignment</button>
                    </form>
                </div>
                
                <div id="panel-redirect" class="bg-dark-800 rounded-2xl p-6 border border-dark-600 hidden">
                    <form id="redirectForm" class="space-y-4">
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Target URL</label>
                            <input type="text" name="url" placeholder="https://example.com/login?next=" class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        <button type="submit" class="btn-primary w-full py-3 bg-gradient-to-r from-orange-500 to-red-500 rounded-xl font-semibold text-white">↩️ Test Redirect</button>
                    </form>
                </div>
                
                <div id="panel-ratelimit" class="bg-dark-800 rounded-2xl p-6 border border-dark-600 card-glow-blue hidden">
                    <form id="ratelimitForm" class="space-y-4">
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Target Endpoint</label>
                            <input type="text" name="url" placeholder="https://api.example.com/login" class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Number of Requests</label>
                            <input type="number" name="requests" value="30" class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        <button type="submit" class="btn-primary w-full py-3 gradient-blue rounded-xl font-semibold text-white">⏱️ Test Rate Limit</button>
                    </form>
                </div>
                
                <div id="panel-pii" class="bg-dark-800 rounded-2xl p-6 border border-dark-600 hidden">
                    <form id="piiForm" class="space-y-4">
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Target URL</label>
                            <input type="text" name="url" placeholder="https://api.example.com/user/1" class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        <button type="submit" class="btn-primary w-full py-3 bg-gradient-to-r from-orange-500 to-amber-500 rounded-xl font-semibold text-white">👤 Scan PII</button>
                    </form>
                </div>
                
                <div id="panel-cve" class="bg-dark-800 rounded-2xl p-6 border border-dark-600 card-glow-blue hidden">
                    <form id="cveForm" class="space-y-4">
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Target URL</label>
                            <input type="text" name="url" value="http://localhost:5000" class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Technology</label>
                            <input type="text" name="tech" placeholder="nginx, Flask, Django" class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        <button type="submit" class="btn-primary w-full py-3 gradient-blue rounded-xl font-semibold text-white">📋 Lookup CVEs</button>
                    </form>
                </div>
                
                <div id="panel-race" class="bg-dark-800 rounded-2xl p-6 border border-dark-600 card-glow-green hidden">
                    <form id="raceForm" class="space-y-4">
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Target Endpoint</label>
                            <input type="text" name="url" value="http://localhost:5000/api/wallet/withdraw" class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">Auth Token</label>
                            <input type="text" name="token" value="token_alice_123" class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        <button type="submit" class="btn-primary w-full py-3 gradient-green rounded-xl font-semibold text-white">⚡ Test Race</button>
                    </form>
                </div>
                
                <div id="panel-graphql" class="bg-dark-800 rounded-2xl p-6 border border-dark-600 card-glow-purple hidden">
                    <form id="graphqlForm" class="space-y-4">
                        <div>
                            <label class="block text-sm text-gray-400 mb-2">GraphQL Endpoint</label>
                            <input type="text" name="endpoint" placeholder="https://api.example.com/graphql" class="w-full px-4 py-3 bg-dark-900 border border-dark-600 rounded-xl mono text-sm">
                        </div>
                        <button type="submit" class="btn-primary w-full py-3 gradient-purple rounded-xl font-semibold text-white">💎 Attack GraphQL</button>
                    </form>
                </div>
            </div>
            
            <!-- Right Panel: Results -->
            <div class="lg:col-span-2">
                <div class="bg-dark-800 rounded-2xl p-6 border border-dark-600 min-h-[600px]">
                    <div class="flex items-center justify-between mb-4">
                        <h3 class="font-semibold text-lg">📊 Scan Results</h3>
                        <div id="scanStatus" class="hidden">
                            <span class="flex items-center gap-2 text-sm text-cyber-blue">
                                <svg class="animate-spin w-4 h-4" viewBox="0 0 24 24">
                                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"/>
                                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"/>
                                </svg>
                                Scanning...
                            </span>
                        </div>
                    </div>
                    <div id="resultsContent" class="space-y-4">
                        <div class="text-center py-20 text-gray-500">
                            <div class="text-6xl mb-4">🔱</div>
                            <p>Select a scan type and launch to see results</p>
                            <p class="text-sm mt-2 text-gray-600">Results will appear here</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </main>
    
    <script>
        // Panel titles and descriptions
        const panelInfo = {{
            'autoscan': ['🎯 Auto Scanner', 'Run all security tests automatically with one click'],
            'bola': ['BOLA/IDOR Scanner', 'Broken Object Level Authorization detection'],
            'bfla': ['BFLA Scanner', 'Broken Function Level Authorization testing'],
            'jwt': ['JWT Attacks', 'Token manipulation and weak secret detection'],
            'mass': ['Mass Assignment', 'Test for unprotected object property binding'],
            'sqli': ['SQL Injection', 'Error-based and time-based SQLi detection'],
            'xss': ['XSS Scanner', 'Cross-Site Scripting with context-aware payloads'],
            'ssrf': ['SSRF Scanner', 'Server-Side Request Forgery testing'],
            'lfi': ['Path Traversal', 'Local File Inclusion / directory traversal'],
            'headers': ['Security Headers', 'HSTS, CSP, X-Frame-Options analysis (A-F grade)'],
            'cors': ['CORS Scanner', 'Origin reflection, wildcard, null origin detection'],
            'redirect': ['Open Redirect', 'Unvalidated redirect vulnerability testing'],
            'ratelimit': ['Rate Limiting', 'API rate limit and brute force protection'],
            'files': ['Sensitive Files', 'Find exposed .git, .env, backups (80+ paths)'],
            'fingerprint': ['Tech Fingerprint', 'Detect servers, frameworks, CMS, CDN'],
            'pii': ['PII Scanner', 'Detect sensitive data leaks in responses'],
            'cve': ['CVE Lookup', 'Check for known vulnerabilities'],
            'race': ['Race Condition', 'Concurrency exploitation testing'],
            'graphql': ['GraphQL Attacks', 'Introspection, batching, DoS testing'],
            'settings': ['Settings', 'Proxy, custom headers, and SSL configuration']
        }};
        
        function showPanel(panelId) {{
            // Hide all panels
            document.querySelectorAll('[id^="panel-"]').forEach(p => p.classList.add('hidden'));
            
            // Show selected panel
            const panel = document.getElementById('panel-' + panelId);
            if (panel) panel.classList.remove('hidden');
            
            // Update active sidebar item
            document.querySelectorAll('.sidebar-item').forEach(item => item.classList.remove('active'));
            event.target.classList.add('active');
            
            // Update header
            if (panelInfo[panelId]) {{
                document.getElementById('panelTitle').textContent = panelInfo[panelId][0];
                document.getElementById('panelDesc').textContent = panelInfo[panelId][1];
            }}
        }}
        
        function showLoading() {{
            document.getElementById('scanStatus').classList.remove('hidden');
            document.getElementById('resultsContent').innerHTML = `
                <div class="text-center py-20">
                    <div class="text-4xl mb-4 animate-pulse">🔍</div>
                    <p class="text-cyber-blue">Scanning in progress...</p>
                </div>
            `;
        }}
        
        function hideLoading() {{
            document.getElementById('scanStatus').classList.add('hidden');
        }}
        
        function displayResults(html) {{
            hideLoading();
            document.getElementById('resultsContent').innerHTML = html;
        }}
        
        function displayError(message) {{
            hideLoading();
            document.getElementById('resultsContent').innerHTML = `
                <div class="text-center py-10 text-red-400">
                    <div class="text-4xl mb-4">❌</div>
                    <p>${{message}}</p>
                </div>
            `;
        }}
        
        // Form handlers
        document.querySelectorAll('form').forEach(form => {{
            form.addEventListener('submit', async (e) => {{
                e.preventDefault();
                showLoading();
                
                const formData = new FormData(form);
                const endpoint = '/api/' + form.id.replace('Form', '');
                
                try {{
                    const response = await fetch(endpoint, {{
                        method: 'POST',
                        body: formData
                    }});
                    const data = await response.json();
                    
                    // Generic result display
                    let html = '<div class="space-y-3">';
                    if (data.error) {{
                        html += `<div class="p-4 bg-red-900/20 border border-red-500 rounded-xl text-red-400">${{data.error}}</div>`;
                    }} else {{
                        html += `<pre class="p-4 bg-dark-900 rounded-xl text-sm overflow-auto max-h-96">${{JSON.stringify(data, null, 2)}}</pre>`;
                    }}
                    html += '</div>';
                    displayResults(html);
                }} catch (err) {{
                    displayError('Request failed: ' + err.message);
                }}
            }});
        }});
        
        function generateReport() {{
            window.open('/report/html', '_blank');
        }}
        
        function testProxy() {{
            alert('Testing proxy connection...');
        }}
    </script>
</body>
</html>
'''
