<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>QyrexApi | Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script src="https://accounts.google.com/gsi/client" async defer></script>
  <style>
    body { background: #0f0f13; color: #e2e8f0; }
    .card { background: #1a1a24; border: 1px solid #2d2d3a; }
    .btn { transition: all 0.2s; }
    .btn:hover { transform: translateY(-1px); }
  </style>
</head>
<body class="min-h-screen">

  <!-- LOGIN -->
  <div id="loginScreen" class="fixed inset-0 bg-[#0f0f13] flex items-center justify-center z-50">
    <div class="card p-10 rounded-3xl w-full max-w-md shadow-2xl text-center">
      <div class="w-16 h-16 mx-auto mb-6 rounded-2xl bg-gradient-to-br from-purple-500 to-pink-500 flex items-center justify-center text-2xl font-bold">Q</div>
      <h1 class="text-3xl font-bold mb-2 bg-gradient-to-r from-purple-400 to-pink-500 bg-clip-text text-transparent">QyrexApi</h1>
      <p class="text-gray-400 mb-8">Inicia sesión con tu cuenta de Google</p>
      
      <div id="g_id_onload"
           data-client_id="TU_CLIENT_ID_AQUI.apps.googleusercontent.com"
           data-callback="handleGoogleLogin"
           data-auto_prompt="false">
      </div>
      <div class="g_id_signin flex justify-center"
           data-type="standard"
           data-size="large"
           data-theme="filled_black"
           data-text="signin_with"
           data-shape="rectangular"
           data-logo_alignment="left">
      </div>

      <p id="loginError" class="text-red-400 text-sm mt-5 hidden"></p>
    </div>
  </div>

  <!-- DASHBOARD -->
  <div id="dashboard" class="hidden">
    <nav class="border-b border-[#2d2d3a] bg-[#12121a] px-6 py-4 flex justify-between items-center">
      <div class="flex items-center gap-3">
        <div class="w-9 h-9 rounded-xl bg-gradient-to-br from-purple-500 to-pink-500 flex items-center justify-center font-bold">Q</div>
        <span class="font-bold text-xl">QyrexApi</span>
      </div>
      <div class="flex items-center gap-4">
        <div class="flex items-center gap-2">
          <img id="userPicture" class="w-8 h-8 rounded-full border border-[#2d2d3a]" src="" alt="">
          <span id="userName" class="text-sm text-gray-300"></span>
        </div>
        <button onclick="logout()" class="text-sm text-gray-400 hover:text-white transition">Cerrar sesión</button>
      </div>
    </nav>

    <div class="flex">
      <aside class="w-64 border-r border-[#2d2d3a] min-h-[calc(100vh-73px)] p-4 space-y-1">
        <button onclick="showTab('scripts')" class="tab-btn w-full text-left px-4 py-3 rounded-xl hover:bg-[#1a1a24] transition">📜 Scripts</button>
        <button onclick="showTab('upload')" class="tab-btn w-full text-left px-4 py-3 rounded-xl hover:bg-[#1a1a24] transition">⬆️ Subir Script</button>
        <button onclick="showTab('keys')" class="tab-btn w-full text-left px-4 py-3 rounded-xl hover:bg-[#1a1a24] transition">🔑 Keys</button>
        <button onclick="showTab('stats')" class="tab-btn w-full text-left px-4 py-3 rounded-xl hover:bg-[#1a1a24] transition">📊 Visitas & Stats</button>
      </aside>

      <main class="flex-1 p-8">
        <!-- SCRIPTS -->
        <div id="tab-scripts" class="tab-content">
          <h2 class="text-2xl font-bold mb-6">Mis Scripts</h2>
          <div id="scriptsList" class="grid gap-4"></div>
        </div>

        <!-- UPLOAD -->
        <div id="tab-upload" class="tab-content hidden">
          <h2 class="text-2xl font-bold mb-6">Subir / Editar Script</h2>
          
          <div class="card p-6 rounded-2xl mb-6 border-purple-500/40">
            <p class="text-purple-300 font-medium mb-2">🔒 Ofuscador 100% recomendado y hecho por nosotros:</p>
            <a href="https://qyrexobf.onrender.com/" target="_blank" class="text-pink-400 underline hover:text-pink-300">
              https://qyrexobf.onrender.com/
            </a>
            <p class="text-sm text-gray-400 mt-2">Ofusca tu script ahí antes de subirlo. Es el más seguro y compatible con QyrexApi.</p>
          </div>

          <div class="card p-6 rounded-2xl space-y-4">
            <input id="scriptName" placeholder="Nombre del script" class="w-full bg-[#12121a] border border-[#2d2d3a] rounded-xl px-4 py-3 focus:outline-none focus:border-purple-500">
            <input id="scriptDesc" placeholder="Descripción corta" class="w-full bg-[#12121a] border border-[#2d2d3a] rounded-xl px-4 py-3 focus:outline-none focus:border-purple-500">
            <textarea id="scriptCode" rows="12" placeholder="Pega aquí el script YA OFUSCADO..." class="w-full bg-[#12121a] border border-[#2d2d3a] rounded-xl px-4 py-3 font-mono text-sm focus:outline-none focus:border-purple-500"></textarea>
            <button onclick="saveScript()" class="btn bg-gradient-to-r from-purple-600 to-pink-600 px-6 py-3 rounded-xl font-semibold">Guardar Script</button>
          </div>
        </div>

        <!-- KEYS -->
        <div id="tab-keys" class="tab-content hidden">
          <div class="flex justify-between items-center mb-6">
            <h2 class="text-2xl font-bold">Sistema de Keys</h2>
            <button onclick="generateKey()" class="btn bg-green-600 hover:bg-green-500 px-5 py-2 rounded-xl">+ Generar Key</button>
          </div>
          <p class="text-gray-400 mb-4 text-sm">Estas keys se pueden vender con <b>Work.ink</b> o <b>Lootbits</b>. El usuario pone la key en el ejecutor.</p>
          <div id="keysList" class="space-y-3"></div>
        </div>

        <!-- STATS -->
        <div id="tab-stats" class="tab-content hidden">
          <h2 class="text-2xl font-bold mb-6">Visitas & Estadísticas</h2>
          <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            <div class="card p-5 rounded-2xl">
              <p class="text-gray-400 text-sm">Scripts</p>
              <p id="statScripts" class="text-3xl font-bold">0</p>
            </div>
            <div class="card p-5 rounded-2xl">
              <p class="text-gray-400 text-sm">Keys Activas</p>
              <p id="statKeys" class="text-3xl font-bold">0</p>
            </div>
            <div class="card p-5 rounded-2xl">
              <p class="text-gray-400 text-sm">Visitas Totales</p>
              <p id="statVisits" class="text-3xl font-bold">0</p>
            </div>
            <div class="card p-5 rounded-2xl">
              <p class="text-gray-400 text-sm">Usuarios</p>
              <p id="statUsers" class="text-3xl font-bold">0</p>
            </div>
          </div>
          <div class="card p-6 rounded-2xl">
            <canvas id="visitsChart" height="100"></canvas>
          </div>
        </div>
      </main>
    </div>
  </div>

  <script>
    let token = localStorage.getItem('qyrexapi_token') || '';
    let editingId = null;
    let currentUser = null;

    // ============ GOOGLE LOGIN ============
    async function handleGoogleLogin(response) {
      try {
        const res = await fetch('/api/auth/google', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ credential: response.credential })
        });
        const data = await res.json();

        if (data.success) {
          token = data.token;
          currentUser = data.user;
          localStorage.setItem('qyrexapi_token', token);
          showDashboard();
        } else {
          showError(data.error || "Error al iniciar sesión");
        }
      } catch (err) {
        showError("Error de conexión");
      }
    }

    function showError(msg) {
      const el = document.getElementById('loginError');
      el.textContent = msg;
      el.classList.remove('hidden');
    }

    function showDashboard() {
      document.getElementById('loginScreen').classList.add('hidden');
      document.getElementById('dashboard').classList.remove('hidden');
      document.getElementById('userName').textContent = currentUser?.name || 'Usuario';
      document.getElementById('userPicture').src = currentUser?.picture || '';
      loadAll();
    }

    function logout() {
      localStorage.removeItem('qyrexapi_token');
      location.reload();
    }

    // Si ya hay token guardado
    if (token) {
      fetch('/api/me', {
        headers: { 'Authorization': 'Bearer ' + token }
      })
      .then(r => r.json())
      .then(user => {
        if (user.email) {
          currentUser = user;
          showDashboard();
        } else {
          localStorage.removeItem('qyrexapi_token');
        }
      })
      .catch(() => localStorage.removeItem('qyrexapi_token'));
    }

    // ============ TABS ============
    function showTab(name) {
      document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
      document.getElementById('tab-' + name).classList.remove('hidden');
      if (name === 'scripts') loadScripts();
      if (name === 'keys') loadKeys();
      if (name === 'stats') loadStats();
    }

    async function loadAll() {
      loadScripts();
      loadKeys();
      loadStats();
    }

    // ============ SCRIPTS ============
    async function loadScripts() {
      const res = await fetch('/api/admin/scripts', {
        headers: { 'Authorization': 'Bearer ' + token }
      });
      const scripts = await res.json();
      const container = document.getElementById('scriptsList');
      container.innerHTML = scripts.map(s => `
        <div class="card p-5 rounded-2xl flex justify-between items-start">
          <div>
            <h3 class="font-bold text-lg">${s.name}</h3>
            <p class="text-gray-400 text-sm">${s.description || 'Sin descripción'}</p>
            <p class="text-xs text-purple-400 mt-2">ID: ${s.id} • Visitas: ${s.visits || 0}</p>
            <p class="text-xs text-gray-500 mt-1">Endpoint: /api/script/${s.id}</p>
          </div>
          <div class="flex gap-2">
            <button onclick="editScript('${s.id}')" class="text-sm bg-[#2d2d3a] px-3 py-1.5 rounded-lg hover:bg-[#3a3a4a]">Editar</button>
            <button onclick="deleteScript('${s.id}')" class="text-sm bg-red-900/40 text-red-300 px-3 py-1.5 rounded-lg hover:bg-red-900/60">Eliminar</button>
          </div>
        </div>
      `).join('') || '<p class="text-gray-500">No hay scripts todavía</p>';
    }

    function editScript(id) {
      fetch('/api/admin/scripts', { headers: { 'Authorization': 'Bearer ' + token } })
        .then(r => r.json())
        .then(scripts => {
          const s = scripts.find(x => x.id === id);
          if (!s) return;
          editingId = id;
          document.getElementById('scriptName').value = s.name;
          document.getElementById('scriptDesc').value = s.description || '';
          document.getElementById('scriptCode').value = s.code;
          showTab('upload');
        });
    }

    async function saveScript() {
      const body = {
        name: document.getElementById('scriptName').value,
        description: document.getElementById('scriptDesc').value,
        code: document.getElementById('scriptCode').value
      };
      const url = editingId ? `/api/admin/scripts/${editingId}` : '/api/admin/scripts';
      const method = editingId ? 'PUT' : 'POST';

      await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + token
        },
        body: JSON.stringify(body)
      });

      editingId = null;
      document.getElementById('scriptName').value = '';
      document.getElementById('scriptDesc').value = '';
      document.getElementById('scriptCode').value = '';
      showTab('scripts');
      alert('Script guardado correctamente');
    }

    async function deleteScript(id) {
      if (!confirm('¿Eliminar este script?')) return;
      await fetch(`/api/admin/scripts/${id}`, {
        method: 'DELETE',
        headers: { 'Authorization': 'Bearer ' + token }
      });
      loadScripts();
    }

    // ============ KEYS ============
    async function loadKeys() {
      const res = await fetch('/api/admin/keys', {
        headers: { 'Authorization': 'Bearer ' + token }
      });
      const keys = await res.json();
      document.getElementById('keysList').innerHTML = keys.map(k => `
        <div class="card p-4 rounded-xl flex justify-between items-center">
          <div>
            <code class="text-green-400 font-mono text-sm">${k.key}</code>
            <p class="text-xs text-gray-500 mt-1">${k.note} • ${new Date(k.createdAt).toLocaleString()}</p>
          </div>
          <button onclick="deleteKey('${k.key}')" class="text-red-400 text-sm hover:text-red-300">Eliminar</button>
        </div>
      `).join('') || '<p class="text-gray-500">No hay keys generadas</p>';
    }

    async function generateKey() {
      const note = prompt('Nota de la key (opcional):', 'Key de Work.ink / Lootbits');
      await fetch('/api/admin/keys', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + token
        },
        body: JSON.stringify({ note })
      });
      loadKeys();
    }

    async function deleteKey(key) {
      if (!confirm('¿Eliminar esta key?')) return;
      await fetch(`/api/admin/keys/${key}`, {
        method: 'DELETE',
        headers: { 'Authorization': 'Bearer ' + token }
      });
      loadKeys();
    }

    // ============ STATS ============
    async function loadStats() {
      const res = await fetch('/api/admin/stats', {
        headers: { 'Authorization': 'Bearer ' + token }
      });
      const stats = await res.json();
      document.getElementById('statScripts').textContent = stats.totalScripts;
      document.getElementById('statKeys').textContent = stats.activeKeys;
      document.getElementById('statVisits').textContent = stats.totalVisits;
      document.getElementById('statUsers').textContent = stats.totalUsers;

      const ctx = document.getElementById('visitsChart').getContext('2d');
      if (window.myChart) window.myChart.destroy();
      window.myChart = new Chart(ctx, {
        type: 'line',
        data: {
          labels: stats.recentVisits.map((_, i) => `#${i+1}`).reverse(),
          datasets: [{
            label: 'Visitas',
            data: stats.recentVisits.map(() => 1).reverse(),
            borderColor: '#a855f7',
            backgroundColor: 'rgba(168,85,247,0.1)',
            tension: 0.35,
            fill: true
          }]
        },
        options: {
          scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } },
          plugins: { legend: { display: false } }
        }
      });
    }
  </script>
</body>
</html>
