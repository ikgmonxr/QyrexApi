const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cors());

// Simulación de Base de Datos en Memoria (puedes cambiarla por MongoDB o SQL)
let db = {
    visitas: 1420,
    scripts: [
        { id: 1, name: "Aimbot Pro V4", version: "1.2", code: "print('Loaded Aimbot')" },
        { id: 2, name: "ESP Box + Distance", version: "2.0", code: "print('Loaded ESP')" }
    ]
};

// 1. ENDPOINT PRINCIPAL / API WEB (Bloquea navegadores comunes y muestra el mensaje estricto)
app.get('/api/v1/endpoint', (req, res) => {
    const userAgent = req.headers['user-agent'] || '';
    
    // Si el usuario entra directamente desde Chrome, Edge, Firefox, etc.
    if (userAgent.includes('Mozilla') || userAgent.includes('Chrome') || userAgent.includes('Safari')) {
        return res.status(403.4).send(`
            <html>
                <head><title>403 Forbidden</title></head>
                <body style="background-color: #050505; color: #ff3333; font-family: monospace; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0;">
                    <div style="text-align: center;">
                        <h1 style="font-size: 3rem; margin: 0;">ACCESS DENIED</h1>
                        <p style="color: #888; font-size: 1.1rem; margin-top: 10px;">Endpoint bloqueado. Este recurso es exclusivo para ejecución de scripts de Roblox.</p>
                    </div>
                </body>
            </html>
        `);
    }

    // Si la petición viene de Roblox (HttpService) o un Executor autorizado
    res.json({
        status: "success",
        message: "Conexión autorizada con éxito.",
        data: db.scripts
    });
});

// 2. ENDPOINT PARA OBTENER ESTADÍSTICAS EN EL DASHBOARD
app.get('/api/stats', (req, res) => {
    db.visitas++; // Incrementa visita simulada
    res.json({
        visitas: db.visitas,
        activeScripts: db.scripts.length,
        status: "Online"
    });
});

// 3. ENDPOINT PARA SUBIR / GUARDAR SCRIPTS
app.post('/api/upload', (req, res) => {
    const { name, code } = req.body;
    if (!name || !code) {
        return res.status(400).json({ error: "Faltan datos obligatorios." });
    }
    
    const newScript = {
        id: db.scripts.length + 1,
        name: name,
        version: "1.0",
        code: code
    };
    
    db.scripts.push(newScript);
    res.json({ success: true, message: "Script registrado correctamente.", script: newScript });
});

app.listen(PORT, () => {
    console.log(`Servidor corriendo en puerto ${PORT}`);
});
