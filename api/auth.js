const { OAuth2Client } = require('google-auth-library');
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

module.exports = async (req, res) => {
    // Configurar CORS autorizado específicamente para tu GitHub Pages
    res.setHeader('Access-Control-Allow-Origin', 'https://ikgmonxr.github.io');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method === 'POST') {
        const { token } = req.body;
        try {
            const ticket = await client.verifyIdToken({
                idToken: token,
                audience: process.env.GOOGLE_CLIENT_ID,
            });
            const payload = ticket.getPayload();
            
            return res.status(200).json({ 
                success: true, 
                user: { 
                    name: payload.name, 
                    email: payload.email, 
                    picture: payload.picture 
                } 
            });
        } catch (error) {
            return res.status(401).json({ success: false, error: "Token de Google inválido" });
        }
    }

    return res.status(405).json({ error: "Método no permitido" });
};
