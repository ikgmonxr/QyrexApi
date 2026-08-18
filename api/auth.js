// api/auth.js
const { OAuth2Client } = require('google-auth-library');
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

module.exports = async (req, res) => {
    // Manejar CORS (necesario si tu frontend y API no están en el mismo origen)
    res.setHeader('Access-Control-Allow-Origin', '*');
    
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
                user: { name: payload.name, email: payload.email, picture: payload.picture }
            });
        } catch (error) {
            return res.status(401).json({ success: false, error: "Token inválido" });
        }
    }
    res.status(405).send('Método no permitido');
};
