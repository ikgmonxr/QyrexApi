const { OAuth2Client } = require('google-auth-library');
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

module.exports = async (req, res) => {
    // Configurar cabeceras CORS por si tu frontend está en otro dominio (como GitHub Pages)
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
    res.setHeader(
        'Access-Control-Allow-Headers',
        'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
    );

    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, message: 'Método no permitido' });
    }

    try {
        const { token } = req.body;

        if (!token) {
            return res.status(400).json({ success: false, message: 'Token no proporcionado' });
        }

        // Verificar el token con la librería oficial de Google
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });

        const payload = ticket.getPayload();
        
        // Datos extraídos del usuario autenticado
        const userid = payload['sub'];
        const email = payload['email'];
        const name = payload['name'];
        const picture = payload['picture'];

        // Aquí puedes registrar el usuario en tu base de datos si lo deseas

        return res.status(200).json({
            success: true,
            message: 'Autenticación exitosa',
            user: {
                id: userid,
                email: email,
                name: name,
                picture: picture
            }
        });

    } catch (error) {
        console.error('Error al verificar el token:', error);
        return res.status(401).json({
            success: false,
            message: 'Token inválido o expirado',
            error: error.message
        });
    }
};
