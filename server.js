console.log("Iniciando el servidor...");

const express = require('express');
const http = require('http');
const https = require('https');
const fs = require('fs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const { Pool } = require('pg');

// Conexión a la base de datos sessions_db (sesiones de usuario)
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

// Crear la aplicación express
const app = express();
app.use(express.json());

// Configurar CORS para aceptar solicitudes desde los orígenes permitidos
const allowedOrigins = [
    "https://cliente-html-git-master-oswaldo-cuestas-projects.vercel.app",
    "https://generador-toke-git-master-oswaldo-cuestas-projects.vercel.app",
    "http://127.0.0.1:5500",
    "http://127.0.0.1:5501",
    "http://localhost:5500",
    "http://localhost:5501",
];

// Usar CORS antes de las rutas.
app.use(cors({
    origin: (origin, callback) => {
        if (allowedOrigins.includes(origin) || !origin) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
}));

// Responder explícitamente a las solicitudes OPTIONS (preflight)
app.options('*', (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.status(200).end();
});

// Permitir solicitudes OPTIONS para preflight
app.options('*', cors());

// ✅ **Ruta para la raíz del servidor**
app.get('/', (req, res) => {
    res.send('¡Servidor backend_token en funcionamiento!');
});

// ✅ **Ruta para generar un token JWT**
app.post('/generate-token', async (req, res) => {
    const { username, device_id, expiration } = req.body;

    // Validación de parámetros
    if (!username || !device_id || !expiration) {
        return res.status(400).json({ message: 'Faltan parámetros' });
    }

    const expirationDate = new Date(expiration);
    if (isNaN(expirationDate)) {
        return res.status(400).json({ message: 'Fecha de expiración no válida' });
    }

    const payload = {
        username: username,
        device_id: device_id,
        exp: Math.floor(expirationDate.getTime() / 1000),
    };

    const token = jwt.sign(payload, process.env.JWT_SECRET_KEY);

    try {
        // Verificar si el token ya existe en la base de datos
        console.log('Verificando si el token ya existe en la base de datos');
        const result = await pool.query('SELECT * FROM sessions WHERE token = $1', [token]);

        if (result.rows.length > 0) {
            const activeSession = result.rows[0];
            if (activeSession.device_id !== device_id) {
                console.log('Token ya existe y está siendo usado en otro dispositivo');
                await pool.query('UPDATE sessions SET valid = false WHERE token = $1', [token]);
                await pool.query(
                    'UPDATE sessions SET device_id = $1, expiration_time = $2 WHERE token = $3',
                    [device_id, expirationDate, token]
                );
                return res.json({ token, message: 'Token trasladado a otro dispositivo' });
            }
        } else {
            console.log('Token no encontrado, verificando usuario');
            const userResult = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
            let userId;
            if (userResult.rows.length === 0) {
                console.log('Usuario no encontrado, creando usuario');
                const insertUserResult = await pool.query('INSERT INTO users (username) VALUES ($1) RETURNING id', [username]);
                userId = insertUserResult.rows[0].id;
            } else {
                userId = userResult.rows[0].id;
            }

            console.log('Insertando nueva sesión en la base de datos');
            await pool.query('INSERT INTO sessions(token, device_id, username, expiration_time, user_id) VALUES($1, $2, $3, $4, $5)', [token, device_id, username, expirationDate, userId]);
        }

        res.json({ token });

    } catch (err) {
        console.error('Error generando o guardando el token:', err);
        res.status(500).json({ error: 'Error al generar el token' });
    }
});

// ✅ **Ruta para verificar si el token es válido**
app.post('/verify-token', async (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) {
        return res.status(400).json({ error: 'Token no proporcionado' });
    }

    try {
        // Verificar el token
        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
        const username = decoded.username;
        const deviceId = decoded.device_id;

        // Verificar si el token está en uso en otro dispositivo
        const result = await pool.query('SELECT * FROM sessions WHERE token = $1', [token]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Token no encontrado en las sesiones activas' });
        }

        const activeSession = result.rows[0];

        // Verificar si el token ha expirado
        if (new Date(activeSession.expiration_time) < new Date()) {
            return res.status(401).json({ valid: false, message: 'El token ha expirado' });
        }

        if (activeSession.device_id !== deviceId) {
            await pool.query('UPDATE sessions SET valid = false WHERE token = $1', [token]);

            // Actualizamos la sesión en el dispositivo actual
            await pool.query(
                'UPDATE sessions SET device_id = $1, expiration_time = $2 WHERE token = $3',
                [deviceId, activeSession.expiration_time, token]
            );

            return res.status(401).json({ valid: true, message: 'Token trasladado a otro dispositivo' });
        }

        res.json({ valid: true, username });

    } catch (err) {
        console.error('Error verificando el token:', err);
        res.status(500).json({ error: 'Error al verificar el token' });
    }
});

// ✅ **Ruta para eliminar un token específico**
app.post('/delete-token', async (req, res) => {
    const { tokenToDelete } = req.body;

    if (!tokenToDelete) {
        return res.status(400).json({ error: 'Token a eliminar no proporcionado' });
    }

    try {
        // Verificar si el token existe en la base de datos
        const result = await pool.query('SELECT * FROM sessions WHERE token = $1', [tokenToDelete]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Token no encontrado en la base de datos' });
        }

        // Eliminar el token de la base de datos.
        await pool.query('DELETE FROM sessions WHERE token = $1', [tokenToDelete]);

        res.json({ message: `El token ha sido eliminado correctamente.` });

    } catch (err) {
        console.error('Error al eliminar el token:', err);
        res.status(500).json({ error: 'Error al eliminar el token' });
    }
});

// ✅ **Crear el servidor HTTP o HTTPS**
let server;
if (process.env.NODE_ENV === 'production') {
    const sslOptions = {
        key: fs.readFileSync(process.env.SSL_KEY_PATH),
        cert: fs.readFileSync(process.env.SSL_CERT_PATH),
        ca: fs.readFileSync(process.env.SSL_CA_PATH),
    };

    server = https.createServer(sslOptions, app);
} else {
    server = http.createServer(app);
}

// ✅ **Iniciar el servidor**
const start = () => {
    const PORT = process.env.PORT || 4000;
    console.log(`Intentando iniciar servidor en el puerto ${PORT}...`);
    server.listen(PORT, '0.0.0.0', () => {
        console.log(`Servidor escuchando en http://0.0.0.0:${PORT}`);
    });
};

start(); // Iniciar el servidor