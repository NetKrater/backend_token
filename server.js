console.log("Iniciando el servidor...");

const express = require('express');
const http = require('http');
const https = require('https');
const fs = require('fs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const { Pool } = require('pg');

// Conexión a la base de datos
const pool = new Pool({
    user: 'postgres',
    host: '144.126.156.186',
    database: 'sessions_db',
    password: '132187ok',
    port: 5432,
});

// Verificar la conexión a la base de datos al iniciar
const checkDatabase = async () => {
    try {
        const dbResult = await pool.query('SELECT current_database()');
        console.log('Conectado a la base de datos:', dbResult.rows[0].current_database);

        const tableResult = await pool.query(
            'SELECT * FROM information_schema.tables WHERE table_name = $1',
            ['sessions']
        );
        if (tableResult.rows.length === 0) {
            throw new Error('La tabla sessions no existe en la base de datos.');
        }
        console.log('La tabla sessions existe.');
    } catch (err) {
        console.error('Error verificando la base de datos:', err);
        process.exit(1);
    }
};

checkDatabase();

// Crear la aplicación express
const app = express();
app.use(express.json());

// Configurar CORS
const allowedOrigins = [
    "https://cliente-html-git-master-oswaldo-cuestas-projects.vercel.app",
    "https://generador-toke-git-master-oswaldo-cuestas-projects.vercel.app",
    "http://127.0.0.1:5500",
    "http://127.0.0.1:5501",
    "http://localhost:5500",
    "http://localhost:5501",
];

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

// Ruta para generar un token JWT
app.post('/generate-token', async (req, res) => {
    const { username, device_id, expiration } = req.body;

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
        exp: Math.floor(expirationDate.getTime() / 1000), // Fecha de expiración en segundos
    };

    const token = jwt.sign(payload, process.env.JWT_SECRET_KEY);

    try {
        // Invalidar todos los tokens anteriores del usuario
        await pool.query('UPDATE sessions SET valid = false WHERE username = $1', [username]);

        // Insertar el nuevo token en la base de datos
        await pool.query(
            'INSERT INTO sessions(token, device_id, username, expiration_time, valid) VALUES($1, $2, $3, $4, $5)',
            [token, device_id, username, expirationDate, true]
        );

        res.json({ token });
    } catch (err) {
        console.error('Error generando o guardando el token:', err);
        res.status(500).json({ error: 'Error al generar el token' });
    }
});

// Ruta para verificar si el token es válido
app.post('/verify-token', async (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1];
    const { device_id } = req.body; // El cliente envía su device_id

    if (!token || !device_id) {
        return res.status(400).json({ error: 'Token o device_id no proporcionado' });
    }

    try {
        // Verificar el token
        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
        const username = decoded.username;

        // Verificar si el token está en la base de datos y es válido
        const result = await pool.query('SELECT * FROM sessions WHERE token = $1 AND valid = true', [token]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Token no encontrado o no válido' });
        }

        const activeSession = result.rows[0];

        // Verificar si el token ha expirado
        if (new Date(activeSession.expiration_time) < new Date()) {
            await pool.query('UPDATE sessions SET valid = false WHERE token = $1', [token]);
            return res.status(401).json({ valid: false, message: 'El token ha expirado' });
        }

        // Verificar si el token está siendo usado en otro dispositivo
        if (activeSession.device_id !== device_id) {
            return res.status(403).json({ valid: false, message: 'El token está siendo usado en otro dispositivo' });
        }

        res.json({ valid: true, username, expiration: activeSession.expiration_time });
    } catch (err) {
        console.error('Error verificando el token:', err);
        res.status(500).json({ error: 'Error al verificar el token' });
    }
});

// Ruta para eliminar un token específico
app.post('/delete-token', async (req, res) => {
    const { tokenToDelete } = req.body;

    if (!tokenToDelete) {
        return res.status(400).json({ error: 'Token a eliminar no proporcionado' });
    }

    try {
        // Eliminar el token de la base de datos
        await pool.query('DELETE FROM sessions WHERE token = $1', [tokenToDelete]);
        res.json({ message: 'El token ha sido eliminado correctamente.' });
    } catch (err) {
        console.error('Error al eliminar el token:', err);
        res.status(500).json({ error: 'Error al eliminar el token' });
    }
});

// Crear el servidor HTTP o HTTPS
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

// Iniciar el servidor. 
const start = () => {
    const PORT = process.env.PORT || 4000;
    console.log(`Intentando iniciar servidor en el puerto ${PORT}...`);
    server.listen(PORT, '0.0.0.0', () => {
        console.log(`Servidor escuchando en http://0.0.0.0:${PORT}`);
    });
};

start();