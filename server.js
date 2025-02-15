console.log("Iniciando el servidor...");  // Esto debería aparecer en la consola al ejecutar el archivo

const express = require('express');
const http = require('http');
const https = require('https');
const fs = require('fs');
const { Server } = require('socket.io');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const { Pool } = require('pg'); // Importamos el Pool de pg para conectarnos a PostgreSQL

// Conexión a la base de datos sessions_db (sesiones de usuario)
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',  // o tu host de PostgreSQL.
    database: 'sessions_db',  // Base de datos para sesiones
    password: '132187ok',
    port: 5432,
});

// Crear la aplicación express
const app = express();
app.use(express.json());

// Configuración de CORS
app.use(cors({
    origin: '*', // Permitir solicitudes desde cualquier origen
    methods: ['GET', 'POST'],
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
        exp: Math.floor(expirationDate.getTime() / 1000), // Expiración en segundos
    };

    // Generar el token JWT
    const token = jwt.sign(payload, process.env.JWT_SECRET_KEY || 'mi_clave_secreta');

    try {
        // Verificar si ya hay una sesión activa con este token
        const result = await pool.query('SELECT * FROM sessions WHERE token = $1', [token]);

        if (result.rows.length > 0) {
            // Si ya hay una sesión activa, verificamos si el dispositivo es diferente
            const activeSession = result.rows[0];
            if (activeSession.device_id !== device_id) {
                // El token está en uso en otro dispositivo, cerramos la sesión anterior
                await pool.query('UPDATE sessions SET valid = false WHERE token = $1', [token]);

                // Insertar la nueva sesión en el dispositivo actual
                await pool.query(
                    'UPDATE sessions SET device_id = $1, expiration_time = $2 WHERE token = $3',
                    [device_id, expirationDate, token]
                );

                return res.json({ token, message: 'Token trasladado a otro dispositivo y sesión cerrada en el anterior dispositivo' });
            }
        } else {
            // Si no hay sesión activa, creamos una nueva sesión en la base de datos
            const userResult = await pool.query('SELECT id FROM users WHERE username = $1', [username]);

            let userId;
            if (userResult.rows.length === 0) {
                // Si el usuario no existe, creamos uno nuevo
                const insertUserResult = await pool.query('INSERT INTO users (username) VALUES ($1) RETURNING id', [username]);
                userId = insertUserResult.rows[0].id;
            } else {
                // Si el usuario ya existe, usamos su id
                userId = userResult.rows[0].id;
            }

            // Insertar la nueva sesión
            await pool.query(
                'INSERT INTO sessions(token, device_id, username, expiration_time, user_id) VALUES($1, $2, $3, $4, $5)',
                [token, device_id, username, expirationDate, userId]
            );
        }

        res.json({ token });

    } catch (err) {
        console.error('Error generando o guardando el token:', err);
        res.status(500).json({ error: 'Error al generar el token' });
    }
});


// Ruta para verificar si el token es válido y si está en el dispositivo correcto
app.post('/verify-token', async (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Obtener el token del header
    if (!token) {
        return res.status(400).json({ error: 'Token no proporcionado' });
    }

    try {
        // Verificar el token
        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY || 'mi_clave_secreta');
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
            // Si el token está en un dispositivo diferente, cerramos la sesión en el anterior dispositivo
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

// Crear el servidor HTTP
let server;
if (process.env.NODE_ENV === 'production') {
    // Si estamos en producción, usamos HTTPS
    const sslOptions = {
        key: fs.readFileSync('/ruta/a/tu/clave-privada.key'),   // Clave privada del certificado SSL
        cert: fs.readFileSync('/ruta/a/tu/certificado.crt'),  // Certificado SSL
        ca: fs.readFileSync('/ruta/a/tu/cadena-de-certificados.pem'), // Cadena de certificados (si es necesario)
    };

    server = https.createServer(sslOptions, app); // Crear el servidor HTTPS
} else {
    // En desarrollo, usamos HTTP
    server = http.createServer(app); // Crear el servidor HTTP
}

// Función para iniciar el servidor
const start = () => {
    const PORT = process.env.PORT || 4000;  // Puerto 4000 para desarrollo y producción
    console.log(`Intentando iniciar servidor en el puerto ${PORT}...`);
    server.listen(PORT, () => {
        console.log(`Servidor corriendo en ${process.env.NODE_ENV === 'production' ? 'https' : 'http'}://localhost:${PORT}`);
    });
};

start(); // Llamada a la función start para iniciar el servidor
