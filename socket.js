// src/socket/socket.js
const { Server } = require('socket.io');

function setupSocket(server) {
    const io = new Server(server);

    // Almacenar conexiones de dispositivos
    const deviceConnections = {};

    io.on('connection', (socket) => {
        console.log('Nuevo dispositivo conectado:', socket.id);

        // Escuchar el evento "register_device"
        socket.on('register_device', (device_id) => {
            deviceConnections[device_id] = socket.id; // Asociar device_id con socket.id
            console.log(`Dispositivo ${device_id} registrado con socket ID: ${socket.id}`);
        });

        // Escuchar el evento "logout_device"
        socket.on('logout_device', (device_id) => {
            if (deviceConnections[device_id]) {
                io.to(deviceConnections[device_id]).emit('force_logout'); // Notificar al dispositivo
                delete deviceConnections[device_id]; // Eliminar la conexión
                console.log(`Dispositivo ${device_id} ha sido desconectado.`);
            }
        });
    });

    return io;
}

module.exports = setupSocket;