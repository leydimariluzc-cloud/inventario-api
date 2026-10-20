
const mysql = require('mysql2');

const conexion = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '12345l',
    database: 'inventario',
    port: 3307
});

// Comprobar la conexión con MariaDB
conexion.getConnection((error, connection) => {
    if (error) {
        console.error('Error al conectar con MariaDB:', error.message);
        return;
    }

    console.log('Conexión con MariaDB exitosa');

    connection.release();
});

module.exports = conexion.promise();
