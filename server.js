
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const conexion = require('./db');

const app = express();
const PORT = 3000;

// CONFIGURACION GENERAL
app.use(cors());
app.use(express.json());

// COMPROBAR QUE LA API FUNCIONA
app.get('/api', (req, res) => {
    res.json({
        mensaje: 'API de inventario funcionando correctamente'
    });
});

// ===============================
// AUTENTICACION CON TOKEN JWT
// ===============================

function autenticarToken(req, res, next) {
    const cabecera = req.headers.authorization;

    if (!cabecera || !cabecera.startsWith('Bearer ')) {
        return res.status(401).json({
            mensaje: 'Debes iniciar sesion para acceder'
        });
    }

    const token = cabecera.split(' ')[1];

    jwt.verify(token, process.env.JWT_SECRET, (error, usuario) => {
        if (error) {
            return res.status(403).json({
                mensaje: 'Token invalido o vencido'
            });
        }

        req.usuario = usuario;
        next();
    });
}

// COMPROBAR SI ES ADMINISTRADOR
async function soloAdministrador(req, res, next) {
    try {
        const [usuarios] = await conexion.query(
            'SELECT id, rol FROM usuarios WHERE id = ?',
            [req.usuario.id]
        );

        if (usuarios.length === 0) {
            return res.status(401).json({
                mensaje: 'Usuario no encontrado'
            });
        }

        if (usuarios[0].rol !== 'admin') {
            return res.status(403).json({
                mensaje: 'No tienes permisos de administrador'
            });
        }

        next();
    } catch (error) {
        console.error('Error al verificar administrador:', error);
        res.status(500).json({
            mensaje: 'Error al verificar permisos'
        });
    }
}

// ===============================
// REGISTRO DE USUARIOS
// ===============================

app.post('/api/usuarios/registro', async (req, res) => {
    try {
        const { nombre, correo, password } = req.body;

        if (!nombre || !correo || !password) {
            return res.status(400).json({
                mensaje: 'Completa nombre, correo y contrasena'
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                mensaje: 'La contrasena debe tener al menos 8 caracteres'
            });
        }

        const correoNormalizado = correo.trim().toLowerCase();

        const [existentes] = await conexion.query(
            'SELECT id FROM usuarios WHERE correo = ?',
            [correoNormalizado]
        );

        if (existentes.length > 0) {
            return res.status(409).json({
                mensaje: 'El correo ya esta registrado'
            });
        }

        const passwordHash = await bcrypt.hash(password, 10);

        const [resultado] = await conexion.query(
            `INSERT INTO usuarios (nombre, correo, password)
             VALUES (?, ?, ?)`,
            [nombre.trim(), correoNormalizado, passwordHash]
        );

        res.status(201).json({
            mensaje: 'Usuario registrado correctamente',
            id: resultado.insertId
        });
    } catch (error) {
        console.error('Error en registro:', error);
        res.status(500).json({
            mensaje: 'Error al registrar usuario'
        });
    }
});

// ===============================
// INICIO DE SESION
// ===============================

app.post('/api/usuarios/login', async (req, res) => {
    try {
        const { correo, password } = req.body;

        if (!correo || !password) {
            return res.status(400).json({
                mensaje: 'Ingresa correo y contrasena'
            });
        }

        const correoNormalizado = correo.trim().toLowerCase();

        const [usuarios] = await conexion.query(
            `SELECT id, nombre, correo, password, rol
             FROM usuarios
             WHERE correo = ?`,
            [correoNormalizado]
        );

        if (usuarios.length === 0) {
            return res.status(401).json({
                mensaje: 'Correo o contrasena incorrectos'
            });
        }

        const usuario = usuarios[0];

        const passwordCorrecta = await bcrypt.compare(
            password,
            usuario.password
        );

        if (!passwordCorrecta) {
            return res.status(401).json({
                mensaje: 'Correo o contrasena incorrectos'
            });
        }

        const token = jwt.sign(
            {
                id: usuario.id,
                correo: usuario.correo
            },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({
            mensaje: 'Inicio de sesion correcto',
            token,
            usuario: {
                id: usuario.id,
                nombre: usuario.nombre,
                correo: usuario.correo,
                rol: usuario.rol
            }
        });
    } catch (error) {
        console.error('Error en inicio de sesion:', error);
        res.status(500).json({
            mensaje: 'Error al iniciar sesion'
        });
    }
});

// ===============================
// LISTAR TODOS LOS USUARIOS
// SOLO ADMINISTRADOR
// ESTA ES LA RUTA QUE FALTABA
// ===============================

app.get(
    '/api/usuarios',
    autenticarToken,
    soloAdministrador,
    async (req, res) => {
        try {
            const [usuarios] = await conexion.query(
                `SELECT id, nombre, correo, rol, fecha_creacion
                 FROM usuarios
                 ORDER BY id DESC`
            );

            res.json(usuarios);
        } catch (error) {
            console.error('Error al listar usuarios:', error);
            res.status(500).json({
                mensaje: 'Error al consultar usuarios'
            });
        }
    }
);

// ===============================
// CONSULTAR UN USUARIO POR ID
// SOLO ADMINISTRADOR
// ===============================

app.get(
    '/api/usuarios/:id',
    autenticarToken,
    soloAdministrador,
    async (req, res) => {
        try {
            const id = Number(req.params.id);

            if (!Number.isInteger(id) || id <= 0) {
                return res.status(400).json({
                    mensaje: 'ID de usuario invalido'
                });
            }

            const [usuarios] = await conexion.query(
                `SELECT id, nombre, correo, rol, fecha_creacion
                 FROM usuarios
                 WHERE id = ?`,
                [id]
            );

            if (usuarios.length === 0) {
                return res.status(404).json({
                    mensaje: 'Usuario no encontrado'
                });
            }

            res.json(usuarios[0]);
        } catch (error) {
            console.error('Error al consultar usuario:', error);
            res.status(500).json({
                mensaje: 'Error al consultar usuario'
            });
        }
    }
);

// ===============================
// ACTUALIZAR USUARIO
// SOLO ADMINISTRADOR
// ===============================

app.put(
    '/api/usuarios/:id',
    autenticarToken,
    soloAdministrador,
    async (req, res) => {
        try {
            const id = Number(req.params.id);
            const { nombre, correo, password } = req.body;

            if (!Number.isInteger(id) || id <= 0) {
                return res.status(400).json({
                    mensaje: 'ID de usuario invalido'
                });
            }

            if (!nombre || !correo) {
                return res.status(400).json({
                    mensaje: 'Nombre y correo son obligatorios'
                });
            }

            if (password !== undefined &&
                (typeof password !== 'string' || password.length < 8)) {
                return res.status(400).json({
                    mensaje: 'La contrasena debe tener al menos 8 caracteres'
                });
            }

            const correoNormalizado = correo.trim().toLowerCase();

            const [existentes] = await conexion.query(
                'SELECT id FROM usuarios WHERE id = ?',
                [id]
            );

            if (existentes.length === 0) {
                return res.status(404).json({
                    mensaje: 'Usuario no encontrado'
                });
            }

            const [correoOcupado] = await conexion.query(
                'SELECT id FROM usuarios WHERE correo = ? AND id <> ?',
                [correoNormalizado, id]
            );

            if (correoOcupado.length > 0) {
                return res.status(409).json({
                    mensaje: 'Ese correo ya pertenece a otro usuario'
                });
            }

            if (password !== undefined) {
                const passwordHash = await bcrypt.hash(password, 10);

                await conexion.query(
                    `UPDATE usuarios
                     SET nombre = ?, correo = ?, password = ?
                     WHERE id = ?`,
                    [nombre.trim(), correoNormalizado, passwordHash, id]
                );
            } else {
                await conexion.query(
                    `UPDATE usuarios
                     SET nombre = ?, correo = ?
                     WHERE id = ?`,
                    [nombre.trim(), correoNormalizado, id]
                );
            }

            res.json({
                mensaje: 'Usuario actualizado correctamente'
            });
        } catch (error) {
            console.error('Error al actualizar usuario:', error);
            res.status(500).json({
                mensaje: 'Error al actualizar usuario'
            });
        }
    }
);

// ===============================
// ELIMINAR USUARIO
// SOLO ADMINISTRADOR
// ===============================

app.delete(
    '/api/usuarios/:id',
    autenticarToken,
    soloAdministrador,
    async (req, res) => {
        try {
            const id = Number(req.params.id);

            if (!Number.isInteger(id) || id <= 0) {
                return res.status(400).json({
                    mensaje: 'ID de usuario invalido'
                });
            }

            if (id === Number(req.usuario.id)) {
                return res.status(400).json({
                    mensaje: 'No puedes eliminar tu propia cuenta'
                });
            }

            const [resultado] = await conexion.query(
                'DELETE FROM usuarios WHERE id = ?',
                [id]
            );

            if (resultado.affectedRows === 0) {
                return res.status(404).json({
                    mensaje: 'Usuario no encontrado'
                });
            }

            res.json({
                mensaje: 'Usuario eliminado correctamente'
            });
        } catch (error) {
            console.error('Error al eliminar usuario:', error);
            res.status(500).json({
                mensaje: 'Error al eliminar usuario'
            });
        }
    }
);

// ===============================
// LISTAR PRODUCTOS
// ===============================

app.get('/api/productos', async (req, res) => {
    try {
        const [productos] = await conexion.query(
            'SELECT * FROM productos ORDER BY id DESC'
        );

        res.json(productos);
    } catch (error) {
        console.error('Error al listar productos:', error);
        res.status(500).json({
            mensaje: 'Error al consultar productos'
        });
    }
});

// ===============================
// CONSULTAR PRODUCTO POR ID
// ===============================

app.get('/api/productos/:id', async (req, res) => {
    try {
        const id = Number(req.params.id);

        if (!Number.isInteger(id) || id <= 0) {
            return res.status(400).json({
                mensaje: 'ID de producto invalido'
            });
        }

        const [productos] = await conexion.query(
            'SELECT * FROM productos WHERE id = ?',
            [id]
        );

        if (productos.length === 0) {
            return res.status(404).json({
                mensaje: 'Producto no encontrado'
            });
        }

        res.json(productos[0]);
    } catch (error) {
        console.error('Error al consultar producto:', error);
        res.status(500).json({
            mensaje: 'Error al consultar producto'
        });
    }
});

// ===============================
// REGISTRAR PRODUCTO
// REQUIERE TOKEN
// ===============================

app.post('/api/productos', autenticarToken, async (req, res) => {
    try {
        const { nombre, descripcion, precio, stock } = req.body;

        if (!nombre || precio === undefined || stock === undefined) {
            return res.status(400).json({
                mensaje: 'Nombre, precio y stock son obligatorios'
            });
        }

        const precioNumero = Number(precio);
        const stockNumero = Number(stock);

        if (!Number.isFinite(precioNumero) || precioNumero < 0) {
            return res.status(400).json({
                mensaje: 'El precio debe ser un numero valido no negativo'
            });
        }

        if (!Number.isInteger(stockNumero) || stockNumero < 0) {
            return res.status(400).json({
                mensaje: 'El stock debe ser un entero no negativo'
            });
        }

        const [resultado] = await conexion.query(
            `INSERT INTO productos (nombre, descripcion, precio, stock)
             VALUES (?, ?, ?, ?)`,
            [
                nombre.trim(),
                descripcion || '',
                precioNumero,
                stockNumero
            ]
        );

        res.status(201).json({
            mensaje: 'Producto registrado correctamente',
            id: resultado.insertId
        });
    } catch (error) {
        console.error('Error al registrar producto:', error);
        res.status(500).json({
            mensaje: 'Error al registrar producto'
        });
    }
});

// ===============================
// ACTUALIZAR PRODUCTO
// REQUIERE TOKEN
// ===============================

app.put('/api/productos/:id', autenticarToken, async (req, res) => {
    try {
        const id = Number(req.params.id);
        const { nombre, descripcion, precio, stock } = req.body;

        if (!Number.isInteger(id) || id <= 0) {
            return res.status(400).json({
                mensaje: 'ID de producto invalido'
            });
        }

        if (!nombre || precio === undefined || stock === undefined) {
            return res.status(400).json({
                mensaje: 'Nombre, precio y stock son obligatorios'
            });
        }

        const precioNumero = Number(precio);
        const stockNumero = Number(stock);

        if (!Number.isFinite(precioNumero) || precioNumero < 0) {
            return res.status(400).json({
                mensaje: 'El precio debe ser un numero valido no negativo'
            });
        }

        if (!Number.isInteger(stockNumero) || stockNumero < 0) {
            return res.status(400).json({
                mensaje: 'El stock debe ser un entero no negativo'
            });
        }

        const [resultado] = await conexion.query(
            `UPDATE productos
             SET nombre = ?, descripcion = ?, precio = ?, stock = ?
             WHERE id = ?`,
            [
                nombre.trim(),
                descripcion || '',
                precioNumero,
                stockNumero,
                id
            ]
        );

        if (resultado.affectedRows === 0) {
            const [existentes] = await conexion.query(
                'SELECT id FROM productos WHERE id = ?',
                [id]
            );

            if (existentes.length === 0) {
                return res.status(404).json({
                    mensaje: 'Producto no encontrado'
                });
            }
        }

        res.json({
            mensaje: 'Producto actualizado correctamente'
        });
    } catch (error) {
        console.error('Error al actualizar producto:', error);
        res.status(500).json({
            mensaje: 'Error al actualizar producto'
        });
    }
});

// ===============================
// ELIMINAR PRODUCTO
// REQUIERE TOKEN
// ===============================

app.delete('/api/productos/:id', autenticarToken, async (req, res) => {
    try {
        const id = Number(req.params.id);

        if (!Number.isInteger(id) || id <= 0) {
            return res.status(400).json({
                mensaje: 'ID de producto invalido'
            });
        }

        const [resultado] = await conexion.query(
            'DELETE FROM productos WHERE id = ?',
            [id]
        );

        if (resultado.affectedRows === 0) {
            return res.status(404).json({
                mensaje: 'Producto no encontrado'
            });
        }

        res.json({
            mensaje: 'Producto eliminado correctamente'
        });
    } catch (error) {
        console.error('Error al eliminar producto:', error);
        res.status(500).json({
            mensaje: 'Error al eliminar producto'
        });
    }
});

// ===============================
// INICIAR SERVIDOR
// ===============================

app.listen(PORT, () => {
    console.log(`Servidor funcionando en http://localhost:${PORT}`);
});
