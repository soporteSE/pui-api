const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');   // <-- Importa mysql2
const bcrypt = require('bcrypt');          // <-- Importa bcrypt
require('dotenv').config();

const app = express();
app.use(bodyParser.json());

// Conexión a MySQL
const pool = mysql.createPool({
  host: process.env.DB_HOST,       // ej. localhost
  user: process.env.DB_USER,       // tu usuario MySQL
  password: process.env.DB_PASSWORD, // tu contraseña MySQL
  database: process.env.DB_NAME    // tu base de datos
});

// Middleware para validar JWT en endpoints protegidos
function validarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Token requerido' });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Token inválido' });
    req.institucion = decoded;
    next();
  });
}

// Endpoint raíz
app.get('/', (req, res) => {
  res.send('API funcionando 🚀');
});

// Endpoint de login con MySQL
app.post('/login', async (req, res) => {
  const { institucion_id, clave } = req.body;

  try {
    const [rows] = await pool.query(
      'SELECT * FROM usuarios WHERE institucion_id = ?',
      [institucion_id]
    );

    if (rows.length === 0) {
      return res.status(403).json({ error: 'Usuario no encontrado' });
    }

    const usuario = rows[0];
    const match = await bcrypt.compare(clave, usuario.clave);

    if (!match) {
      return res.status(403).json({ error: 'Credenciales inválidas' });
    }

    const token = jwt.sign(
      { institucion_id: usuario.institucion_id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    return res.json({ token });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Error en el servidor', detalle: err.message });
  }
});

// ... (resto de tus endpoints igual que antes)

// Puerto dinámico para Railway/AWS
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`API PUI corriendo en http://localhost:${PORT}`);
});
