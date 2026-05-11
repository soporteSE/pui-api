const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const axios = require('axios');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());

// Conexión a MySQL
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

// Middleware para validar JWT
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

// Login
app.post('/login', async (req, res) => {
  const { institucion_id, clave } = req.body;
  try {
    const [rows] = await pool.query(
      'SELECT * FROM usuarios WHERE institucion_id = ?',
      [institucion_id]
    );
    if (rows.length === 0) return res.status(403).json({ error: 'Usuario no encontrado' });

    const usuario = rows[0];
    const match = await bcrypt.compare(clave, usuario.clave);
    if (!match) return res.status(403).json({ error: 'Credenciales inválidas' });

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

// Activar reporte (fases 1, 2 y 3)
app.post('/activar-reporte', validarToken, async (req, res) => {
  const {
    id, curp, nombre, primer_apellido, segundo_apellido,
    fecha_nacimiento, fecha_desaparicion, lugar_nacimiento,
    sexo_asignado, telefono
  } = req.body;

  if (!id || !curp) return res.status(400).json({ error: 'Campos id y curp son obligatorios' });

  try {
    // Guardar reporte
    await pool.query(
      `INSERT INTO reportes 
        (reporte_id, curp, nombre, primer_apellido, segundo_apellido, 
         fecha_nacimiento, fecha_desaparicion, lugar_nacimiento, sexo_asignado, telefono) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, curp, nombre || null, primer_apellido || null, segundo_apellido || null,
       fecha_nacimiento || null, fecha_desaparicion || null, lugar_nacimiento || null,
       sexo_asignado || null, telefono || null]
    );

    // 🔹 Fase 1: búsqueda básica
    const [rows] = await pool.query('SELECT * FROM personas WHERE curp = ?', [curp]);
    if (rows.length > 0) {
      const persona = rows[0];
      await axios.post('http://localhost:3000/notificar-coincidencia', {
        curp: persona.curp,
        nombre: persona.nombre,
        primer_apellido: persona.primer_apellido,
        segundo_apellido: persona.segundo_apellido,
        fase_busqueda: "1"
      }, { headers: { Authorization: req.headers['authorization'] } });
    }

    // 🔹 Fase 2: búsqueda histórica (máx. 12 años)
    if (fecha_desaparicion) {
      const fechaInicio = new Date(fecha_desaparicion);
      const fechaFin = new Date();
      const limite = new Date(fechaFin);
      limite.setFullYear(limite.getFullYear() - 12);
      if (fechaInicio < limite) fechaInicio.setTime(limite.getTime());

      const [historicos] = await pool.query(
        'SELECT * FROM eventos WHERE curp = ? AND fecha_evento BETWEEN ? AND ?',
        [curp, fechaInicio, fechaFin]
      );

      for (const evento of historicos) {
        await axios.post('http://localhost:3000/notificar-coincidencia', {
          curp,
          nombre,
          primer_apellido,
          segundo_apellido,
          fase_busqueda: "2",
          tipo_evento: evento.tipo_evento,
          fecha_evento: evento.fecha_evento,
          descripcion_lugar_evento: evento.descripcion,
          direccion_evento: evento.direccion
        }, { headers: { Authorization: req.headers['authorization'] } });
      }

      await axios.post('http://localhost:3000/busqueda-finalizada', { id, curp },
        { headers: { Authorization: req.headers['authorization'] } });
    }

    // 🔹 Fase 3: búsqueda continua (ejemplo simple cada hora)
    setInterval(async () => {
      const [nuevos] = await pool.query(
        'SELECT * FROM eventos WHERE curp = ? AND fecha_evento > NOW() - INTERVAL 1 HOUR',
        [curp]
      );
      for (const evento of nuevos) {
        await axios.post('http://localhost:3000/notificar-coincidencia', {
          curp,
          nombre,
          primer_apellido,
          segundo_apellido,
          fase_busqueda: "3",
          tipo_evento: evento.tipo_evento,
          fecha_evento: evento.fecha_evento,
          descripcion_lugar_evento: evento.descripcion,
          direccion_evento: evento.direccion
        }, { headers: { Authorization: req.headers['authorization'] } });
      }
    }, 3600000); // cada hora

    return res.json({ mensaje: 'Reporte activado y fases de búsqueda iniciadas' });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Error en el servidor', detalle: err.message });
  }
});

// Notificar coincidencia
app.post('/notificar-coincidencia', validarToken, async (req, res) => {
  const { curp, nombre, primer_apellido, segundo_apellido,
          fase_busqueda, tipo_evento, fecha_evento,
          descripcion_lugar_evento, direccion_evento } = req.body;

  if (!curp || !fase_busqueda) return res.status(400).json({ error: 'Campos curp y fase_busqueda son obligatorios' });
  if (!["1","2","3"].includes(fase_busqueda)) return res.status(400).json({ error: 'fase_busqueda debe ser 1, 2 o 3' });

  await pool.query(
    `INSERT INTO coincidencias_reportadas 
      (curp, nombre, primer_apellido, segundo_apellido, fase_busqueda, 
       tipo_evento, fecha_evento, descripcion_lugar_evento, direccion_evento) 
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [curp, nombre || null, primer_apellido || null, segundo_apellido || null,
     fase_busqueda, tipo_evento || null, fecha_evento || null,
     descripcion_lugar_evento || null, direccion_evento || null]
  );

  return res.json({ mensaje: 'Coincidencia notificada correctamente' });
});

// Finalizar búsqueda histórica
app.post('/busqueda-finalizada', validarToken, (req, res) => {
  const { id, curp } = req.body;
  if (!id || !curp) return res.status(400).json({ error: 'Campos id y curp son obligatorios' });
  console.log(`Búsqueda finalizada para ID: ${id}, CURP: ${curp}`);
  return res.json({ mensaje: 'Búsqueda histórica finalizada correctamente', datos: { id, curp } });
});

// Desactivar reporte
app.post('/desactivar-reporte', validarToken, (req, res) => {
  const { id, curp } = req.body;
  if (!id || !curp) return res.status(400).json({ error: 'Campos id y curp son obligatorios' });
  console.log(`Reporte desactivado para ID: ${id}, CURP: ${curp}`);
  return res.json({ mensaje: 'Reporte desactivado correctamente', datos: { id, curp } });
});

// Puerto dinámico
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`API PUI corriendo en http://localhost:${PORT}`);
});
