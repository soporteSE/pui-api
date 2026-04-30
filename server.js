const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());

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

// Endpoint de login
app.post('/login', (req, res) => {
  const { institucion_id, clave } = req.body;

  if (institucion_id === process.env.INSTITUCION_ID && clave === process.env.CLAVE) {
    const token = jwt.sign(
      { institucion_id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    return res.json({ token });
  } else {
    return res.status(403).json({ error: 'Credenciales inválidas' });
  }
});

// Ejemplo de endpoint protegido
app.post('/activar-reporte', validarToken, (req, res) => {
  const { id, curp } = req.body;
  if (!id || !curp) {
    return res.status(400).json({ error: 'Campos id y curp son obligatorios' });
  }
  // Aquí guardarías el reporte en tu base de datos
  return res.json({ mensaje: 'Reporte activado correctamente', datos: { id, curp } });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`API PUI corriendo en http://localhost:${PORT}`);
});

// Endpoint para notificar coincidencia
app.post('/notificar-coincidencia', validarToken, (req, res) => {
  const {
    curp,
    nombre,
    primer_apellido,
    segundo_apellido,
    fase_busqueda,
    tipo_evento,
    fecha_evento,
    descripcion_lugar_evento,
    direccion_evento
  } = req.body;

  // Validaciones básicas
  if (!curp || !fase_busqueda) {
    return res.status(400).json({ error: 'Campos curp y fase_busqueda son obligatorios' });
  }

  if (!/^[A-Z0-9]{18}$/.test(curp)) {
    return res.status(400).json({ error: 'CURP inválido, debe tener 18 caracteres alfanuméricos en mayúsculas' });
  }

  if (!["1", "2", "3"].includes(fase_busqueda)) {
    return res.status(400).json({ error: 'fase_busqueda debe ser 1, 2 o 3' });
  }

  // Simulación de persistencia (aquí iría tu base de datos)
  const coincidencia = {
    curp,
    nombre,
    primer_apellido,
    segundo_apellido,
    fase_busqueda,
    tipo_evento,
    fecha_evento,
    descripcion_lugar_evento,
    direccion_evento
  };

  console.log("Coincidencia recibida:", coincidencia);

  return res.json({
    mensaje: 'Coincidencia notificada correctamente',
    datos: coincidencia
  });
});

// Endpoint para reportar finalización de búsqueda histórica
app.post('/busqueda-finalizada', validarToken, (req, res) => {
  const { id, curp } = req.body;

  if (!id || !curp) {
    return res.status(400).json({ error: 'Campos id y curp son obligatorios' });
  }

  if (!/^[A-Z0-9]{18}$/.test(curp)) {
    return res.status(400).json({ error: 'CURP inválido, debe tener 18 caracteres alfanuméricos en mayúsculas' });
  }

  // Aquí podrías marcar en tu base de datos que la búsqueda histórica terminó
  console.log(`Búsqueda finalizada para ID: ${id}, CURP: ${curp}`);

  return res.json({
    mensaje: 'Búsqueda histórica finalizada correctamente',
    datos: { id, curp }
  });
});

// Endpoint para desactivar reporte cuando CNB localiza a la persona
app.post('/desactivar-reporte', validarToken, (req, res) => {
  const { id, curp } = req.body;

  if (!id || !curp) {
    return res.status(400).json({ error: 'Campos id y curp son obligatorios' });
  }

  if (!/^[A-Z0-9]{18}$/.test(curp)) {
    return res.status(400).json({ error: 'CURP inválido, debe tener 18 caracteres alfanuméricos en mayúsculas' });
  }

  // Aquí marcarías en tu base de datos que el caso fue dado de baja
  console.log(`Reporte desactivado para ID: ${id}, CURP: ${curp}`);

  return res.json({
    mensaje: 'Reporte desactivado correctamente',
    datos: { id, curp }
  });
});

