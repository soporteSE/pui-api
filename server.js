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

// Endpoint raíz
app.get('/', (req, res) => {
  res.send('API funcionando 🚀');
});

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
    return res.status(500).json({ error: 'Error en el servidor' });
  }
});


// Ejemplo de endpoint protegido
app.post('/activar-reporte', validarToken, (req, res) => {
  const { id, curp } = req.body;
  if (!id || !curp) {
    return res.status(400).json({ error: 'Campos id y curp son obligatorios' });
  }
  return res.json({ mensaje: 'Reporte activado correctamente', datos: { id, curp } });
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

  if (!curp || !fase_busqueda) {
    return res.status(400).json({ error: 'Campos curp y fase_busqueda son obligatorios' });
  }

  if (!/^[A-Z0-9]{18}$/.test(curp)) {
    return res.status(400).json({ error: 'CURP inválido, debe tener 18 caracteres alfanuméricos en mayúsculas' });
  }

  if (!["1", "2", "3"].includes(fase_busqueda)) {
    return res.status(400).json({ error: 'fase_busqueda debe ser 1, 2 o 3' });
  }

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

  console.log(`Búsqueda finalizada para ID: ${id}, CURP: ${curp}`);

  return res.json({
    mensaje: 'Búsqueda histórica finalizada correctamente',
    datos: { id, curp }
  });
});

// Endpoint para desactivar reporte
app.post('/desactivar-reporte', validarToken, (req, res) => {
  const { id, curp } = req.body;

  if (!id || !curp) {
    return res.status(400).json({ error: 'Campos id y curp son obligatorios' });
  }

  if (!/^[A-Z0-9]{18}$/.test(curp)) {
    return res.status(400).json({ error: 'CURP inválido, debe tener 18 caracteres alfanuméricos en mayúsculas' });
  }

  console.log(`Reporte desactivado para ID: ${id}, CURP: ${curp}`);

  return res.json({
    mensaje: 'Reporte desactivado correctamente',
    datos: { id, curp }
  });
});

// Puerto dinámico para Railway/AWS
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`API PUI corriendo en http://localhost:${PORT}`);
});
