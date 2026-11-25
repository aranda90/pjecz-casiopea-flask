-- 2026-11-24
-- Desactivar temporalmente los tipos de envío SMS y WhatsApp en `aut_tipos_envios`
-- mientras no esté lista la conexión con Twilio y WhatsApp.
-- Con esto, la verificación en dos pasos solo ofrece el envío por correo electrónico.
-- Para volver a activarlos: UPDATE aut_tipos_envios SET activo = TRUE, modificado = CURRENT_TIMESTAMP WHERE id IN (2, 3);

UPDATE aut_tipos_envios
SET activo = FALSE, modificado = CURRENT_TIMESTAMP
WHERE id IN (2, 3);
