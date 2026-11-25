"""
Communications, enviar a Sendgrid un mensaje con el código de verificación en dos pasos
"""

import base64
import os
from datetime import datetime

import pytz
import sendgrid
from flask import current_app, render_template
from sendgrid.helpers.mail import Attachment, Content, ContentId, Disposition, Email, FileContent, FileName, FileType, Mail, To

from ....lib.exceptions import (
    MyIsDeletedError,
    MyMissingConfigurationError,
    MyNotExistsError,
    MyNotValidParamError,
    MyRequestError,
)
from ....lib.safe_string import safe_uuid
from ...aut_verificaciones_usuarios.models import AutVerificacionUsuario
from . import bitacora

# Logo del encabezado; va adjunto dentro del correo y la plantilla lo usa con <img src="cid:logo_saji">
LOGO_ARCHIVO = os.path.join("img", "logo-saji-invertido.png")
LOGO_CONTENT_ID = "logo_saji"


def logo_adjunto() -> Attachment | None:
    """Elaborar el logo como adjunto incrustado; si no existe el archivo, el correo se envía sin logo"""
    ruta = os.path.join(current_app.static_folder, LOGO_ARCHIVO)
    if not os.path.exists(ruta):
        bitacora.warning(f"No se encontró el logo {ruta}, se envía el correo sin logo")
        return None
    with open(ruta, "rb") as archivo:
        contenido = base64.b64encode(archivo.read()).decode()
    return Attachment(
        FileContent(contenido),
        FileName(os.path.basename(ruta)),
        FileType("image/png"),
        Disposition("inline"),
        ContentId(LOGO_CONTENT_ID),
    )


def enviar_a_sendgrid_mensaje_codigo_verificacion(
    aut_verificacion_usuario_id: str, motivo: str, minutos: int
) -> tuple[str, str, str]:
    """Enviar a Sendgrid un mensaje con el código de verificación; se ejecuta en el momento, no en segundo plano"""
    mensajes = []
    mensaje_info = "Inicia enviar a Sendgrid un mensaje con el código de verificación"
    mensajes.append(mensaje_info)
    bitacora.info(mensaje_info)

    # Tomar las variables de entorno de la configuración de la aplicación (se ejecuta dentro de la petición)
    sendgrid_api_key = current_app.config.get("SENDGRID_API_KEY", "")
    sendgrid_from_email = current_app.config.get("SENDGRID_FROM_EMAIL", "")
    tz = current_app.config.get("TZ", "America/Mexico_City")

    # Validar que esté definida la variable de entorno SENDGRID_API_KEY
    if not sendgrid_api_key:
        mensaje_error = "La variable de entorno SENDGRID_API_KEY no está definida"
        bitacora.error(mensaje_error)
        raise MyMissingConfigurationError(mensaje_error)

    # Validar que esté definida la variable de entorno SENDGRID_FROM_EMAIL
    if not sendgrid_from_email:
        mensaje_error = "La variable de entorno SENDGRID_FROM_EMAIL no está definida"
        bitacora.error(mensaje_error)
        raise MyMissingConfigurationError(mensaje_error)

    # Consultar la aut_verificacion_usuario
    aut_verificacion_usuario_id = safe_uuid(aut_verificacion_usuario_id)
    if not aut_verificacion_usuario_id:
        mensaje_error = "ID de verificación inválido"
        bitacora.error(mensaje_error)
        raise MyNotValidParamError(mensaje_error)
    aut_verificacion_usuario = AutVerificacionUsuario.query.get(aut_verificacion_usuario_id)
    if not aut_verificacion_usuario:
        mensaje_error = "La verificación no existe"
        bitacora.error(mensaje_error)
        raise MyNotExistsError(mensaje_error)

    # Validar el estatus, que no esté eliminada
    if aut_verificacion_usuario.estatus != "A":
        mensaje_error = "La verificación está eliminada"
        bitacora.error(mensaje_error)
        raise MyIsDeletedError(mensaje_error)

    # Validar que el código NO haya sido utilizado
    if aut_verificacion_usuario.utilizado is True:
        mensaje_error = "El código de verificación YA FUE utilizado"
        bitacora.error(mensaje_error)
        raise MyIsDeletedError(mensaje_error)

    # Validar que tenga el correo electrónico a donde se envía
    if not aut_verificacion_usuario.email:
        mensaje_error = "La verificación no tiene correo electrónico"
        bitacora.error(mensaje_error)
        raise MyNotValidParamError(mensaje_error)

    # Elaborar el asunto del mensaje
    asunto_str = "Código de verificación de la Plataforma Casiopea"

    # Elaborar el contenido del mensaje
    fecha_envio = datetime.now(tz=pytz.timezone(tz)).strftime("%d/%b/%Y %H:%M")
    contenido_html = render_template(
        "usuarios/email_codigo_verificacion.jinja2",
        nombre=aut_verificacion_usuario.usuario.nombres,
        email=aut_verificacion_usuario.email,
        codigo=aut_verificacion_usuario.codigo_verificacion,
        motivo=motivo,
        minutos=minutos,
        fecha_elaboracion=fecha_envio,
    )

    # Enviar el e-mail
    send_grid = sendgrid.SendGridAPIClient(api_key=sendgrid_api_key)
    to_email = To(aut_verificacion_usuario.email)
    remitente_email = Email(sendgrid_from_email)
    contenido = Content("text/html", contenido_html)
    mail = Mail(
        from_email=remitente_email,
        to_emails=to_email,
        subject=asunto_str,
        html_content=contenido,
    )
    logo = logo_adjunto()
    if logo is not None:
        mail.attachment = logo

    # Enviar mensaje de correo electrónico
    try:
        send_grid.send(mail)
    except Exception as error:
        mensaje_error = f"Error al enviar el mensaje por Sendgrid: {str(error)}"
        bitacora.error(mensaje_error)
        raise MyRequestError(mensaje_error)

    # Elaborar mensaje_termino (sin el código, para no dejarlo en la bitácora)
    mensaje_termino = f"Se ha enviado un mensaje por Sendgrid a {aut_verificacion_usuario.email} con el código de verificación."
    mensajes.append(mensaje_termino)
    bitacora.info(mensaje_termino)

    # Entregar mensaje_termino, nombre_archivo y url_publica
    return "\n".join(mensajes), "", ""
