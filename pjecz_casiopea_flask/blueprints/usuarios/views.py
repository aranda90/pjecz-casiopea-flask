"""
Usuarios, vistas
"""

import json
import re
import secrets
from datetime import datetime, timedelta

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from google.auth.transport.requests import Request
from google.oauth2.id_token import verify_firebase_token
from pytz import timezone

from ...config.extensions import pwd_context
from ...config.firebase import get_firebase_settings
from ...lib.cryptography_api_key import generate_api_key
from ...lib.datatables import get_datatable_parameters, output_datatable_json
from ...lib.exceptions import MyAnyError
from ...lib.pwgen import generar_contrasena
from ...lib.safe_next_url import safe_next_url
from ...lib.safe_string import CONTRASENA_REGEXP, EMAIL_REGEXP, safe_email, safe_message, safe_string, safe_telefono, safe_uuid
from ..aut_tipos_envios.models import AutTipoEnvio
from ..aut_verificaciones_usuarios.models import AutVerificacionUsuario
from ..autoridades.models import Autoridad
from ..bitacoras.models import Bitacora
from ..distritos.models import Distrito
from ..entradas_salidas.models import EntradaSalida
from ..modulos.models import Modulo
from ..permisos.models import Permiso
from .communications.send_to_sendgrid_email_codigo_verificacion import enviar_a_sendgrid_mensaje_codigo_verificacion
from .decorators import anonymous_required, permission_required
from .forms import (
    CONTRASENA_MENSAJE,
    AccesoForm,
    CambiarContrasenaForm,
    FirebaseForm,
    UsuarioForm,
    VerificacionCodigoForm,
    VerificacionMetodoForm,
)
from .models import Usuario

MODULO = "USUARIOS"

# Verificación en dos pasos
VERIFICACION_MINUTOS_CADUCIDAD = 10  # Minutos que dura vigente un código
VERIFICACION_MINUTOS_SESION = 15  # Minutos para terminar la verificación después de escribir la contraseña
VERIFICACION_SEGUNDOS_REENVIO = 60  # Segundos de espera para reenviar un código
VERIFICACION_MAXIMO_INTENTOS = 5  # Igual que MAXIMO_INTENTOS de aut_verificaciones_usuarios
TIPO_ENVIO_CORREO = 1  # aut_tipos_envios: 1 = Correo Electrónico, 2 = SMS, 3 = WhatsApp

usuarios = Blueprint("usuarios", __name__, template_folder="templates")


def enmascarar_correo(correo: str) -> str:
    """Deja visibles los 2 primeros caracteres del correo"""
    arroba = correo.find("@")
    if arroba <= 2:
        return correo
    return correo[:2] + "*" * (arroba - 2) + correo[arroba:]


def enmascarar_telefono(telefono: str | None) -> str | None:
    """Deja visibles los 4 últimos dígitos del teléfono"""
    if not telefono or len(telefono) < 4:
        return None
    return "*" * 6 + telefono[-4:]


def iniciar_sesion(usuario: Usuario, siguiente: str):
    """Entrar al sistema; si la verificación en dos pasos está activa, primero pedir el código"""
    if current_app.config["TWO_FACTOR_AUTHENTICATION_ENABLED"]:
        limpiar_verificacion()
        session["verificacion_usuario_id"] = str(usuario.id)
        session["verificacion_siguiente"] = siguiente or ""
        session["verificacion_inicio"] = datetime.now().isoformat()
        return redirect(url_for("usuarios.verificacion_metodo"))
    return entrar(usuario, siguiente)


def entrar(usuario: Usuario, siguiente: str):
    """Hacer el login y redirigir"""
    if login_user(usuario, remember=True):
        if siguiente:
            return redirect(safe_next_url(siguiente))
        return redirect(url_for("sistemas.start"))
    flash("No está activa esa cuenta", "warning")
    return redirect(url_for("usuarios.login"))


def limpiar_verificacion():
    """Quitar de la sesión los datos de la verificación en dos pasos"""
    for llave in (
        "verificacion_usuario_id",
        "verificacion_siguiente",
        "verificacion_inicio",
        "verificacion_id",
        "verificacion_enviado",
    ):
        session.pop(llave, None)


def usuario_en_verificacion() -> Usuario | None:
    """Entregar el usuario que escribió bien su contraseña y está pendiente de verificar, o None"""
    usuario_id = session.get("verificacion_usuario_id")
    inicio = session.get("verificacion_inicio")
    if usuario_id is None or inicio is None:
        return None
    # Si ya pasó mucho tiempo desde que escribió la contraseña, tiene que volver a empezar
    if datetime.fromisoformat(inicio) < datetime.now() - timedelta(minutes=VERIFICACION_MINUTOS_SESION):
        limpiar_verificacion()
        return None
    usuario = Usuario.query.get(usuario_id)
    if usuario is None or usuario.estatus != "A":
        limpiar_verificacion()
        return None
    return usuario


def opciones_envio(usuario: Usuario) -> tuple[list[dict], str | None]:
    """Entregar los métodos de envío activos para el usuario y su teléfono enmascarado"""
    correo = enmascarar_correo(usuario.email)
    telefono = enmascarar_telefono(usuario.telefono)
    textos = {
        1: "Enviar código al correo electrónico",
        2: "Enviar código por mensaje de texto al número",
        3: "Enviar código por WhatsApp al número",
    }
    opciones = []
    for tipo in AutTipoEnvio.query.filter_by(activo=True, estatus="A").order_by(AutTipoEnvio.id).all():
        es_correo = tipo.id == TIPO_ENVIO_CORREO
        # Sin teléfono solo se puede por correo electrónico
        if not es_correo and telefono is None:
            continue
        opciones.append(
            {
                "id": tipo.id,
                "texto": textos.get(tipo.id, f"Enviar código por {tipo.descripcion}"),
                "destino": correo if es_correo else telefono,
            }
        )
    return opciones, telefono


def segundos_para_reenviar() -> int:
    """Entregar los segundos que faltan para poder pedir otro código"""
    enviado = session.get("verificacion_enviado")
    if not enviado:
        return 0
    transcurridos = (datetime.now() - datetime.fromisoformat(enviado)).total_seconds()
    return max(0, int(VERIFICACION_SEGUNDOS_REENVIO - transcurridos))


class CodigoNoEnviadoError(Exception):
    """No se pudo enviar el código de verificación"""


# Para qué se pide el código, aparece en el correo: "Hemos recibido una solicitud para ..."
MOTIVOS_CODIGO = {
    "login": "iniciar sesión en la Plataforma Casiopea",
    "contrasena": "cambiar la contraseña",
    "telefono": "cambiar el teléfono",
}


def generar_codigo(usuario: Usuario, aut_tipo_envio_id: int, motivo: str) -> str:
    """Guardar un código nuevo en aut_verificaciones_usuarios, enviarlo y entregar el destino enmascarado.
    Si no se puede enviar, el código se da de baja y se lanza CodigoNoEnviadoError"""
    es_correo = aut_tipo_envio_id == TIPO_ENVIO_CORREO
    codigo = f"{secrets.randbelow(1_000_000):06d}"
    verificacion = AutVerificacionUsuario(
        usuario_id=usuario.id,
        aut_tipo_envio_id=aut_tipo_envio_id,
        codigo_verificacion=codigo,
        tiempo_caducidad=datetime.now() + timedelta(minutes=VERIFICACION_MINUTOS_CADUCIDAD),
        email=usuario.email if es_correo else None,
        telefono=None if es_correo else usuario.telefono,
        direccion_ip=request.remote_addr,
        dispositivo=request.user_agent.string[:300] if request.user_agent.string else None,
    ).save()
    # En desarrollo, mostrar el código en la terminal
    if current_app.config["ENVIRONMENT"].lower() != "production":
        current_app.logger.warning("Verificación en dos pasos (desarrollo) %s: código %s", usuario.email, codigo)

    # Enviar por correo electrónico, solo si está configurado SendGrid
    # TODO: Enviar por SMS y WhatsApp cuando haya proveedor (por ahora están desactivados en aut_tipos_envios)
    if es_correo and current_app.config.get("SENDGRID_API_KEY"):
        try:
            enviar_a_sendgrid_mensaje_codigo_verificacion(
                aut_verificacion_usuario_id=str(verificacion.id),
                motivo=MOTIVOS_CODIGO.get(motivo, "verificar su identidad"),
                minutos=VERIFICACION_MINUTOS_CADUCIDAD,
            )
        except MyAnyError as error:
            current_app.logger.error(str(error))
            verificacion.delete()  # Se da de baja porque nunca llegó
            raise CodigoNoEnviadoError(
                "No se pudo enviar el correo con el código de verificación. Intente de nuevo."
            ) from error

    session["verificacion_id"] = str(verificacion.id)
    session["verificacion_enviado"] = datetime.now().isoformat()
    return destino_verificacion(verificacion)


def verificacion_en_curso(usuario: Usuario) -> AutVerificacionUsuario | None:
    """Entregar la verificación que se generó para el usuario y está guardada en la sesión, o None"""
    verificacion_id = session.get("verificacion_id")
    verificacion = AutVerificacionUsuario.query.get(verificacion_id) if verificacion_id else None
    if verificacion is None or verificacion.usuario_id != usuario.id:
        return None
    return verificacion


def destino_verificacion(verificacion: AutVerificacionUsuario) -> str | None:
    """Entregar el correo o teléfono enmascarado a donde se envió el código"""
    if verificacion.aut_tipo_envio_id == TIPO_ENVIO_CORREO:
        return enmascarar_correo(verificacion.email or "")
    return enmascarar_telefono(verificacion.telefono)


def validar_codigo(verificacion: AutVerificacionUsuario, codigo: str) -> str | None:
    """Validar el código; entrega None si es correcto o el mensaje de error.
    Cuando hay que pedir otro código, quita la verificación de la sesión."""
    if verificacion.utilizado:
        session.pop("verificacion_id", None)
        return "Ese código ya fue utilizado. Solicite uno nuevo."
    # Contar el intento
    verificacion.intentos += 1
    verificacion.save()
    if verificacion.intentos > VERIFICACION_MAXIMO_INTENTOS:
        session.pop("verificacion_id", None)
        return "Superó el número de intentos. Solicite un nuevo código."
    if verificacion.tiempo_caducidad < datetime.now():
        session.pop("verificacion_id", None)
        return "El código caducó. Solicite uno nuevo."
    if not secrets.compare_digest(codigo, verificacion.codigo_verificacion):
        restantes = VERIFICACION_MAXIMO_INTENTOS + 1 - verificacion.intentos
        return f"El código de verificación es incorrecto. Le quedan {restantes} intentos."
    # Código correcto: marcarlo como utilizado
    verificacion.utilizado = True
    verificacion.save()
    session.pop("verificacion_id", None)
    session.pop("verificacion_enviado", None)
    return None


@usuarios.route("/login", methods=["GET", "POST"])
@anonymous_required()
def login():
    """Acceso al Sistema"""
    firebase_settings = get_firebase_settings()
    # Si está configurado Firebase, usar formulario identidad-contraseña
    if firebase_settings.APIKEY != "":
        form = FirebaseForm()
        # Si se recibe el formulario
        if form.validate_on_submit():
            identidad = str(form.identidad.data).strip()
            token = form.token.data
            siguiente = str(form.siguiente.data)
            # Si es válido el email
            if re.fullmatch(EMAIL_REGEXP, identidad) is not None:
                http_request = Request()
                try:
                    id_info = verify_firebase_token(token, http_request)
                except Exception as error:
                    id_info = None
                    flash(f"Error al verificar el token: {error}", "warning")
                # Si es válido el token y el email coincide con la identidad
                if id_info and id_info["email"] == identidad:
                    usuario = Usuario.find_by_identity(identidad)
                    # Si el usuario existe y está activo, hacer login
                    if usuario and usuario.estatus == "A":
                        return iniciar_sesion(usuario, siguiente)
                    else:
                        flash("No está activa esa cuenta", "warning")
            else:
                flash("No es válido el correo electrónico o el token.", "warning")
        # Si viene el parámetro siguiente en la URL, agregarlo al formulario
        siguiente = request.args.get("siguiente")
        if siguiente is not None:
            form.siguiente.data = siguiente
        # Entregar formulario
        return render_template(
            "usuarios/login.jinja2",
            form=form,
            title="Plataforma Casiopea",
            firebase_settings=firebase_settings,
        )
    else:
        form = AccesoForm(siguiente=request.args.get("siguiente"))
        # Si se recibe el formulario
        if form.validate_on_submit():
            correo_electronico = str(form.correo_electronico.data).strip()
            contrasena = str(form.contrasena.data).strip()
            siguiente = str(form.siguiente.data)
            # Si son válidos el email y la contraseña
            if re.fullmatch(EMAIL_REGEXP, correo_electronico) is None:
                flash("No es válido el correo electrónico.", "warning")
            elif re.fullmatch(CONTRASENA_REGEXP, contrasena) is None:
                flash("No es válida la contraseña.", "warning")
            else:
                usuario = Usuario.find_by_identity(correo_electronico)
                # Si el usuario existe y está activo, hacer login
                if usuario and usuario.authenticated(password=contrasena):
                    if usuario.estatus == "A":
                        return iniciar_sesion(usuario, siguiente)
                    else:
                        flash("No está activa esa cuenta", "warning")
                else:
                    flash("Correo electrónico o contraseña incorrectos.", "warning")
        # Si viene el parámetro siguiente en la URL, agregarlo al formulario
        siguiente = request.args.get("siguiente")
        if siguiente is not None:
            form.siguiente.data = siguiente
        # Entregar formulario
        return render_template(
            "usuarios/login.jinja2",
            form=form,
            title="Plataforma Casiopea",
            firebase_settings=None,
        )


@usuarios.route("/login/verificacion", methods=["GET", "POST"])
@anonymous_required()
def verificacion_metodo():
    """Verificación en dos pasos, paso 1: elegir el método de envío y generar el código"""
    usuario = usuario_en_verificacion()
    if usuario is None:
        flash("Ingrese de nuevo su correo electrónico y contraseña.", "warning")
        return redirect(url_for("usuarios.login"))

    # Formulario con los métodos de envío
    opciones, telefono = opciones_envio(usuario)
    form = VerificacionMetodoForm()
    form.aut_tipo_envio.choices = [(opcion["id"], opcion["texto"]) for opcion in opciones]

    # Si se recibe el formulario, generar el código
    if form.validate_on_submit():
        if segundos_para_reenviar() > 0:
            flash(f"Espere {VERIFICACION_SEGUNDOS_REENVIO} segundos para solicitar otro código.", "warning")
            if session.get("verificacion_id"):
                return redirect(url_for("usuarios.verificacion_codigo"))
            return redirect(url_for("usuarios.verificacion_metodo"))
        try:
            destino = generar_codigo(usuario, form.aut_tipo_envio.data, "login")
        except CodigoNoEnviadoError as error:
            flash(str(error), "danger")
            return redirect(url_for("usuarios.verificacion_metodo"))
        flash(f"Se envió el código de verificación a {destino}.", "success")
        return redirect(url_for("usuarios.verificacion_codigo"))

    # Entregar formulario
    return render_template(
        "usuarios/verificacion_metodo.jinja2",
        form=form,
        opciones=opciones,
        telefono=telefono,
        title="Verificación de identidad",
    )


@usuarios.route("/login/verificacion/codigo", methods=["GET", "POST"])
@anonymous_required()
def verificacion_codigo():
    """Verificación en dos pasos, paso 2: capturar y validar el código"""
    usuario = usuario_en_verificacion()
    if usuario is None:
        flash("Ingrese de nuevo su correo electrónico y contraseña.", "warning")
        return redirect(url_for("usuarios.login"))

    # Consultar la verificación que se generó en el paso 1
    verificacion = verificacion_en_curso(usuario)
    if verificacion is None:
        return redirect(url_for("usuarios.verificacion_metodo"))

    # Si se recibe el formulario, validar el código
    form = VerificacionCodigoForm()
    if form.validate_on_submit():
        error = validar_codigo(verificacion, form.codigo.data)
        if error is None:
            # Código correcto: entrar
            siguiente = session.get("verificacion_siguiente", "")
            limpiar_verificacion()
            return entrar(usuario, siguiente)
        flash(error, "danger")
        if session.get("verificacion_id"):
            return redirect(url_for("usuarios.verificacion_codigo"))
        return redirect(url_for("usuarios.verificacion_metodo"))

    # Entregar formulario
    return render_template(
        "usuarios/verificacion_codigo.jinja2",
        form=form,
        destino=destino_verificacion(verificacion),
        aut_tipo_envio_id=verificacion.aut_tipo_envio_id,
        segundos_reenvio=segundos_para_reenviar(),
        title="Verificación de identidad",
    )


@usuarios.route("/login/verificacion/cancelar")
def verificacion_cancelar():
    """Cancelar la verificación en dos pasos y regresar al login"""
    limpiar_verificacion()
    return redirect(url_for("usuarios.login"))


@usuarios.route("/logout")
@login_required
def logout():
    """Salir del Sistema"""
    EntradaSalida(
        usuario_id=current_user.id,
        tipo="SALIO",
        direccion_ip=request.remote_addr,
    ).save()
    logout_user()
    flash("Ha salido de este sistema.", "success")
    return redirect(url_for("usuarios.login"))


@usuarios.route("/perfil")
@login_required
def profile():
    """Mostrar el Perfil"""
    ahora_utc = datetime.now(timezone("UTC"))
    ahora_mx_coah = ahora_utc.astimezone(timezone("America/Mexico_City"))
    formato_fecha = "%Y-%m-%d %H:%M %p"
    # Métodos de envío para el diálogo de cambiar teléfono
    opciones, telefono_enmascarado = opciones_envio(Usuario.query.get(current_user.id))
    return render_template(
        "usuarios/profile.jinja2",
        ahora_utc_str=ahora_utc.strftime(formato_fecha),
        ahora_mx_coah_str=ahora_mx_coah.strftime(formato_fecha),
        opciones=opciones,
        telefono_enmascarado=telefono_enmascarado,
        segundos_reenvio=VERIFICACION_SEGUNDOS_REENVIO,
    )


# Datos que el usuario puede cambiar desde su perfil en páginas, después de confirmar su identidad con un código
# El teléfono y el correo electrónico se cambian en diálogos dentro del perfil (ver las rutas *_json)
PERFIL_ACCIONES = {
    "contrasena": {
        "titulo": "Cambiar contraseña",
        "icono": "mdi-key-outline",
        "dato": "tu contraseña",
        "ruta": "usuarios.perfil_contrasena_nueva",
    },
}


def limpiar_perfil_verificacion():
    """Quitar de la sesión los datos de la verificación del perfil"""
    for llave in ("verificacion_id", "verificacion_enviado", "perfil_verificado_accion", "perfil_verificado_hora"):
        session.pop(llave, None)


def perfil_verificado(accion: str) -> bool:
    """¿Validó el código para esta acción hace menos de VERIFICACION_MINUTOS_CADUCIDAD minutos?"""
    hora = session.get("perfil_verificado_hora")
    if session.get("perfil_verificado_accion") != accion or hora is None:
        return False
    return datetime.fromisoformat(hora) >= datetime.now() - timedelta(minutes=VERIFICACION_MINUTOS_CADUCIDAD)


def registrar_bitacora_perfil(descripcion: str):
    """Registrar en la bitácora un cambio hecho desde el perfil"""
    Bitacora(
        modulo=Modulo.query.filter_by(nombre=MODULO).first(),
        usuario=current_user,
        descripcion=safe_message(descripcion),
        url=url_for("usuarios.profile"),
    ).save()


def terminar_cambio_perfil(descripcion: str, mensaje: str):
    """Limpiar la sesión, registrar en la bitácora y regresar al perfil"""
    limpiar_perfil_verificacion()
    registrar_bitacora_perfil(descripcion)
    flash(mensaje, "success")
    return redirect(url_for("usuarios.profile"))


def pedir_verificacion(accion: str):
    """Regresar al paso 1 porque no ha confirmado su identidad"""
    session.pop("perfil_verificado_accion", None)
    session.pop("perfil_verificado_hora", None)
    flash("Primero confirme su identidad con el código de verificación.", "warning")
    return redirect(url_for("usuarios.perfil_verificacion_metodo", accion=accion))


@usuarios.route("/perfil/<accion>")
@login_required
def perfil_verificacion_metodo(accion):
    """Cambiar un dato del perfil, paso 1: elegir el método de envío.
    El código se pide en un diálogo de la misma página (ver perfil_enviar_codigo_json y perfil_validar_codigo_json)"""
    if accion not in PERFIL_ACCIONES:
        abort(404)
    usuario = Usuario.query.get(current_user.id)
    session.pop("perfil_verificado_accion", None)  # Hay que verificar de nuevo
    session.pop("perfil_verificado_hora", None)
    opciones, telefono = opciones_envio(usuario)
    return render_template(
        "usuarios/perfil_verificacion_metodo.jinja2",
        opciones=opciones,
        telefono=telefono,
        accion=accion,
        segundos_reenvio=VERIFICACION_SEGUNDOS_REENVIO,
        **PERFIL_ACCIONES[accion],
    )


@usuarios.route("/perfil/contrasena/nueva", methods=["GET", "POST"])
@login_required
def perfil_contrasena_nueva():
    """Cambiar contraseña, paso 3: escribir la contraseña nueva"""
    if not perfil_verificado("contrasena"):
        return pedir_verificacion("contrasena")
    form = CambiarContrasenaForm()
    if form.validate_on_submit():
        usuario = Usuario.query.get(current_user.id)
        usuario.contrasena = pwd_context.hash(form.contrasena.data.strip())
        usuario.save()
        return terminar_cambio_perfil(f"Cambió su contraseña {usuario.email}", "Su contraseña se actualizó correctamente.")
    return render_template(
        "usuarios/perfil_contrasena_nueva.jinja2",
        form=form,
        contrasena_mensaje=CONTRASENA_MENSAJE,
        **PERFIL_ACCIONES["contrasena"],
    )


@usuarios.route("/perfil/correo/guardar_json", methods=["POST"])
@login_required
def perfil_correo_guardar_json():
    """Diálogo cambiar correo electrónico: se confirma con la contraseña actual (igual que DialogCambiarCorreo.tsx)"""
    usuario = Usuario.query.get(current_user.id)
    datos = request.get_json(silent=True) or {}
    email = safe_email(str(datos.get("email", "")))
    confirmar = safe_email(str(datos.get("confirmar", "")))
    contrasena = str(datos.get("contrasena", "")).strip()
    contrasena_confirmar = str(datos.get("contrasena_confirmar", "")).strip()
    if email == "":
        return {"success": False, "message": "El correo electrónico no es válido."}
    if email != confirmar:
        return {"success": False, "message": "Los correos electrónicos no coinciden."}
    if contrasena != contrasena_confirmar:
        return {"success": False, "message": "Las contraseñas no coinciden."}
    if contrasena == "" or not usuario.contrasena or not usuario.authenticated(password=contrasena):
        return {"success": False, "message": "La contraseña es incorrecta."}
    if email == usuario.email:
        return {"success": False, "message": "Es el mismo correo electrónico que ya tiene."}
    if Usuario.query.filter(Usuario.email == email, Usuario.id != usuario.id).first():
        return {"success": False, "message": "Ese correo electrónico ya está en uso. Debe de ser único."}
    anterior = usuario.email
    usuario.email = email
    usuario.save()
    registrar_bitacora_perfil(f"Cambió su correo electrónico de {anterior} a {email}")
    return {"success": True, "message": "Su correo electrónico se actualizó correctamente.", "email": email}


# Datos del perfil que se cambian después de validar un código en un diálogo
PERFIL_ACCIONES_CON_CODIGO = ("contrasena", "telefono")


@usuarios.route("/perfil/<accion>/enviar_codigo_json", methods=["POST"])
@login_required
def perfil_enviar_codigo_json(accion):
    """Generar el código de verificación con el método elegido (cambiar contraseña o teléfono)"""
    if accion not in PERFIL_ACCIONES_CON_CODIGO:
        abort(404)
    usuario = Usuario.query.get(current_user.id)
    datos = request.get_json(silent=True) or {}
    try:
        aut_tipo_envio_id = int(datos.get("aut_tipo_envio"))
    except TypeError, ValueError:
        aut_tipo_envio_id = 0
    opciones, _ = opciones_envio(usuario)
    if aut_tipo_envio_id not in [opcion["id"] for opcion in opciones]:
        return {"success": False, "message": "Elija un método de envío."}
    session.pop("perfil_verificado_accion", None)  # Hay que verificar de nuevo
    session.pop("perfil_verificado_hora", None)
    segundos = segundos_para_reenviar()
    if segundos > 0:
        return {"success": False, "message": f"Espere {segundos} segundos para solicitar otro código.", "segundos": segundos}
    try:
        destino = generar_codigo(usuario, aut_tipo_envio_id, accion)
    except CodigoNoEnviadoError as error:
        return {"success": False, "message": str(error)}
    return {
        "success": True,
        "message": f"Se envió el código de verificación a {destino}.",
        "destino": destino,
        "segundos": VERIFICACION_SEGUNDOS_REENVIO,
    }


@usuarios.route("/perfil/<accion>/validar_codigo_json", methods=["POST"])
@login_required
def perfil_validar_codigo_json(accion):
    """Validar el código de verificación (cambiar contraseña o teléfono)"""
    if accion not in PERFIL_ACCIONES_CON_CODIGO:
        abort(404)
    usuario = Usuario.query.get(current_user.id)
    verificacion = verificacion_en_curso(usuario)
    if verificacion is None:
        return {"success": False, "message": "Solicite un código de verificación.", "reiniciar": True}
    datos = request.get_json(silent=True) or {}
    codigo = str(datos.get("codigo", ""))
    if re.fullmatch(r"\d{6}", codigo) is None:
        return {"success": False, "message": "El código debe tener 6 dígitos."}
    error = validar_codigo(verificacion, codigo)
    if error is not None:
        # Si hay que pedir otro código, el diálogo regresa al paso 1
        return {"success": False, "message": error, "reiniciar": session.get("verificacion_id") is None}
    session["perfil_verificado_accion"] = accion
    session["perfil_verificado_hora"] = datetime.now().isoformat()
    # Para la contraseña, el siguiente paso es la página para escribir la nueva
    siguiente = url_for(PERFIL_ACCIONES[accion]["ruta"]) if accion in PERFIL_ACCIONES else ""
    return {"success": True, "message": "Identidad confirmada.", "siguiente": siguiente}


@usuarios.route("/perfil/telefono/guardar_json", methods=["POST"])
@login_required
def perfil_telefono_guardar_json():
    """Diálogo cambiar teléfono, paso 3: guardar el teléfono nuevo"""
    if not perfil_verificado("telefono"):
        return {"success": False, "message": "Primero confirme su identidad con el código de verificación.", "reiniciar": True}
    usuario = Usuario.query.get(current_user.id)
    datos = request.get_json(silent=True) or {}
    telefono = safe_telefono(str(datos.get("telefono", "")))
    confirmar = str(datos.get("confirmar", "")).strip()
    if telefono == "":
        return {"success": False, "message": "El teléfono debe tener 10 dígitos."}
    if telefono != confirmar:
        return {"success": False, "message": "Los teléfonos no coinciden."}
    if telefono == usuario.telefono:
        return {"success": False, "message": "Es el mismo teléfono que ya tiene."}
    usuario.telefono = telefono
    usuario.save()
    limpiar_perfil_verificacion()
    registrar_bitacora_perfil(f"Cambió su teléfono {usuario.email}")
    return {"success": True, "message": "Su teléfono se actualizó correctamente.", "telefono": telefono}


@usuarios.route("/perfil/verificacion/cancelar")
@login_required
def perfil_verificacion_cancelar():
    """Cancelar el cambio y regresar al perfil"""
    limpiar_perfil_verificacion()
    return redirect(url_for("usuarios.profile"))


@usuarios.route("/usuarios/datatable_json", methods=["GET", "POST"])
@login_required
@permission_required(MODULO, Permiso.VER)
def datatable_json():
    """DataTable JSON para listado de Usuarios"""
    # Tomar parámetros de Datatables
    draw, start, rows_per_page = get_datatable_parameters()
    # Consultar
    consulta = Usuario.query
    # Primero filtrar por columnas propias
    if "estatus" in request.form:
        consulta = consulta.filter(Usuario.estatus == request.form["estatus"])
    else:
        consulta = consulta.filter(Usuario.estatus == "A")
    # Filtrar por autoridad_id u autoridad_id_diferente_a
    if "autoridad_id" in request.form:
        consulta = consulta.filter(Usuario.autoridad_id == request.form["autoridad_id"])
    elif "autoridad_id_diferente_a" in request.form:
        consulta = consulta.filter(Usuario.autoridad_id != request.form["autoridad_id_diferente_a"])
    # Filtrar por las columnas de texto de Usuario
    if "nombres" in request.form:
        consulta = consulta.filter(Usuario.nombres.contains(safe_string(request.form["nombres"])))
    if "apellido_paterno" in request.form:
        consulta = consulta.filter(Usuario.apellido_paterno.contains(safe_string(request.form["apellido_paterno"])))
    if "apellido_materno" in request.form:
        consulta = consulta.filter(Usuario.apellido_materno.contains(safe_string(request.form["apellido_materno"])))
    if "puesto" in request.form:
        consulta = consulta.filter(Usuario.puesto.contains(safe_string(request.form["puesto"])))
    if "email" in request.form:
        consulta = consulta.filter(Usuario.email.contains(safe_email(request.form["email"], search_fragment=True)))
    # Ordenar y paginar
    registros = consulta.order_by(Usuario.email).offset(start).limit(rows_per_page).all()
    total = consulta.count()
    # Elaborar datos para DataTable
    data = []
    for resultado in registros:
        data.append(
            {
                "detalle": {
                    "email": resultado.email,
                    "url": url_for("usuarios.detail", usuario_id=resultado.id),
                },
                "nombre": resultado.nombre,
                "puesto": resultado.puesto,
                "autoridad": {
                    "clave": resultado.autoridad.clave,
                    "url": (
                        url_for("autoridades.detail", autoridad_id=resultado.autoridad_id)
                        if current_user.can_view("AUTORIDADES")
                        else ""
                    ),
                },
            }
        )
    # Entregar JSON
    return output_datatable_json(draw, total, data)


@usuarios.route("/usuarios/api_key_request/<usuario_id>", methods=["GET", "POST"])
@login_required
@permission_required(MODULO, Permiso.ADMINISTRAR)
def request_api_key_json(usuario_id):
    """Solicitar API Key"""

    # Consultar usuario
    usuario_id = safe_uuid(usuario_id)
    if usuario_id == "":
        abort(400)
    usuario = Usuario.query.get_or_404(usuario_id)
    if usuario.estatus != "A":
        return {
            "success": False,
            "message": "El usuario no está activo",
            "api_key": "",
            "api_key_expiracion": "",
        }

    # Si se recibe action con clean, se va a limpiar
    if "action" in request.form and request.form["action"] == "clean":
        usuario.api_key = ""
        usuario.api_key_expiracion = datetime(year=2000, month=1, day=1)
        usuario.save()
        mensaje = f"La API Key de {usuario.email} fue eliminada"
        bitacora = Bitacora(
            modulo=Modulo.query.filter_by(nombre=MODULO).first(),
            usuario=current_user,
            descripcion=mensaje,
            url=url_for("usuarios.detail", usuario_id=usuario.id),
        )
        bitacora.save()
        return {
            "success": True,
            "message": mensaje,
            "api_key": usuario.api_key,
            "api_key_expiracion": usuario.api_key_expiracion,
        }

    # Si se recibe action con new, se va a crear una nueva
    if "action" in request.form and request.form["action"] == "new":
        if "days" in request.form:
            days = int(request.form["days"])
        else:
            days = 90
        usuario.api_key = generate_api_key(usuario.email)
        usuario.api_key_expiracion = datetime.now() + timedelta(days=days)
        usuario.save()
        mensaje = f"Nueva API Key para {usuario.email} con expiración en {days} días"
        bitacora = Bitacora(
            modulo=Modulo.query.filter_by(nombre=MODULO).first(),
            usuario=current_user,
            descripcion=mensaje,
            url=url_for("usuarios.detail", usuario_id=usuario.id),
        )
        bitacora.save()
        return {
            "success": True,
            "message": mensaje,
            "api_key": usuario.api_key,
            "api_key_expiracion": usuario.api_key_expiracion,
        }

    # Si no se recibe nada, entregar la actual
    return {
        "success": True,
        "message": "Se ha entregado la API Key a la interfaz",
        "api_key": usuario.api_key,
        "api_key_expiracion": usuario.api_key_expiracion,
    }


@usuarios.route("/usuarios")
@login_required
@permission_required(MODULO, Permiso.VER)
def list_active():
    """Listado de Usuarios activos"""
    return render_template(
        "usuarios/list.jinja2",
        filtros=json.dumps({"estatus": "A"}),
        titulo="Usuarios",
        estatus="A",
    )


@usuarios.route("/usuarios/inactivos")
@login_required
@permission_required(MODULO, Permiso.ADMINISTRAR)
def list_inactive():
    """Listado de Usuarios inactivos"""
    return render_template(
        "usuarios/list.jinja2",
        filtros=json.dumps({"estatus": "B"}),
        titulo="Usuarios inactivos",
        estatus="B",
    )


@usuarios.route("/usuarios/<usuario_id>")
@login_required
@permission_required(MODULO, Permiso.VER)
def detail(usuario_id):
    """Detalle de un Usuario"""
    usuario_id = safe_uuid(usuario_id)
    if usuario_id == "":
        abort(400)
    usuario = Usuario.query.get_or_404(usuario_id)
    return render_template("usuarios/detail.jinja2", usuario=usuario)


@usuarios.route("/usuarios/api_key/<usuario_id>")
@login_required
@permission_required(MODULO, Permiso.ADMINISTRAR)
def view_api_key(usuario_id):
    """Ver API Key"""

    # Consultar usuario
    usuario_id = safe_uuid(usuario_id)
    if usuario_id == "":
        abort(400)
    usuario = Usuario.query.get_or_404(usuario_id)
    if usuario.estatus != "A":
        flash("El usuario no está activo.", "warning")
        return redirect(url_for("usuarios.detail", usuario_id=usuario.id))

    # Juntar los permisos por nivel
    permisos_por_nivel = {1: [], 2: [], 3: [], 4: []}
    for etiqueta, nivel in usuario.permisos.items():
        permisos_por_nivel[nivel].append(etiqueta)

    # Mostrar api_key.jinja2
    return render_template(
        "usuarios/api_key.jinja2",
        usuario=usuario,
        permisos_en_nivel_1=sorted(permisos_por_nivel[1]),
        permisos_en_nivel_2=sorted(permisos_por_nivel[2]),
        permisos_en_nivel_3=sorted(permisos_por_nivel[3]),
        permisos_en_nivel_4=sorted(permisos_por_nivel[4]),
    )


@usuarios.route("/usuarios/nuevo", methods=["GET", "POST"])
@login_required
@permission_required(MODULO, Permiso.CREAR)
def new():
    """Nuevo Usuario"""
    form = UsuarioForm()
    if form.validate_on_submit():
        # Validaciones
        es_valido = True
        # Validar que el email no se repita
        email = safe_email(form.email.data)
        if Usuario.query.filter_by(email=email).first():
            flash("El e-mail ya está en uso. Debe de ser único.", "warning")
            es_valido = False
        # Validar el teléfono, es opcional
        telefono = None
        if form.telefono.data:
            telefono = safe_telefono(form.telefono.data)
            if telefono == "":
                flash("El teléfono debe tener 10 dígitos.", "warning")
                es_valido = False
        # Guardar
        if es_valido:
            usuario = Usuario(
                autoridad_id=form.autoridad.data,
                email=email,
                nombres=safe_string(form.nombres.data, save_enie=True),
                apellido_paterno=safe_string(form.apellido_paterno.data, save_enie=True),
                apellido_materno=safe_string(form.apellido_materno.data, save_enie=True),
                puesto=safe_string(form.puesto.data),
                telefono=telefono,
                api_key="",
                api_key_expiracion=datetime(year=2000, month=1, day=1, hour=0, minute=0, second=0),
                contrasena=generar_contrasena(),
            )
            usuario.save()
            bitacora = Bitacora(
                modulo=Modulo.query.filter_by(nombre=MODULO).first(),
                usuario=current_user,
                descripcion=safe_message(f"Nuevo Usuario {usuario.email}"),
                url=url_for("usuarios.detail", usuario_id=usuario.id),
            )
            bitacora.save()
            flash(bitacora.descripcion, "success")
            return redirect(bitacora.url)
    # Consultar el distrito NO DEFINIDO
    distrito_no_definido_id = None
    distrito_no_definido = Distrito.query.filter_by(clave="ND").first()
    if distrito_no_definido:
        distrito_no_definido_id = str(distrito_no_definido.id)  # Es un SelectField
    # Consultar la autoridad NO DEFINIDO
    autoridad_no_definida_id = None
    autoridad_no_definida = Autoridad.query.filter_by(clave="ND").first()
    if autoridad_no_definida:
        autoridad_no_definida_id = str(autoridad_no_definida.id)  # Es un SelectField
    # Entregar formulario
    return render_template(
        "usuarios/new.jinja2",
        form=form,
        distrito_no_definido_id=distrito_no_definido_id,
        autoridad_no_definida_id=autoridad_no_definida_id,
    )


@usuarios.route("/usuarios/edicion/<usuario_id>", methods=["GET", "POST"])
@login_required
@permission_required(MODULO, Permiso.MODIFICAR)
def edit(usuario_id):
    """Editar Usuario"""
    usuario_id = safe_uuid(usuario_id)
    if usuario_id == "":
        abort(400)
    usuario = Usuario.query.get_or_404(usuario_id)
    form = UsuarioForm()
    if form.validate_on_submit():
        es_valido = True
        # Si cambia el e-mail verificar que no este en uso
        email = safe_email(form.email.data)
        if usuario.email != email:
            usuario_existente = Usuario.query.filter_by(email=email).first()
            if usuario_existente and usuario_existente.id != usuario.id:
                es_valido = False
                flash("La e-mail ya está en uso. Debe de ser único.", "warning")
        # Validar el teléfono, es opcional
        telefono = None
        if form.telefono.data:
            telefono = safe_telefono(form.telefono.data)
            if telefono == "":
                flash("El teléfono debe tener 10 dígitos.", "warning")
                es_valido = False
        # Si es valido actualizar
        if es_valido:
            usuario.autoridad_id = form.autoridad.data  # Combo select distrito-autoridad
            usuario.email = email
            usuario.nombres = safe_string(form.nombres.data, save_enie=True)
            usuario.apellido_paterno = safe_string(form.apellido_paterno.data, save_enie=True)
            usuario.apellido_materno = safe_string(form.apellido_materno.data, save_enie=True)
            usuario.puesto = safe_string(form.puesto.data)
            usuario.telefono = telefono
            usuario.save()
            bitacora = Bitacora(
                modulo=Modulo.query.filter_by(nombre=MODULO).first(),
                usuario=current_user,
                descripcion=safe_message(f"Editado Usuario {usuario.email}"),
                url=url_for("usuarios.detail", usuario_id=usuario.id),
            )
            bitacora.save()
            flash(bitacora.descripcion, "success")
            return redirect(bitacora.url)
    # No es necesario pasar autoridad_id porque se va a tomar de usuario con JS
    # Tampoco es necesario pasar oficina_id porque se va a tomar de usuario con JS
    form.email.data = usuario.email
    form.nombres.data = usuario.nombres
    form.apellido_paterno.data = usuario.apellido_paterno
    form.apellido_materno.data = usuario.apellido_materno
    form.puesto.data = usuario.puesto
    form.telefono.data = usuario.telefono
    return render_template("usuarios/edit.jinja2", form=form, usuario=usuario)


@usuarios.route("/usuarios/eliminar/<usuario_id>")
@login_required
@permission_required(MODULO, Permiso.ADMINISTRAR)
def delete(usuario_id):
    """Eliminar Usuario"""
    usuario_id = safe_uuid(usuario_id)
    if usuario_id == "":
        abort(400)
    usuario = Usuario.query.get_or_404(usuario_id)
    if usuario.estatus == "A":
        # Dar de baja al usuario
        usuario.delete()
        # Dar de baja los roles del usuario
        for usuario_rol in usuario.usuarios_roles:
            usuario_rol.delete()
        # Guardar en la bitacora
        bitacora = Bitacora(
            modulo=Modulo.query.filter_by(nombre=MODULO).first(),
            usuario=current_user,
            descripcion=safe_message(f"Eliminado Usuario {usuario.email}"),
            url=url_for("usuarios.detail", usuario_id=usuario.id),
        )
        bitacora.save()
        flash(bitacora.descripcion, "success")
    return redirect(url_for("usuarios.detail", usuario_id=usuario.id))


@usuarios.route("/usuarios/recuperar/<usuario_id>")
@login_required
@permission_required(MODULO, Permiso.ADMINISTRAR)
def recover(usuario_id):
    """Recuperar Usuario"""
    usuario_id = safe_uuid(usuario_id)
    if usuario_id == "":
        abort(400)
    usuario = Usuario.query.get_or_404(usuario_id)
    if usuario.estatus == "B":
        # Recuperar al usuario
        usuario.recover()
        # Recuperar los roles del usuario
        for usuario_rol in usuario.usuarios_roles:
            usuario_rol.recover()
        # Guardar en la bitacora
        bitacora = Bitacora(
            modulo=Modulo.query.filter_by(nombre=MODULO).first(),
            usuario=current_user,
            descripcion=safe_message(f"Recuperado Usuario {usuario.email}"),
            url=url_for("usuarios.detail", usuario_id=usuario.id),
        )
        bitacora.save()
        flash(bitacora.descripcion, "success")
    return redirect(url_for("usuarios.detail", usuario_id=usuario.id))


@usuarios.route("/usuarios/select_json", methods=["GET", "POST"])
def select_json():
    """Proporcionar el JSON de usuarios para elegir con un select"""
    consulta = Usuario.query.filter_by(estatus="A").order_by(Usuario.email)
    data = []
    for resultado in consulta.all():
        data.append({"id": str(resultado.id), "texto": resultado.email})
    return json.dumps(data)


@usuarios.route("/usuarios/select2_json", methods=["POST"])
def select2_json():
    """Proporcionar el JSON de usuarios para elegir con un Select2, puede recibir parte del email a buscar"""
    consulta = Usuario.query.filter(Usuario.estatus == "A")
    if "searchString" in request.form:
        email = safe_email(request.form["searchString"], search_fragment=True)
        if email != "":
            consulta = consulta.filter(Usuario.email.contains(email))
    data = []
    for usuario in consulta.order_by(Usuario.email).limit(10).all():
        data.append({"id": str(usuario.id), "text": f"{usuario.email}: {usuario.nombre}"})
    return {"results": data, "pagination": {"more": False}}
