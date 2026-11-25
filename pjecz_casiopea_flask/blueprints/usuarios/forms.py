"""
Usuarios, formularios
"""

from flask_wtf import FlaskForm
from wtforms import HiddenField, PasswordField, RadioField, SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional, Regexp

from ...lib.safe_string import CONTRASENA_REGEXP

CONTRASENA_MENSAJE = "De 8 a 48 caracteres con al menos una mayúscula, una minúscula y un número. No acentos, ni eñe."


class VerificacionMetodoForm(FlaskForm):
    """Formulario de verificación en dos pasos: elegir el método de envío del código"""

    aut_tipo_envio = RadioField("Método de envío", coerce=int, validators=[DataRequired()])  # Opciones desde aut_tipos_envios
    enviar = SubmitField("Enviar código de verificación")


class VerificacionCodigoForm(FlaskForm):
    """Formulario de verificación en dos pasos: capturar el código de verificación"""

    codigo = StringField("Código", validators=[DataRequired(), Regexp(r"^\d{6}$", 0, "El código debe tener 6 dígitos.")])
    validar = SubmitField("Validar código")


class CambiarContrasenaForm(FlaskForm):
    """Formulario para cambiar la contraseña desde el perfil"""

    contrasena = PasswordField(
        "Contraseña nueva",
        validators=[DataRequired(), Length(8, 48), Regexp(CONTRASENA_REGEXP, 0, CONTRASENA_MENSAJE)],
    )
    confirmar = PasswordField(
        "Confirmar contraseña",
        validators=[DataRequired(), EqualTo("contrasena", "Las contraseñas no coinciden.")],
    )
    guardar = SubmitField("Guardar contraseña")


class AccesoForm(FlaskForm):
    """Formulario de acceso al sistema"""

    siguiente = HiddenField(default="")
    correo_electronico = StringField("Correo electrónico", validators=[DataRequired(), Length(8, 256)])
    contrasena = PasswordField(
        "Contraseña",
        validators=[DataRequired(), Length(8, 48), Regexp(CONTRASENA_REGEXP, 0, CONTRASENA_MENSAJE)],
    )
    ingresar = SubmitField("Ingresar")


class FirebaseForm(FlaskForm):
    """Formulario de acceso por Firebase"""

    siguiente = HiddenField(default="")
    identidad = StringField("Identidad", validators=[DataRequired()])
    token = StringField("Token", validators=[DataRequired()])
    ingresar = SubmitField("Ingresar")


class UsuarioForm(FlaskForm):
    """Formulario Usuario"""

    distrito = SelectField("Distrito", choices=None, validate_choice=False)  # Las opciones se agregan con JS
    autoridad = SelectField("Autoridad", choices=None, validate_choice=False)  # Las opciones se agregan con JS
    email = StringField("e-mail", validators=[DataRequired(), Email()])
    nombres = StringField("Nombres", validators=[DataRequired(), Length(max=256)])
    apellido_paterno = StringField("Apellido primero", validators=[DataRequired(), Length(max=256)])
    apellido_materno = StringField("Apellido segundo", validators=[Optional(), Length(max=256)])
    puesto = StringField("Puesto", validators=[Optional(), Length(max=256)])
    telefono = StringField("Telefono", validators=[Optional(), Length(max=20)])
    guardar = SubmitField("Guardar")
