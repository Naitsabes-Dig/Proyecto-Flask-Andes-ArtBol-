import json
import os
import psycopg2
import random
import re
import string
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, jsonify, render_template, request, redirect, url_for, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.sql import text
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")

# Configuración Flask-Mail
app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER")
app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT"))
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config['MAIL_USE_TLS'] = os.getenv("MAIL_USE_TLS") == "True"
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_DEFAULT_SENDER")

db = SQLAlchemy(app)
mail = Mail(app)

# Función para obtener la conexión a la base de datos
def get_db_connection():
    return psycopg2.connect(
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST"),
        client_encoding="UTF8"
    )
    
# Decorador para verificar si el usuario está autenticado
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario_id' not in session:
            flash('Por favor, inicia sesión primero.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Ruta principal
@app.route('/')
def home():
    return redirect(url_for('index'))

#Politicas de privacidad
@app.route('/politicas')
def politicas():
    return render_template('politicas.html')

# Ruta para cerrar sesión
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login') + '?logout=1')


@app.route('/index')    
def index():
    return render_template('index.html')

#Login de la pagina
@app.route('/login', methods=['GET', 'POST'])
def login():
    error_message = None
    if request.method == 'POST':
        correo = request.form['correo']
        contraseña = request.form['contraseña']
        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT * FROM Usuarios WHERE correo = %s", (correo,))
            user = cur.fetchone()

            if user and check_password_hash(user[3], contraseña):
                if user[7]:  # Si el usuario está verificado
                    session['usuario_id'] = user[0]
                    session['correo'] = correo  # Guardar el correo en la sesión
                    return redirect(url_for('dashboard'))
                else:
                    error_message = 'Debes verificar tu correo antes de iniciar sesión.'
            else:
                error_message = 'Correo o contraseña incorrectos.'

        except Exception as e:
            error_message = f'Error de conexión a la base de datos: {str(e)}'

        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    if request.args.get('logout'):
        flash('Has cerrado sesión exitosamente', 'success')

    return render_template('login.html', error_message=error_message)


# Ruta del dashboard protegida por el decorador login_required

@app.route('/dashboard')
def dashboard():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    usuario_id = session['usuario_id']
    conn = get_db_connection()
    cur = conn.cursor()

    # Obtener el nombre del usuario de la base de datos
    cur.execute('SELECT nombre, rol_id FROM usuarios WHERE usuario_id = %s', (usuario_id,))
    usuario = cur.fetchone()

    # Obtener los productos más vendidos (stock más bajo)
    cur.execute('''
        SELECT nombre, stock, precio
        FROM productos
        ORDER BY stock ASC
        LIMIT 25;
    ''')
    productos_mas_vendidos = cur.fetchall()

    # Obtener los productos menos vendidos (stock más alto)
    cur.execute('''
        SELECT nombre, stock, precio
        FROM productos
        ORDER BY stock DESC
        LIMIT 17;
    ''')
    productos_menos_vendidos = cur.fetchall()

    # Obtener las comunidades con más usuarios
    cur.execute('''
        SELECT c.nombre, COUNT(u.usuario_id) AS cantidad
        FROM comunidades c
        LEFT JOIN usuarios u ON c.comunidad_id = u.comunidad_id
        GROUP BY c.nombre
        ORDER BY cantidad DESC;
    ''')
    comunidades_mas_usuarios = cur.fetchall()

    cur.close()
    conn.close()
    
    # Verificar si ha pasado una hora desde la última verificación del stock
    last_check = session.get('last_stock_check')
    if not last_check or datetime.now() - datetime.fromisoformat(last_check) > timedelta(hours=1):
        verificar_stock_bajo()  # Llamar a la función de verificación
        session['last_stock_check'] = datetime.now().isoformat() 

    nombre = usuario[0] if usuario else 'Cliente'
    rol_id = usuario[1] if usuario else None

    # Verificar roles
    is_admin = session.get('correo') == 'dignosebastiangutierrezoropeza@gmail.com'
    is_delivery = (rol_id == 4)
    is_cliente = (rol_id == 3)
    is_artesano = (rol_id == 2)

    # Preparar datos para los gráficos
    data = {
        'productos_mas_vendidos': [{'nombre': p[0], 'stock': p[1], 'precio': float(p[2])} for p in productos_mas_vendidos],
        'productos_menos_vendidos': [{'nombre': p[0], 'stock': p[1], 'precio': float(p[2])} for p in productos_menos_vendidos],
        'comunidades_mas_usuarios': [{'nombre': c[0], 'cantidad': c[1]} for c in comunidades_mas_usuarios],
    }

    return render_template(
        'dashboard.html',
        nombre=nombre,
        is_admin=is_admin,
        is_delivery=is_delivery,
        is_cliente=is_cliente,
        is_artesano=is_artesano,
        data=json.dumps(data)  # Convertimos los datos a JSON
    )


@app.route('/registro', methods=['GET', 'POST'])
def registro():
    # Cargar roles y comunidades antes de la validación
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT rol_id, nombre FROM roles")  # Asumiendo que tienes una tabla 'roles'
    roles = cur.fetchall()

    cur.execute("SELECT comunidad_id, nombre FROM comunidades")  # Asumiendo que tienes una tabla 'comunidades'
    comunidades = cur.fetchall()

    cur.close()
    conn.close()

    if request.method == 'POST':
        nombre = request.form['nombre']
        correo = request.form['correo']
        contraseña = request.form['contraseña']
        telefono = request.form['telefono']
        rol_id = request.form['rol_id']
        comunidad_id = request.form['comunidad_id']

        # Validaciones
        if not nombre or not correo or not contraseña or not telefono or not rol_id or not comunidad_id:
            error_message = 'Todos los campos son obligatorios.'
            return render_template('registro.html', roles=roles, comunidades=comunidades, error_message=error_message)

        if not re.match(r"[^@]+@[^@]+\.[^@]+", correo):
            error_message = 'Correo inválido.'
            return render_template('registro.html', roles=roles, comunidades=comunidades, error_message=error_message)

        if not telefono.isdigit():
            error_message = 'El teléfono debe contener solo números.'
            return render_template('registro.html', roles=roles, comunidades=comunidades, error_message=error_message)

        if not validar_contraseña(contraseña):
            error_message = 'La contraseña debe tener al menos 8 caracteres, incluyendo una mayúscula, una minúscula, un número y un símbolo especial.'
            return render_template('registro.html', roles=roles, comunidades=comunidades, error_message=error_message)

        # Verificar si el correo ya está registrado
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM usuarios WHERE correo = %s", (correo,))
        existing_user = cur.fetchone()

        if existing_user:
            error_message = 'Este correo ya está registrado. Por favor, inicia sesión o usa otro correo.'
            cur.close()
            conn.close()
            return render_template('registro.html', roles=roles, comunidades=comunidades, error_message=error_message)

        # Si el correo no existe, proceder con el registro
        contraseña = generate_password_hash(contraseña)
        codigo_verificacion = generar_codigo()

        try:
            cur.execute(
                "INSERT INTO usuarios (nombre, correo, contraseña, telefono, rol_id, comunidad_id, codigo_verificacion, verificado) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)", 
                (nombre, correo, contraseña, telefono, rol_id, comunidad_id, codigo_verificacion, False)
            )
            conn.commit()

            # Enviar el correo de verificación
            msg = Message('Verificación de cuenta', sender=app.config['MAIL_USERNAME'], recipients=[correo])
            msg.body = f'Tu código de verificación es: {codigo_verificacion}'
            mail.send(msg)

            session['correo_verificacion'] = correo  # Guardar correo en la sesión
            return redirect(url_for('verificar_codigo_registro'))

        except Exception as e:
            error_message = f'Error al registrar el usuario: {str(e)}'
            conn.rollback()

        finally:
            cur.close()
            conn.close()

        return render_template('registro.html', roles=roles, comunidades=comunidades, error_message=error_message)

    return render_template('registro.html', roles=roles, comunidades=comunidades)

# Verificar el código de recuperación
@app.route('/verificar_codigo_recuperacion', methods=['GET', 'POST'])
def verificar_codigo_recuperacion():
    if request.method == 'POST':
        codigo = request.form['codigo']

        if codigo == session.get('codigo'):
            flash('Código verificado correctamente', 'success')
            return redirect(url_for('cambiar_contraseña'))
        else:
            flash('Código incorrecto', 'danger')

    return render_template('verificar_codigo_recuperacion.html')

#Verificar el código de registro
@app.route('/verificar_codigo_registro', methods=['GET', 'POST'])
def verificar_codigo_registro():   
        correo = session.get('correo_verificacion')
        if request.method == 'POST':
            codigo_ingresado = request.form['codigo']
        # Verificar el código en la base de datos
            conn = None
            cur = None
            try:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("SELECT codigo_verificacion FROM usuarios WHERE correo = %s", (correo,))
                codigo_correcto = cur.fetchone()[0]

                if codigo_correcto == codigo_ingresado:
                # Código verificado, actualizar usuario como verificado
                    cur.execute("UPDATE usuarios SET verificado = TRUE WHERE correo = %s", (correo,))
                    conn.commit()
                    flash('Cuenta verificada correctamente.', 'success')
                    return redirect(url_for('login'))
                else:
                    flash('El código ingresado es incorrecto.', 'danger')

            except Exception as e:
                flash(f'Error al verificar el código: {str(e)}', 'danger')

            finally:
                if cur:
                    cur.close()
                if conn:
                    conn.close()
        return render_template('verificar_codigo_registro.html')

# Función para validar la contraseña
def validar_contraseña(contraseña):
    if len(contraseña) < 8:
        return False
    if not any(char.isdigit() for char in contraseña):
        return False
    if not any(char.isupper() for char in contraseña):
        return False
    if not any(char.islower() for char in contraseña):
        return False
    if not any(char in "!@#$%^&*()_+" for char in contraseña):
        return False
    return True

# Ruta para recuperación de contraseña
@app.route('/recuperar', methods=['GET', 'POST'])
def recuperar():
    if request.method == 'POST':
        correo = request.form['correo']
        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT * FROM usuarios WHERE correo = %s", (correo,))
            user = cur.fetchone()

            if user:
                codigo = generar_codigo()
                session['codigo'] = codigo
                session['usuario_id'] = user[0]

                msg = Message('Código de recuperación', sender=app.config['MAIL_USERNAME'], recipients=[correo])
                msg.html = render_template('correo_codigo.html', codigo=codigo)
                mail.send(msg)
                
                flash('Código de recuperación enviado a tu correo.', 'success')
                print('Se envio el correo pero no se redirige')
                return redirect(url_for('verificar_codigo_recuperacion'))

            else:
                flash('El correo no está registrado.', 'danger')

        except Exception as e:
            flash(f'Error al enviar el código de recuperación: {str(e)}', 'danger')

        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()
    
    return render_template('recuperar.html')

# Ruta para cambiar la contraseña
@app.route('/cambiar_contraseña', methods=['GET', 'POST'])
def cambiar_contraseña():
    if request.method == 'POST':
        nueva_contraseña = request.form['nueva_contraseña']
        usuario_id = session.get('usuario_id')

        nueva_contraseña_hash = generate_password_hash(nueva_contraseña)

        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("UPDATE Usuarios SET contraseña = %s WHERE usuario_id = %s", (nueva_contraseña_hash, usuario_id))
            conn.commit()

            flash('Contraseña cambiada con éxito', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            flash(f'Error al cambiar la contraseña: {str(e)}', 'danger')

        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    return render_template('cambiar_contraseña.html')

# Ruta oara nueva contraseña
@app.route('/nueva_contraseña', methods=['GET', 'POST'])
def nueva_contraseña():
    if request.method == 'POST':
        nueva_contraseña = request.form['nueva_contraseña']
        confirmacion_contraseña = request.form['confirmacion_contraseña']

        if nueva_contraseña != confirmacion_contraseña:
            flash('Las contraseñas no coinciden', 'danger')
            return render_template('nueva_contraseña.html')

        if not validar_contraseña(nueva_contraseña):
            flash('La nueva contraseña no cumple con los requisitos de seguridad', 'danger')
            return render_template('nueva_contraseña.html')

        # Encriptar y actualizar la contraseña
        nueva_contraseña_hash = generate_password_hash(nueva_contraseña)

        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("UPDATE Usuarios SET contraseña = %s WHERE id = %s", (nueva_contraseña_hash, session['usuario_id']))
            conn.commit()

            flash('Contraseña actualizada correctamente', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            flash(f'Error al actualizar la contraseña: {str(e)}', 'danger')

        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    return render_template('nueva_contraseña.html')
# Función para generar códigos de verificación aleatorios
def generar_codigo(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

#perfil del usuario
@app.route('/perfil', methods=['GET', 'POST'])
@login_required  # Este decorador verifica si el usuario está autenticado
def perfil():
    usuario_id = session['usuario_id']
    conn = None
    cur = None
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Obtener información del usuario
        cur.execute("SELECT nombre, correo, telefono, rol_id, comunidad_id FROM usuarios WHERE usuario_id = %s", (usuario_id,))
        usuario = cur.fetchone()

        # Obtener la lista de roles
        cur.execute("SELECT rol_id, nombre FROM roles")
        roles = cur.fetchall()

        # Obtener la lista de comunidades
        cur.execute("SELECT comunidad_id, nombre FROM comunidades")
        comunidades = cur.fetchall()

        if request.method == 'POST':
            # Datos enviados para actualizar el perfil
            nombre = request.form['nombre']
            correo = request.form['correo']
            telefono = request.form['telefono']
            rol_id = request.form['rol_id']
            comunidad_id = request.form['comunidad_id']

            # Validaciones básicas
            if not nombre or not correo or not telefono or not rol_id or not comunidad_id:
                flash('Todos los campos son obligatorios.', 'danger')
                return redirect(url_for('perfil'))

            if not re.match(r"[^@]+@[^@]+\.[^@]+", correo):
                flash('Correo inválido', 'danger')
                return redirect(url_for('perfil'))

            if not telefono.isdigit():
                flash('El teléfono debe contener solo números', 'danger')
                return redirect(url_for('perfil'))

            # Actualizar datos del usuario en la base de datos
            cur.execute(
                "UPDATE usuarios SET nombre = %s, correo = %s, telefono = %s, rol_id = %s, comunidad_id = %s WHERE usuario_id = %s",
                (nombre, correo, telefono, rol_id, comunidad_id, usuario_id)
            )
            conn.commit()
            flash('Perfil actualizado correctamente', 'success')

    except Exception as e:
        flash(f'Error al cargar el perfil: {str(e)}', 'danger')
        if conn:
            conn.rollback()
    
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    # Renderizar plantilla con datos del usuario, roles y comunidades
    return render_template('perfil.html', usuario=usuario, roles=roles, comunidades=comunidades)

# Ruta para la página de administración
@app.route('/admin')
def admin():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    correo_usuario = session.get('correo')
    if correo_usuario != 'dignosebastiangutierrezoropeza@gmail.com':
        return "No tienes permiso para acceder a esta página.", 403

    conn = get_db_connection()
    cur = conn.cursor()

    # Obtener usuarios que están pendientes
    cur.execute("SELECT usuario_id, nombre, correo FROM usuarios WHERE rol_id= 2 AND estado_aprobacion = 0 ORDER BY usuario_id ASC")
    usuarios = cur.fetchall()

    # Obtener usuarios aceptados
    cur.execute("SELECT usuario_id, nombre, correo FROM usuarios WHERE rol_id= 2 AND estado_aprobacion = 1 ORDER BY usuario_id ASC")
    aceptados = cur.fetchall()

    # Obtener usuarios cancelados
    cur.execute("SELECT usuario_id, nombre, correo FROM usuarios WHERE rol_id= 2 AND estado_aprobacion = 2 ORDER BY usuario_id ASC")
    cancelados = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('admin.html', usuarios=usuarios, aceptados=aceptados, cancelados=cancelados)

#ruta de Acerca de Nostros
@app.route('/acerca_de_nosotros')
def acerca_de_nosotros():
    return render_template('acerca_de_nosotros.html')

#Ruta Historial de envios
@app.route('/historial_envios')
def historial_envios():
    # Obtener el ID de usuario desde la sesión
    user_id = session.get('usuario_id')
    conn = get_db_connection()
    cur = conn.cursor()

    # Obtener envíos que llegaron para el usuario
    cur.execute("""
        SELECT envio_id, ubicacion, numero_contacto, tiempo_estimado, fecha_envio, estado, puntuacion, resena
        FROM envios
        WHERE estado = 'Llegó' AND usuario_id = %s
    """, (user_id,))
    envios_llego = cur.fetchall()

    # Obtener envíos que no llegaron para el usuario
    cur.execute("""
        SELECT envio_id, ubicacion, numero_contacto, tiempo_estimado, fecha_envio, estado, puntuacion, resena
        FROM envios
        WHERE estado = 'No Llegó' AND usuario_id = %s
    """, (user_id,))
    envios_no_llego = cur.fetchall()

    # Obtener envíos pendientes para el usuario
    cur.execute("""
        SELECT envio_id, ubicacion, numero_contacto, tiempo_estimado, fecha_envio, estado, puntuacion, resena
        FROM envios
        WHERE estado = 'Pendiente' AND usuario_id = %s
    """, (user_id,))
    envios_pendientes = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('historial_envios.html', 
                           envios_llego=envios_llego, 
                           envios_no_llego=envios_no_llego, 
                           envios_pendientes=envios_pendientes)

@app.route('/actualizar_estado_envios', methods=['POST'])
def actualizar_estado_envios():
    data = request.get_json()
    envio_id = data.get('envioId')
    estado = data.get('estado')
    puntuacion = data.get('puntuacion')
    resena = data.get('resena')

    try:
        # Validar que envio_id y puntuacion sean enteros
        envio_id = int(envio_id)
        puntuacion = int(puntuacion)

        conn = get_db_connection()
        cur = conn.cursor()

        # Actualizar estado, puntuación y reseña en la base de datos
        cur.execute("""
            UPDATE envios
            SET estado = %s, fecha_entrega = NOW(), puntuacion = %s, resena = %s
            WHERE envio_id = %s
        """, (estado, puntuacion, resena, envio_id))
        
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"message": "Estado y reseña actualizados correctamente."})

    except ValueError:
        return jsonify({"error": "Datos inválidos."}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500
      
@app.route('/actualizar_estado_envios', methods=['POST'])
def actualizar_estado_envios_alternativos():
    data = request.get_json()
    envio_id, nuevo_estado = list(data.items())[0]  # Obtener el ID de envío y el nuevo estado

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("UPDATE Deliverys SET estado = %s, fecha_entrega = %s WHERE delivery_id = %s",
                    (nuevo_estado, datetime.now(), envio_id))
        conn.commit()
        return jsonify({"message": "Estado actualizado con éxito."})
    except Exception as e:
        conn.rollback()
        return jsonify({"error": f"Error al actualizar el estado: {e}"})
    finally:
        cur.close()
        conn.close()
    

@app.route('/agregar_producto', methods=['GET', 'POST'])
def agregar_producto():
    if 'usuario_id' not in session:
        flash('Por favor, inicia sesión primero.', 'warning')
        return redirect(url_for('login'))

    usuario_id = session['usuario_id']
    conn = get_db_connection()
    cur = conn.cursor()

    # Verificar si el usuario es vendedor
    cur.execute("""
        SELECT vendedor_id FROM vendedores WHERE usuario_id = %s
    """, (usuario_id,))
    vendedor = cur.fetchone()

    if not vendedor:
        return "No tienes un perfil de vendedor para agregar productos.", 403

    vendedor_id = vendedor[0]

    if request.method == 'POST':
        # Agregar producto
        if 'nombre' in request.form:
            nombre = request.form['nombre']
            precio = request.form['precio']
            descripcion = request.form['descripcion']
            categoria_id = request.form['categoria_id']
            imagen_url = request.form['imagen_url']
            dimension = request.form['dimension']
            color = request.form['color']
            stock = request.form['stock']

            imagen1 = request.files['imagen1']
            imagen2 = request.files['imagen2']

            if imagen1 and imagen2:
                imagen1_filename = os.path.join(app.config['UPLOAD_FOLDER'], imagen1.filename)
                imagen2_filename = os.path.join(app.config['UPLOAD_FOLDER'], imagen2.filename)
                imagen1.save(imagen1_filename)
                imagen2.save(imagen2_filename)

                cur.execute("""
                    INSERT INTO productos (nombre, precio, descripcion, imagen_url, categoria_id, dimension, color, vendedor_id, stock)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (nombre, precio, descripcion, imagen_url, categoria_id, dimension, color, vendedor_id, stock))
                conn.commit()
                flash('Producto agregado exitosamente.', 'success')
            else:
                flash("Las imágenes no se subieron correctamente.", 'error')

        # Actualizar stock
        elif 'producto_id' in request.form:
            producto_id = request.form['producto_id']
            nuevo_stock = int(request.form['nuevo_stock'])
            cur.execute("""
                UPDATE productos
                SET stock = stock + %s
                WHERE producto_id = %s AND vendedor_id = %s
            """, (nuevo_stock, producto_id, vendedor_id))
            conn.commit()
            flash('Stock actualizado exitosamente.', 'success')

    # Obtener categorías para el formulario
    cur.execute("SELECT categoria_id, nombre FROM categorias")
    categorias = cur.fetchall()

    # Obtener productos del vendedor actual
    cur.execute("""
        SELECT producto_id, nombre, precio, descripcion, stock
        FROM productos
        WHERE vendedor_id = %s
    """, (vendedor_id,))
    productos = cur.fetchall()

    conn.close()
    return render_template('agregar_producto.html', categorias=categorias, productos=productos, usuario_rol='Vendedor')

@app.route('/aceptar_admin/<int:usuario_id>', methods=['POST'])
def aceptar_admin(usuario_id):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("UPDATE usuarios SET estado_aprobacion = 1 WHERE usuario_id = %s", (usuario_id,))
    conn.commit()

    cur.close()
    conn.close()

    return redirect(url_for('admin'))

@app.route('/cancelar_admin/<int:usuario_id>', methods=['POST'])
def cancelar_admin(usuario_id):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("UPDATE usuarios SET estado_aprobacion = 2 WHERE usuario_id = %s", (usuario_id,))
    conn.commit()

    cur.close()
    conn.close()

    return redirect(url_for('admin'))

# Definir modelos para las tablas según los archivos CSV (ejemplo de Usuarios)
class Usuarios(db.Model):
    __tablename__ = 'usuarios'
    usuario_id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(255), nullable=False)
    correo = db.Column(db.String(255), unique=True, nullable=False)
    contraseña = db.Column(db.String(255), nullable=False)
    telefono = db.Column(db.String(20), nullable=True)
    fecha_registro = db.Column(db.DateTime, default=db.func.current_timestamp())
    rol_id = db.Column(db.Integer, db.ForeignKey('roles.rol_id'), nullable=True)
    comunidad_id = db.Column(db.Integer, db.ForeignKey('comunidades.comunidad_id'), nullable=True)

    # Relaciones
    rol = db.relationship('Roles', backref='usuarios', lazy=True)
    comunidad = db.relationship('Comunidades', backref='usuarios', lazy=True)

    def __repr__(self):
        return f"<Usuario {self.nombre}>"

class Roles(db.Model):
    __tablename__ = 'roles'
    rol_id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(50), nullable=False)
    descripcion = db.Column(db.Text)

class Envios(db.Model):
    __tablename__ = 'envios'
    envio_id = db.Column(db.Integer, primary_key=True)
    ubicacion = db.Column(db.String(255), nullable=False)
    numero_contacto = db.Column(db.String(20), nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    fecha_envio = db.Column(db.DateTime, default=db.func.current_timestamp())
    estado = db.Column(db.String(50), nullable=False)
    fecha_entrega = db.Column(db.DateTime, nullable=True)

    # Relaciones
    usuario = db.relationship('Usuarios', backref='envios', lazy=True)

class Categorias(db.Model):
    __tablename__ = 'categorias'
    categoria_id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f"<Categoria {self.nombre}>"

class Vendedores(db.Model):
    __tablename__ = 'vendedores'
    vendedor_id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.usuario_id'), nullable=False)
    nombre_tienda = db.Column(db.String(255), nullable=True)
    descripcion = db.Column(db.Text, nullable=True)
    contacto = db.Column(db.String(255), nullable=True)
    comunidad_id = db.Column(db.Integer, db.ForeignKey('comunidades.comunidad_id'), nullable=True)

    # Relaciones
    usuario = db.relationship('Usuarios', backref='vendedores', lazy=True)
    comunidad = db.relationship('Comunidades', backref='vendedores', lazy=True)

    def __repr__(self):
        return f"<Vendedor {self.nombre_tienda}>"

class Comunidades(db.Model):
    __tablename__ = 'comunidades'
    comunidad_id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(255), nullable=False)
    ubicacion = db.Column(db.String(255), nullable=True)
    descripcion = db.Column(db.Text)

    def __repr__(self):
        return f"<Comunidad {self.nombre}>"

class Producto(db.Model):
    __tablename__ = 'productos'

    producto_id = db.Column(db.Integer, primary_key=True)  # Clave primaria
    vendedor_id = db.Column(db.Integer, db.ForeignKey('vendedores.vendedor_id'), nullable=False)  # Relación con tabla vendedores
    categoria_id = db.Column(db.Integer, db.ForeignKey('categorias.categoria_id'), nullable=False)  # Relación con tabla categorías
    nombre = db.Column(db.String(100), nullable=False)  # Nombre del producto
    descripcion = db.Column(db.Text)  # Descripción del producto
    precio = db.Column(db.Numeric(10, 2), nullable=False)  # Precio (hasta 10 dígitos, 2 decimales)
    imagen_url = db.Column(db.String(255))  # URL de la imagen
    fecha_creacion = db.Column(db.DateTime, default=db.func.current_timestamp())  # Fecha de creación
    comunidad_id = db.Column(db.Integer, db.ForeignKey('comunidades.comunidad_id'))  # Relación con tabla comunidad
    dimension = db.Column(db.String(50))  # Dimensiones del producto
    color = db.Column(db.String(50))  # Color del producto
    stock = db.Column(db.Integer, nullable=False, default=0)  # Cantidad de productos en stock

    # Relaciones
    vendedor = db.relationship('Vendedores', backref='productos', lazy=True)
    categoria = db.relationship('Categorias', backref='productos', lazy=True)
    comunidad = db.relationship('Comunidades', backref='productos', lazy=True)

    def __repr__(self):
        return f"<Producto {self.nombre}>"

class Comentario(db.Model):
    __tablename__ = 'comentarios'
    comentario_id = db.Column(db.Integer, primary_key=True)
    producto_id = db.Column(db.Integer, db.ForeignKey('productos.producto_id'), nullable=False)
    usuario = db.Column(db.String(255), nullable=False)  # Nombre del usuario que comenta
    comentario = db.Column(db.Text, nullable=False)  # El comentario en sí
    fecha = db.Column(db.DateTime, default=db.func.current_timestamp())  # Fecha del comentario

    # Relaciones
    producto = db.relationship('Producto', backref='comentarios', lazy=True)

    def __repr__(self):
        return f"<Comentario {self.comentario[:50]}>"

class Reclamos(db.Model):
    __tablename__ = 'reclamos'
    reclamo_id = db.Column(db.Integer, primary_key=True)
    envio_id = db.Column(db.Integer, db.ForeignKey('envios.envio_id'), nullable=False)
    motivo = db.Column(db.Text, nullable=False)
    fecha = db.Column(db.DateTime, default=db.func.current_timestamp())
    estado = db.Column(db.String(50), nullable=False)

    # Relaciones
    envio = db.relationship('Envios', backref='reclamos', lazy=True)

@app.route('/catalogo')
def catalogo():
    productos = Producto.query.all()
    comentarios = {
        producto.producto_id: Comentario.query.filter_by(producto_id=producto.producto_id).all()
        for producto in productos
    }
    
    # Obtener el nombre del usuario de la sesión
    nombre_usuario = session.get('correo', 'Cliente')  # Cambia 'Cliente' por un valor por defecto si es necesario
    
    # Renderizar la plantilla con productos, comentarios y el nombre del usuario
    return render_template('catalogo.html', productos=productos, comentarios=comentarios, nombre=nombre_usuario)

@app.route('/agregar_comentario/<int:producto_id>', methods=['POST'])
def agregar_comentario(producto_id):
    comentario_texto = request.form['comentario']
    
    # Obtener el nombre del usuario de la sesión
    usuario = session.get('correo', 'Cliente')  # Cambia 'Cliente' por un valor por defecto si es necesario

    nuevo_comentario = Comentario(
        producto_id=producto_id,
        usuario=usuario,  # Ahora se utiliza el nombre de la sesión
        comentario=comentario_texto,
        fecha=datetime.now()  # Asegúrate de importar datetime si lo usas
    )
    
    db.session.add(nuevo_comentario)
    db.session.commit()
    
    return redirect(url_for('catalogo'))

# Ruta para la página de descarga
@app.route('/descargar')
def descargar():
    return render_template('download.html')

# Ruta para la descarga del APK
@app.route('/download')
def download_file():
    return send_from_directory('static/apks', 'ANDESARTBOL.apk', as_attachment=True)

#Configuracion de DELIVERYS
@app.route('/confirmar_delivery', methods=['GET', 'POST'])
@login_required
def confirmar_delivery():
    delivery_id = session.get('usuario_id')
    if not delivery_id:
        flash('Usuario no autenticado.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    cur = conn.cursor()

    # Obtener envíos pendientes para el usuario de delivery actual
    cur.execute("""
        SELECT envio_id, ubicacion, numero_contacto, tiempo_estimado
        FROM envios
        WHERE usuario_delivery_id = %s AND estado_delivery = 'pendiente'
    """, (delivery_id,))
    envios_pendientes = cur.fetchall()
    print(envios_pendientes)  # Para verificar los resultados

    if request.method == 'POST':
        print(request.form)  # Para verificar los datos del formulario
        envio_id = request.form.get('envio_id')
        tiempo_estimado = request.form.get('tiempo_estimado')  # Captura el tiempo estimado ingresado

        # Actualizar el estado a "Aceptado" y guardar el tiempo estimado
        cur.execute("""
            UPDATE envios
            SET estado_delivery = 'Aceptado', fecha_envio = NOW(), tiempo_estimado = %s
            WHERE envio_id = %s
        """, (tiempo_estimado, envio_id))
        conn.commit()

        flash('Pedido aceptado exitosamente con el tiempo estimado.', 'success')
        return redirect(url_for('confirmar_delivery'))

    cur.close()
    conn.close()

    return render_template('confirmar_delivery.html', envios=envios_pendientes)

@app.route('/pago', methods=['GET', 'POST'])
def pago():
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    usuario_id = session['usuario_id']
    conn = get_db_connection()
    cur = conn.cursor()

    # Datos del usuario
    cur.execute('SELECT nombre, correo FROM usuarios WHERE usuario_id = %s', (usuario_id,))
    usuario = cur.fetchone()
    cur.close()
    conn.close()

    nombre = usuario[0] if usuario else 'Cliente'
    correo_cliente = usuario[1] if usuario else None

    # Recuperar el carrito desde la sesión
    productos_carrito = session.get('productos_carrito', [])
    total = sum(item['price'] * item['cantidad'] for item in productos_carrito)

    if request.method == 'POST':
        metodo_pago = request.form.get('payment-method', 'Desconocido')
        productos = request.json.get('cart', [])
        usuario_id = request.json.get('usuario_id')

        # Calcular total
        total = sum(item['price'] * item['cantidad'] for item in productos)
        flash('Pago realizado con éxito.', 'success')
        return jsonify({'success': True, 'redirect': url_for('manejar_pedido')})

    return render_template(
        'pago.html',
        nombre=nombre,
        correo_cliente=correo_cliente,
        productos_carrito=productos_carrito,
        total=total
    )

@app.route('/realizar_pedido', methods=['POST'])
@login_required
def realizar_pedido():
    nombre = request.form.get('nombre', '').strip()
    correo = request.form.get('correo', '').strip()
    telefono = request.form.get('telefono', '').strip()
    producto_id = request.form.get('producto')
    cantidad = request.form.get('cantidad')

    # Validar que todos los campos estén completos
    if not nombre or not correo or not telefono or not producto_id or not cantidad:
        flash('Todos los campos son obligatorios.', 'danger')
        return redirect(url_for('pago'))  # Redirigir a la página de pago para corregir

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO pedidos (nombre, correo, telefono, producto_id, cantidad) VALUES (%s, %s, %s, %s, %s)",
                    (nombre, correo, telefono, producto_id, cantidad))
        conn.commit()
        flash('Pedido realizado con éxito.', 'success')
    except Exception as e:
        flash(f'Error al realizar el pedido: {str(e)}', 'danger')
        conn.rollback()
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('pago'))
 # Redirigir a la página de pago o confirmación# Redirigir a la página de pago o confirmación

# Ruta para mostrar información del envío actual
@app.route('/delivery')
@login_required
def delivery():
    usuario_id = session['usuario_id']
    conn = get_db_connection()
    cur = conn.cursor()

    # Obtener el envío más reciente del usuario actual
    cur.execute("""
        SELECT e.ubicacion, e.numero_contacto, u.nombre AS nombre_delivery, e.tiempo_estimado, e.confirmacion_entrega
        FROM envios e
        JOIN usuarios u ON e.usuario_delivery_id = u.usuario_id
        WHERE e.usuario_id = %s AND e.estado_delivery = 'Aceptado'
        ORDER BY e.envio_id DESC
        LIMIT 1
    """, (usuario_id,))

    envio = cur.fetchone()

    cur.close()
    conn.close()

    if envio:
        ubicacion, numero_contacto, nombre_delivery, tiempo_estimado, confirmacion_entrega = envio
    else:
        flash('No tienes envíos pendientes.', 'info')
        return redirect(url_for('dashboard'))

    return render_template(
        'delivery.html',
        ubicacion=ubicacion,
        numero_contacto=numero_contacto,
        nombre_delivery=nombre_delivery,
        tiempo_estimado=tiempo_estimado,
        confirmacion_entrega=confirmacion_entrega
    )

# Ruta para manejar el pedido
@app.route('/pedido', methods=['GET', 'POST']) 
@login_required
def manejar_pedido():
    if request.method == 'POST':
        ubicacion = request.form['ubicacion']
        numero_contacto = request.form['numero_contacto']

        usuario_id = session['usuario_id']

        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("SELECT usuario_id FROM usuarios WHERE rol_id = 4")
        delivery_users = cur.fetchall()

        if not delivery_users:
            flash('No hay usuarios de delivery disponibles.', 'danger')
            return redirect(url_for('pedido'))

        # Asignar un usuario de delivery al azar
        delivery_user = random.choice(delivery_users)[0]  # Obtener usuario_id

        # Insertar el nuevo envío sin el tiempo_estimado
        cur.execute("""
            INSERT INTO envios (ubicacion, numero_contacto, usuario_delivery_id, usuario_id)
            VALUES (%s, %s, %s, %s) RETURNING envio_id
        """, (ubicacion, numero_contacto, delivery_user, usuario_id))

        nuevo_envio_id = cur.fetchone()[0]  # Captura el nuevo envio_id
        conn.commit()
        cur.close()
        conn.close()

        flash('Pedido realizado con éxito. Esperando confirmación del delivery.', 'success')
        return redirect(url_for('dashboard', envio_id=nuevo_envio_id))

    return render_template('pedido.html')

#ruta de confirmacion de envio
@app.route('/confirmar_envio/<int:envio_id>', methods=['POST'])
@login_required
def confirmar_envio(envio_id):
    usuario_id = session['usuario_id']
    envio_id = request.form['envio_id']  # Obtener el envio_id del formulario
    
    # Verificar que el usuario sea delivery
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT rol_id FROM usuarios WHERE usuario_id = %s", (usuario_id,))
    rol = cur.fetchone()
    
    #el tiempo estimado lo define el delivery no el cliente
    if not rol or rol[0] != 4:  # Verificar que rol_id == 4 para delivery
        flash('No tienes permiso para confirmar envíos.', 'danger')
        return redirect(url_for('dashboard'))

    # Actualizar el estado del envío a 'aceptado'
    cur.execute("""
        UPDATE envios
        SET estado = 'aceptado'
        WHERE envio_id = %s AND usuario_delivery_id = %s
    """, (envio_id, usuario_id))

    conn.commit()
    cur.close()
    conn.close()

    flash('Envío aceptado exitosamente.', 'success')
    return redirect(url_for('dashboard'))

############
@app.route('/historial_envios_delivery')
def historial_envios_delivery():
    # Conexión a la base de datos
    conn = get_db_connection()
    cursor = conn.cursor()

    # Obtener todos los envíos
    cursor.execute('SELECT envio_id, ubicacion, numero_contacto, fecha_envio, estado, fecha_entrega, confirmacion_entrega FROM envios')
    envios = cursor.fetchall()

    cursor.close()
    conn.close()

    # Renderizar la plantilla y pasar los detalles de los envíos
    return render_template('historial_envios_delivery.html', envios=envios)

@app.route('/confirmar_entrega/<int:envio_id>', methods=['GET', 'POST'])
def confirmar_entrega(envio_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Obtener los detalles del envío
    cursor.execute('SELECT envio_id, ubicacion, numero_contacto, fecha_envio, estado, fecha_entrega, confirmacion_entrega FROM envios WHERE envio_id = %s', (envio_id,))
    envio = cursor.fetchone()

    if envio is None:
        return "Envío no encontrado", 404

    # Si se envía el formulario para confirmar la entrega
    if request.method == 'POST':
        # Actualizar confirmacion_entrega a True
        cursor.execute('UPDATE envios SET confirmacion_entrega = TRUE WHERE envio_id = %s', (envio_id,))
        conn.commit()
        return redirect(url_for('historial_envios_delivery'))

    cursor.close()
    conn.close()

    # Renderizar la plantilla y pasar los detalles del envío
    return render_template('confirmar_entrega.html', envio=envio)

#reclamos
@app.route('/reclamar/<int:envio_id>', methods=['GET', 'POST'])
def reclamar(envio_id):
    if request.method == 'POST':
        motivo = request.form.get('motivo')
        fecha = datetime.now()
        estado = "Pendiente"

        # Inserción en la tabla de reclamos utilizando la conexión establecida con get_db_connection()
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO reclamos (envio_id, motivo, fecha, estado) VALUES (%s, %s, %s, %s)",
                (envio_id, motivo, fecha, estado)
            )
            conn.commit()
            cur.close()
            conn.close()
            flash("Reclamo registrado exitosamente.", "success")
            return redirect(url_for('historial_de_envios'))
        except Exception as e:
            print("Error:", e)
            flash("Hubo un problema al registrar el reclamo.", "danger")
            if cur:
                cur.close()
            if conn:
                conn.close()

    return render_template('reclamar.html', envio_id=envio_id)

#mostrar reclamo
@app.route('/mostrar_reclamos')
def mostrar_reclamos():
    try:
        # Conexión a la base de datos y consulta de reclamos
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, envio_id, motivo, fecha, estado FROM reclamos ORDER BY fecha DESC")
        reclamos = cur.fetchall()
        
        cur.close()
        conn.close()
        
        return render_template('mostrar_reclamos.html', reclamos=reclamos)
    except Exception as e:
        print("Error:", e)
        flash("Hubo un problema al cargar los reclamos.", "danger")
        return render_template('mostrar_reclamos.html', reclamos=[])

#REGISTRO DE VENDEDORES
@app.route('/registrar_vendedor', methods=['GET', 'POST'])
@login_required  # Verifica si el usuario está autenticado
def registrar_vendedor():
    usuario_id = session['usuario_id']
    conn = None
    cur = None
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Verificar que el usuario tiene rol_id = 2
        cur.execute("SELECT rol_id, nombre, correo, comunidad_id FROM usuarios WHERE usuario_id = %s", (usuario_id,))
        usuario = cur.fetchone()

        if not usuario or usuario[0] != 2:
            flash("No tienes permiso para registrar un vendedor.", "danger")
            return redirect(url_for('perfil'))

        # Cargar datos del formulario
        if request.method == 'POST':
            nombre_tienda = request.form['nombre_tienda']
            descripcion = request.form['descripcion']
            contacto = request.form.get('contacto', usuario[2])  # Por defecto, el correo del usuario
            comunidad_id = request.form.get('comunidad_id', usuario[3])  # Por defecto, la comunidad del usuario

            # Validar campos
            if not nombre_tienda or not descripcion:
                flash("Todos los campos son obligatorios.", "danger")
                return redirect(url_for('registrar_vendedor'))

            # Insertar en la tabla Vendedores
            cur.execute(
                "INSERT INTO vendedores (usuario_id, nombre_tienda, descripcion, contacto, comunidad_id) VALUES (%s, %s, %s, %s, %s)",
                (usuario_id, nombre_tienda, descripcion, contacto, comunidad_id)
            )
            conn.commit()
            flash("Vendedor registrado exitosamente.", "success")
            return redirect(url_for('perfil'))
    
    except Exception as e:
        flash(f"Error al registrar el vendedor: {str(e)}", "danger")
        if conn:
            conn.rollback()
    
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    return render_template('registrar_vendedor.html', usuario=usuario)

#MODIFICAR STOCK
@app.route('/modificar_stock/<int:producto_id>', methods=['POST'])
def modificar_stock(producto_id):
    if 'usuario_id' not in session:
        return redirect(url_for('login'))

    usuario_id = session['usuario_id']
    nuevo_stock = request.form['stock']

    conn = get_db_connection()
    cur = conn.cursor()

    # Verificar si el usuario es el propietario del producto
    cur.execute("""
        SELECT p.vendedor_id 
        FROM productos p
        JOIN vendedores v ON p.vendedor_id = v.vendedor_id
        WHERE p.producto_id = %s AND v.usuario_id = %s
    """, (producto_id, usuario_id))
    propietario = cur.fetchone()

    if not propietario:
        conn.close()
        flash("No tienes permiso para modificar este producto.", "danger")
        return redirect(url_for('productos'))

    # Actualizar el stock del producto
    cur.execute("UPDATE productos SET stock = %s WHERE producto_id = %s", (nuevo_stock, producto_id))
    conn.commit()
    conn.close()

    flash("Stock actualizado exitosamente.", "success")
    return redirect(url_for('productos'))

#CARRITO
@app.route('/carritos', methods=['GET'])
def carritos():
    categoria_id = request.args.get('categoria_id')
    connection = get_db_connection()
    cursor = connection.cursor()

    # Consultar las categorías
    cursor.execute("SELECT categoria_id, nombre FROM categorias")
    categorias = cursor.fetchall()

    # Consulta para obtener los productos con la información adicional
    query = """
        SELECT 
            p.producto_id, p.vendedor_id, p.categoria_id, p.nombre, p.descripcion, 
            p.imagen_url, p.fecha_creacion, p.comunidad_id, p.dimension, p.stock, p.precio, 
            COALESCE(v.nombre_tienda, 'Artesano no disponible') AS artesano, 
            COALESCE(c.nombre, 'Comunidad no disponible') AS comunidad
        FROM productos p
        LEFT JOIN vendedores v ON p.vendedor_id = v.vendedor_id
        LEFT JOIN comunidades c ON p.comunidad_id = c.comunidad_id
    """
    
    # Filtrar por categoría si se proporciona
    if categoria_id:
        query += " WHERE p.categoria_id = %s"
        cursor.execute(query, (categoria_id,))
    else:
        cursor.execute(query)

    productos = cursor.fetchall()
    productos_dict = [
        {
            'producto_id': producto[0],
            'vendedor_id': producto[1],
            'categoria_id': producto[2],
            'nombre': producto[3],
            'descripcion': producto[4],
            'imagen_url': producto[5],
            'fecha_creacion': producto[6],
            'comunidad_id': producto[7],
            'dimension': producto[8],
            'stock': producto[9],
            'precio': producto[10],
            'artesano': producto[11],
            'comunidad': producto[12],
        }
        for producto in productos
    ]

    connection.close()

    return render_template('carritos.html', productos=productos_dict, categorias=categorias)


@app.route('/finalizar-compra', methods=['POST'])
def finalizar_compra():
    if 'usuario_id' not in session:  # Verificar si el usuario está autenticado
        return jsonify({'success': False, 'message': 'Usuario no autenticado.'}), 403

    carrito = request.json  # Obtener el carrito desde el JSON enviado
    if not carrito:
        return jsonify({'success': False, 'message': 'El carrito está vacío.'}), 400

    # Conexión a la base de datos
    try:
        # Usamos la función `get_db_connection` que ya incluye la codificación UTF-8
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                for item in carrito:
                    producto_id = item['productoId']
                    cantidad = item['cantidad']

                    # Consultar stock actual
                    cur.execute("SELECT stock FROM productos WHERE producto_id = %s", (producto_id,))
                    result = cur.fetchone()
                    if not result:
                        return jsonify({'success': False, 'message': f"Producto {producto_id} no encontrado."}), 404
                    
                    stock_actual = result[0]

                    if stock_actual < cantidad:
                        return jsonify({'success': False, 'message': f"Stock insuficiente para el producto {producto_id}."}), 400

                    # Actualizar el stock
                    cur.execute(
                        "UPDATE productos SET stock = stock - %s WHERE producto_id = %s",
                        (cantidad, producto_id)
                    )

                conn.commit()

        return jsonify({'success': True, 'message': 'Compra realizada con éxito.'}), 200

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/procesar_pedido', methods=['POST'])
def procesar_pedido():
    data = request.get_json()
    nombre = data.get('nombre')
    cart = data.get('cart')
    
    # Aquí puedes procesar los datos del carrito (almacenarlos en la base de datos, etc.)
    print(f"Nombre del cliente: {nombre}")
    print(f"Productos del carrito: {cart}")
    
    return jsonify({'status': 'success'})

#ENVIAR FACTURA: 
class Facturacion(db.Model):
    __tablename__ = 'facturacion'
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, nullable=False)
    monto_total = db.Column(db.Numeric(10, 2), nullable=False)
    fecha = db.Column(db.DateTime, default=datetime.utcnow)

@app.route('/enviar_factura', methods=['POST'])
def enviar_factura():
    try:
        # Obtener los datos enviados
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "No se recibieron datos."}), 400

        # Recuperar datos de la solicitud
        nombre = data.get('nombre')
        correo = data.get('correo')
        productos = data.get('cart')  # Esto debe ser una lista
        usuario_id = data.get('usuario_id')

        # Log para depuración
        app.logger.info(f"Datos recibidos: nombre={nombre}, correo={correo}, productos={productos}, usuario_id={usuario_id}")
        app.logger.info(f"Productos recibidos: {productos}")
        # Validaciones básicas
        if not nombre or not correo or not productos or not usuario_id:
            return jsonify({"status": "error", "message": "Faltan datos importantes en la solicitud."}), 400
        if not isinstance(productos, list):
            return jsonify({"status": "error", "message": "Formato de productos inválido. Se esperaba una lista."}), 400

        # Validar la estructura de los productos
        for producto in productos:
            if not isinstance(producto, dict):
                return jsonify({"status": "error", "message": "Cada producto debe ser un diccionario válido."}), 400
            if not all(key in producto for key in ['name', 'cantidad', 'price']):
                return jsonify({"status": "error", "message": "Cada producto debe contener las claves 'name', 'cantidad' y 'price'."}), 400

        # Calcular el total
        total = sum(producto['price'] * producto['cantidad'] for producto in productos)

        # Guardar la factura en la base de datos
        try:
            nueva_factura = Facturacion(usuario_id=usuario_id, monto_total=total, fecha=datetime.utcnow())
            db.session.add(nueva_factura)
            db.session.commit()
        except Exception as e:
            app.logger.error(f"Error al guardar la factura en la base de datos: {str(e)}")
            return jsonify({"status": "error", "message": f"Error al guardar la factura en la base de datos: {str(e)}"}), 500

        # Construir el contenido de la factura en formato HTML
        try:
            factura_html = render_template(
                'factura_email.html',
                nombre=nombre,
                correo=correo,
                productos=productos,
                total=total,
                fecha=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            )
        except Exception as e:
            app.logger.error(f"Error al generar el HTML de la factura: {str(e)}")
            return jsonify({"status": "error", "message": f"Error al generar el HTML de la factura: {str(e)}"}), 500

        # Crear el mensaje de correo
        try:
            msg = Message('Factura de Pago', sender=app.config['MAIL_USERNAME'], recipients=[correo])
            msg.html = factura_html

            # Enviar el correo sin el logo adjunto
            mail.send(msg)  # Enviar el correo
        except Exception as e:
            app.logger.error(f"Error al enviar el correo: {str(e)}")
            return jsonify({"status": "error", "message": f"Error al enviar el correo: {str(e)}"}), 500

        # Retornar éxito si todo salió bien
        return jsonify({"status": "success", "message": "Factura enviada correctamente."})

    except Exception as e:
        app.logger.error(f"Error inesperado: {str(e)}")
        return jsonify({"status": "error", "message": f"Error inesperado: {str(e)}"}), 500

@app.route('/chatbot', methods=['POST'])
def chatbot():
    user_message = request.json.get('message', '').strip()

    if not user_message:
        return jsonify({'response': "Por favor, escribe algo para que pueda ayudarte."})
    
    # Lógica básica para el chatbot
    bot_response = generar_respuesta(user_message)
    
    return jsonify({'response': bot_response})
def generar_respuesta(mensaje):
    # Lógica de respuestas simples basada en palabras clave
    mensaje = mensaje.lower()

    if "hola" in mensaje:
        return "¡Hola! Bienvenido a AndesArtBol. ¿En qué puedo ayudarte hoy?"
    elif "adiós" in mensaje or "bye" in mensaje:
        return "¡Adiós! Gracias por visitar AndesArtBol. ¡Vuelve pronto!"
    elif "ayuda" in mensaje:
        return "Claro, puedo ayudarte con temas de productos, compras o vendedores. ¿Qué necesitas?"
    elif "producto" in mensaje:
        return "Puedes buscar productos organizados por categorías como textiles, cerámica o joyería. También puedes usar filtros como precio o popularidad."
    elif "compra" in mensaje:
        return "Puedes realizar compras directas o agregar productos a tu carrito para más tarde. ¿Te gustaría ayuda con tu compra?"
    elif "pago" in mensaje:
        return "Ofrecemos métodos de pago como tarjetas de crédito, débito, transferencias bancarias y opciones de pago móvil."
    elif "pedido" in mensaje:
        return "Puedes rastrear el estado de tus pedidos en tiempo real desde la compra hasta la entrega."
    elif "vendedor" in mensaje:
        return "Si eres vendedor, puedes gestionar tu inventario, añadir productos nuevos o actualizar los existentes. ¿Quieres más detalles?"
    elif "inventario" in mensaje:
        return "Los vendedores pueden ver el stock actual, recibir notificaciones de bajo stock y gestionar entradas y salidas. ¿Te interesa saber más?"
    elif "favorito" in mensaje or "deseos" in mensaje:
        return "Puedes agregar productos a tu lista de favoritos para revisarlos y comprarlos más tarde."
    elif "reseña" in mensaje or "calificación" in mensaje:
        return "Después de realizar una compra, puedes dejar reseñas y calificaciones para ayudar a otros compradores."
    elif "ubicación" in mensaje or "cerca" in mensaje:
        return "Nuestra plataforma utiliza geolocalización para mostrarte productos y vendedores cercanos."
    elif "historial" in mensaje:
        return "Puedes consultar tu historial de compras con detalles de cada transacción realizada."
    elif "idioma" in mensaje or "lenguaje" in mensaje:
        return "Nuestra plataforma soporta múltiples idiomas para facilitar su uso en diversas comunidades."
    elif "offline" in mensaje:
        return "Puedes navegar offline los productos previamente cargados, y los datos se sincronizarán cuando estés en línea."
    elif "compartir" in mensaje or "redes sociales" in mensaje:
        return "Puedes compartir tus productos favoritos o experiencias de compra directamente en tus redes sociales."
    elif "seguridad" in mensaje:
        return "Tus datos sensibles, como métodos de pago, están protegidos mediante encriptación avanzada."
    elif "soporte" in mensaje:
        return "Estamos aquí para ayudarte. ¿Tienes alguna pregunta o problema específico que resolver?"
    elif "tendencias" in mensaje or "estadísticas" in mensaje:
        return "Los vendedores tienen acceso a estadísticas sobre ventas, productos más populares y tendencias directamente en la app."
    elif "creador" in mensaje or "desarrollador" in mensaje:
        return "La app fue desarrollada por Sebastian, una empresa de tecnología enfocada en soluciones para el comercio local."
    elif "gracias" in mensaje or "genial" in mensaje:
        return "¡De nada! Si tienes más preguntas, ¡aquí estoy para ayudarte!"
    else:
        return "Lo siento, no entiendo tu mensaje. ¿Puedes ser más específico?"

#dashboard
@app.route('/dash')
def dash():
    return render_template('dash.html')

@app.route('/data/usuarios')
def usuarios_data():
    data = db.session.query(Usuarios).all()
    result = [{"nombre": u.nombre, "fecha_registro": u.fecha_registro} for u in data]
    return jsonify(result)

@app.route('/data/envios')
def envios_data():
    try:
        envios = db.session.query(Envios).all()  # Reemplaza con el modelo real de Envios
        result = [{"estado": envio.estado} for envio in envios]
        return jsonify(result)
    except Exception as e:
        print(f"Error al obtener datos de envíos: {e}")
        return jsonify({"error": "No se pudieron obtener los datos de envíos"}), 500

# Endpoint: Productos por Categoría
@app.route('/data/productos')
def productos_data():
    query = text('SELECT categoria_id, COUNT(*) as total FROM productos GROUP BY categoria_id')
    productos = db.session.execute(query).fetchall()
    result = [{"categoria_id": p[0], "total": p[1]} for p in productos]
    return jsonify(result)

# Endpoint: Categorías (para mapeo de nombres)
@app.route('/data/categorias')
def categorias_data():
    query = text('SELECT categoria_id, nombre FROM categorias')
    categorias = db.session.execute(query).fetchall()
    result = [{"categoria_id": c[0], "nombre": c[1]} for c in categorias]
    return jsonify(result)

# Endpoint: Listado de productos (tabla)
@app.route('/data/productos/list')
def productos_list():
    query = text('SELECT producto_id, nombre, categoria_id FROM productos')
    productos = db.session.execute(query).fetchall()
    result = [{"producto_id": p[0], "nombre": p[1], "categoria_id": p[2]} for p in productos]
    return jsonify(result)


@app.route('/update_cart', methods=['POST'])
def update_cart():
    carrito = request.json  # Obtenemos el carrito desde el cliente
    session['productos_carrito'] = carrito  # Guardamos el carrito en la sesión
    return jsonify({'success': True})

#notificaciones

@app.route('/productos_bajos', methods=['GET', 'POST'])
def productos_bajos():
    conn = get_db_connection()
    cur = conn.cursor()

    if request.method == 'POST':
        producto_id = request.form['producto_id']
        nuevo_stock = request.form['nuevo_stock']
        
        # Actualizar el stock del producto en la base de datos
        cur.execute('UPDATE productos SET stock = %s WHERE producto_id = %s', (nuevo_stock, producto_id))
        conn.commit()

    # Obtener los productos con stock bajo (menos de 5 unidades)
    cur.execute('SELECT producto_id, nombre, precio, descripcion, stock FROM productos WHERE stock > 5')
    productos_bajos = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('productos_bajos.html', productos_bajos=productos_bajos)

def verificar_stock_bajo():
    productos_bajos = Producto.query.filter(Producto.stock < 5).all()
    
    for producto in productos_bajos:
        vendedor = Vendedores.query.filter_by(vendedor_id=producto.vendedor_id).first()
        usuario = Usuarios.query.filter_by(usuario_id=vendedor.usuario_id).first()

        # Verificar si el vendedor tiene un correo registrado
        if usuario and usuario.correo:
            # Crear el mensaje de correo
            mensaje = Message(
                subject=f'Alerta: Stock bajo de {producto.nombre}',
                recipients=[usuario.correo],
                body=f"Estimado {usuario.nombre},\n\nEl stock de tu producto '{producto.nombre}' es inferior a 5 unidades. Por favor, revisa tu inventario y realiza un pedido de reposición.\n\nFecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\nSaludos,\nEl equipo de Andes Artbol"
            )
            # Enviar el correo
            try:
                mail.send(mensaje)
                print(f"Correo enviado a {usuario.correo} sobre el producto {producto.nombre}.")
            except Exception as e:
                print(f"Error al enviar correo: {str(e)}")


# Endpoint: Distribución de usuarios por rol
@app.route('/data/usuarios_por_rol')
def usuarios_por_rol():
    try:
        # Obtener el conteo de usuarios por rol
        query = text("""
            SELECT r.nombre, COUNT(u.usuario_id) as total 
            FROM usuarios u
            LEFT JOIN roles r ON u.rol_id = r.rol_id
            GROUP BY r.nombre
        """)
        usuarios_rol = db.session.execute(query).fetchall()
        result = [{"rol": u[0], "total": u[1]} for u in usuarios_rol]
        return jsonify(result)
    except Exception as e:
        print(f"Error al obtener datos de usuarios por rol: {e}")
        return jsonify({"error": "No se pudieron obtener los datos de usuarios por rol"}), 500

# Endpoint: Distribución de productos por comunidad
@app.route('/data/productos_por_comunidad')
def productos_por_comunidad():
    try:
        # Obtener el conteo de productos por comunidad
        query = text("""
            SELECT c.nombre, COUNT(p.producto_id) as total
            FROM productos p
            LEFT JOIN comunidades c ON p.comunidad_id = c.comunidad_id
            GROUP BY c.nombre
        """)
        productos_comunidad = db.session.execute(query).fetchall()
        result = [{"comunidad": p[0], "total": p[1]} for p in productos_comunidad]
        return jsonify(result)
    except Exception as e:
        print(f"Error al obtener datos de productos por comunidad: {e}")
        return jsonify({"error": "No se pudieron obtener los datos de productos por comunidad"}), 500

# Endpoint: Stock de productos
@app.route('/data/stock_productos')
def stock_productos():
    try:
        # Obtener el stock de productos
        query = text("""
            SELECT p.nombre, p.stock
            FROM productos p
        """)
        stock_productos = db.session.execute(query).fetchall()
        result = [{"producto": p[0], "stock": p[1]} for p in stock_productos]
        return jsonify(result)
    except Exception as e:
        print(f"Error al obtener datos de stock de productos: {e}")
        return jsonify({"error": "No se pudieron obtener los datos de stock de productos"}), 500

# Endpoint: Envíos por usuario
@app.route('/data/envios_por_usuario')
def envios_por_usuario():
    try:
        # Obtener el conteo de envíos por usuario
        query = text("""
            SELECT u.nombre, COUNT(e.envio_id) as total
            FROM envios e
            LEFT JOIN usuarios u ON e.usuario_id = u.usuario_id
            GROUP BY u.nombre
        """)
        envios_usuario = db.session.execute(query).fetchall()
        result = [{"usuario": e[0], "total_envios": e[1]} for e in envios_usuario]
        return jsonify(result)
    except Exception as e:
        print(f"Error al obtener datos de envíos por usuario: {e}")
        return jsonify({"error": "No se pudieron obtener los datos de envíos por usuario"}), 500

# Endpoint: Productos por vendedor
@app.route('/data/productos_por_vendedor')
def productos_por_vendedor():
    try:
        # Obtener el conteo de productos por vendedor
        query = text("""
            SELECT v.nombre_tienda, COUNT(p.producto_id) as total
            FROM productos p
            LEFT JOIN vendedores v ON p.vendedor_id = v.vendedor_id
            GROUP BY v.nombre_tienda
        """)
        productos_vendedor = db.session.execute(query).fetchall()
        result = [{"vendedor": p[0], "total_productos": p[1]} for p in productos_vendedor]
        return jsonify(result)
    except Exception as e:
        print(f"Error al obtener datos de productos por vendedor: {e}")
        return jsonify({"error": "No se pudieron obtener los datos de productos por vendedor"}), 500

# Endpoint: Ganancia por vendedor
@app.route('/data/ganancia_por_vendedor')
def ganancia_por_vendedor():
    try:
        # Obtener la ganancia por vendedor (asumimos que el precio del producto * stock da la ganancia)
        query = text("""
            SELECT v.nombre_tienda, SUM(p.precio * p.stock) as ganancia
            FROM productos p
            LEFT JOIN vendedores v ON p.vendedor_id = v.vendedor_id
            GROUP BY v.nombre_tienda
        """)
        ganancia_vendedor = db.session.execute(query).fetchall()
        result = [{"vendedor": g[0], "ganancia": float(g[1])} for g in ganancia_vendedor]
        return jsonify(result)
    except Exception as e:
        print(f"Error al obtener datos de ganancia por vendedor: {e}")
        return jsonify({"error": "No se pudieron obtener los datos de ganancia por vendedor"}), 500

    
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
    app.run(debug=True)