# === LIBRERÍAS ===
import streamlit as st
import pandas as pd
import bcrypt
import os
import base64
from azure.storage.blob import BlobServiceClient
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
from datetime import datetime
from azure.data.tables import TableServiceClient
from PIL import Image

st.set_page_config(page_title="Firma Digital", layout="wide", page_icon="🔐")

AZURE_CONNECTION_STRING = st.secrets["AZURE_CONNECTION_STRING"]
USERS_CONTAINER = st.secrets["USERS_CONTAINER"]
FILES_CONTAINER = st.secrets["FILES_CONTAINER"]
LOG_CONTAINER = st.secrets["LOG_CONTAINER"]

table_service = TableServiceClient.from_connection_string(AZURE_CONNECTION_STRING)
users_table = table_service.get_table_client(table_name=USERS_CONTAINER)
acces_table = table_service.get_table_client(table_name=LOG_CONTAINER)

blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)
files_container_client = blob_service_client.get_container_client(FILES_CONTAINER)

if "role" not in st.session_state:
    st.session_state.role = "IniciarSesion"
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "current_user" not in st.session_state:
    st.session_state.current_user = ""


# === FUNCIONES ===
def generate_keys(username):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    
    return private_pem, public_pem


def insert_user(username, password):
    private_key, public_key = generate_keys(username)
    users_table.upsert_entity(
        {
            "PartitionKey": "usuario",
            "RowKey": username,
            "Password": password,
            "PrivateKey": private_key,
            "PublicKey": public_key,
            "FechaCreacion": datetime.utcnow().isoformat(),
        }
    )


def insert_access_log(username):
    acces_table.upsert_entity(
        {
            "PartitionKey": "acceso",
            "RowKey": username,
            "FechaAcceso": datetime.utcnow().isoformat(),
        }
    )


def load_users():
    users = users_table.query_entities("PartitionKey eq 'usuario'")
    user_list = []
    for user in users:
        user_list.append([user["RowKey"], user["Password"]])
    return pd.DataFrame(user_list, columns=["username", "password"])


def user_exists(username):
    df = load_users()
    return username in df["username"].values


def verify_user(username, password):
    df = load_users()
    user = df[df["username"] == username]
    if not user.empty:
        stored = user.iloc[0]["password"]
        hashed = stored if isinstance(stored, bytes) else stored.encode()

        return bcrypt.checkpw(password.encode(), hashed)
    return False


# === FUNCIONES DE CRIPTOGRAFÍA ===
def cargar_llave_privada():
    user = st.session_state.current_user
    user_data = users_table.get_entity("usuario", user)
    return serialization.load_pem_private_key(
        user_data["PrivateKey"].encode(), password=None
    )


def cargar_llave_publica():
    user = st.session_state.current_user
    user_data = users_table.get_entity("usuario", user)
    return serialization.load_pem_public_key(user_data["PublicKey"].encode())


def firmar_archivo(file_bytes):
    private_key = cargar_llave_privada()
    firma = private_key.sign(
        file_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(firma).decode()


def verificar_firma(file_bytes, firma_base64):
    public_key = cargar_llave_publica()
    firma = base64.b64decode(firma_base64)
    try:
        public_key.verify(
            firma,
            file_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


# === FIRMAS ===
def guardar_archivo_firmado(username, filename, firma_base64):
    firma_blob_path = f"firmas/{username}/{filename}.firma"
    metadata_blob_path = f"firmas/{username}/{filename}.meta.txt"
    firma_blob = blob_service_client.get_blob_client(container=FILES_CONTAINER, blob=firma_blob_path)
    firma_blob.upload_blob(firma_base64, overwrite=True)
    metadata_content = f"Usuario: {username}\nArchivo: {filename}\nFecha: {datetime.now()}\n"
    meta_blob = blob_service_client.get_blob_client(container=FILES_CONTAINER, blob=metadata_blob_path)
    meta_blob.upload_blob(metadata_content, overwrite=True)


def identificar_firmante(file_bytes, firma_base64):
    users = users_table.query_entities("PartitionKey eq 'usuario'")
    for user in users:
        username = user["RowKey"]
        public_key_pem = user["PublicKey"]
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            public_key.verify(
                base64.b64decode(firma_base64),
                file_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return username
        except InvalidSignature:
            continue
        except Exception:
            continue
    return None


def registrar_acceso(username):
    insert_access_log(username)


# === POST CREACIÓN DE CUENTA ===
if st.session_state.get("creado"):
    st.session_state.role = "IniciarSesion"
    st.success("Cuenta creada con éxito. Bienvenido")

    st.download_button(
        label="📥 Descargar Clave Privada",
        data=st.session_state["private_key_data"],
        file_name=f"{st.session_state.get('nuevo_usuario')}_clave_privada.pem",
        mime="text/plain",
    )

    # Resetear el estado de creación
    del st.session_state["creado"]
    del st.session_state["private_key_data"]
    del st.session_state["nuevo_usuario"]

# Cargar imágenes desde archivos locales
logo_izq = Image.open(
    "logotipo-prepanet-programa-social-preparatoria-bachillerato-en-linea-tec-de-monterrey.jpg"
)
logo_der = Image.open("tecnologico-de-monterrey-blue.png")

# Crear layout con columnas
col1, col2, col3 = st.columns([3, 8, 3])

with col1:
    st.image(logo_izq, width=250)

with col3:
    st.image(logo_der, width=250)

# === INTERFAZ DE USUARIO ===
st.markdown(
    "<h1 style='text-align: center;'>Firma Digital para PrepaNet 🔐</h1>",
    unsafe_allow_html=True,
)
st.markdown(
    "<div style='text-align: center;'>Bienvenido a la aplicación para la producción de <span style='color:#1f77b4'><b>firmas digitales</b></span></div>",
    unsafe_allow_html=True,
)


# === MENU PRINCIPAL ===
if not st.session_state.logged_in:
    tabs = st.tabs(["Iniciar Sesión", "Crear Cuenta"])
    # === INICIAR SESIÓN ===
    with tabs[0]:
        df_usuarios = load_users()
        df_usuarios["password_str"] = df_usuarios["password"].apply(lambda x: bytes(map(int, x.split(","))).decode())
        df_usuarios["unhashed_password"] = df_usuarios["password_str"].apply(
            lambda x: bcrypt.hashpw(x.encode(), bcrypt.gensalt()).decode()
        )
        st.subheader("📋 Debug - Usuarios desde Azure Table")
        st.dataframe(df_usuarios)
        st.session_state.role = "IniciarSesion"
        st.markdown("<h2>Iniciar Sesión 🔑</h2>", unsafe_allow_html=True)

        login_user = st.text_input("Nombre de Usuario", key="login_user")
        login_pass = st.text_input("Contraseña", type="password", key="login_pass")
        if st.button("Iniciar Sesión"):
            if verify_user(login_user, login_pass):
                st.session_state.logged_in = True
                st.session_state.current_user = login_user
                registrar_acceso(login_user)
                st.rerun()  # Recarga la app para mostrar las nuevas tabs
            else:
                st.error("Usuario o contraseña incorrectos ❌")

    # === CREAR CUENTA ===
    with tabs[1]:
        st.session_state.role = "CrearCuenta"
        st.markdown("<h2>Crear Cuenta 💼</h2>", unsafe_allow_html=True)

        new_user = st.text_input("Nombre de Usuario", key="new user")
        new_pass = st.text_input("Contraseña", type="password", key="new_pass")
        new_pass_confirm = st.text_input(
            "Confirmar Contraseña", type="password", key="new_pass_confirm"
        )

        if new_pass and new_pass_confirm:
            if new_pass != new_pass_confirm:
                st.error("Las contraseñas no coinciden ❌")
            elif user_exists(new_user):
                st.warning("El nombre de usuario ya está registrado ⚠️")
            else:
                st.success("Las contraseñas coinciden ✅")
                if st.button("Crear Cuenta"):
                    hashed_password = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt())
                    insert_user(new_user, hashed_password)
                    st.rerun()

# === MENU DE PERFIL ===
else:
    st.write("")
    st.markdown(
        f"<div style='text-align: center; color: green; font-weight: bold; background-color: #d4edda; "
        "padding: 10px; border-radius: 5px; border: 1px solid #c3e6cb;'>"
        f"Bienvenido {st.session_state.current_user}, estás en línea"
        "</div>",
        unsafe_allow_html=True,
    )
    st.write("")

    if st.button("Cerrar Sesión"):
        st.session_state.logged_in = False
        st.session_state.current_user = ""
        st.rerun()

    if st.session_state.current_user == "Admin":
        # === TABS PARA ADMINISTRADOR ===
        admin_tabs = st.tabs(
            [
                "📋 Usuarios Registrados",
                "📁 Archivos Firmados",
                "🔐 Claves Públicas/Privadas",
                "📈 Gráfico de Accesos",
                "📄 Código de la Página",
            ]
        )

        # === TAB 1: Usuarios Registrados ===
        with admin_tabs[0]:
            st.subheader("📋 Usuarios Registrados")
            if os.path.exists(USER_FILE):
                usuarios_df = pd.read_csv(USER_FILE)
                st.dataframe(usuarios_df)
            else:
                st.warning("No hay usuarios registrados.")

        # === TAB 2: Archivos Firmados ===
        with admin_tabs[1]:
            st.subheader("📁 Archivos Firmados por Todos los Usuarios")
            all_firmas = []
            for user_folder in os.listdir(SIGNED_FOLDER):
                user_path = os.path.join(SIGNED_FOLDER, user_folder)
                if os.path.isdir(user_path):
                    for file in os.listdir(user_path):
                        if file.endswith(".firma"):
                            all_firmas.append(
                                {
                                    "Usuario": user_folder,
                                    "Archivo": file.replace(".firma", ""),
                                }
                            )
            if all_firmas:
                st.dataframe(pd.DataFrame(all_firmas))
            else:
                st.info("No hay archivos firmados todavía.")

        # === TAB 3: Carpetas de Claves ===
        with admin_tabs[2]:
            st.subheader("🔐 Carpetas de Claves")

            # Obtener archivos
            pub_keys = os.listdir(PUBLIC_KEY_FOLDER)
            priv_keys = os.listdir(PRIVATE_KEY_FOLDER)

            # Crear DataFrames
            df_pub = pd.DataFrame(pub_keys, columns=["Claves Públicas"])
            df_priv = pd.DataFrame(priv_keys, columns=["Claves Privadas"])

            # Tabs para claves
            tab_pub, tab_priv = st.tabs(["🔓 Claves Públicas", "🔒 Claves Privadas"])

            with tab_pub:
                st.dataframe(df_pub, use_container_width=True)

            with tab_priv:
                st.dataframe(df_priv, use_container_width=True)

        # === TAB 4: Accesos por Día ===
        with admin_tabs[3]:
            st.subheader("📈 Accesos por Día")
            access_df = pd.read_csv(ACCESS_LOG)
            access_df["timestamp"] = pd.to_datetime(access_df["timestamp"])
            access_df["date"] = access_df[
                "timestamp"
            ].dt.date  # Solo la fecha (sin hora)

            # Agrupar por fecha y contar accesos
            daily_counts = access_df.groupby("date")["username"].count().reset_index()
            daily_counts.columns = ["Fecha", "Accesos"]

            # Crear gráfico de líneas
            import plotly.express as px

            fig = px.line(
                daily_counts,
                x="Fecha",
                y="Accesos",
                title="Accesos por Día",
                markers=True,
            )
            st.plotly_chart(fig)
        with admin_tabs[4]:
            st.subheader("📄 Código Fuente de esta Aplicación")

            try:
                with open(__file__, "r", encoding="utf-8") as f:
                    codigo = f.read()
                with st.expander(
                    "Ver código completo de FirmaDigital.py", expanded=False
                ):
                    st.code(codigo, language="python")
            except Exception:
                st.warning(
                    "⚠️ No se pudo cargar el archivo fuente. Esto puede ocurrir si estás usando un entorno como Streamlit Cloud o ejecutando desde IPython."
                )

    else:

        # === TABS PARA USUARIOS REGULARES ===
        signed_tabs = st.tabs(
            ["Verificar Firma ✅", "Visualizar Archivos Verificados 📁"]
        )

        # === Verificar Firma ===
        with signed_tabs[0]:
            st.subheader("Verificar Firma ✅")
            original_file = st.file_uploader(
                "Sube el archivo original", key="file_original"
            )
            signature_file = st.file_uploader(
                "Sube el archivo .firma", key="file_signature"
            )

            if original_file and signature_file:
                original_bytes = original_file.read()
                signature_b64 = signature_file.read().decode()

                firmante = identificar_firmante(original_bytes, signature_b64)

                if firmante:
                    try:
                        guardar_archivo_firmado(firmante, original_file.name, signature_b64)
                    except Exception as e:
                        st.error(f"Error al guardar el archivo firmado: {e}")
                        st.stop()
                    st.success(
                        f"Firma válida. Documento firmado por: **{firmante}** ✅"
                    )
                else:
                    st.error(
                        "La firma NO es válida o no se pudo identificar al firmante ❌"
                    )

        # === Re-descargar Clave Privada ===
        with signed_tabs[1]:
            st.subheader("Visualizar Archivos Verificados 📁")
            st.write(
                "Aquí puedes ver los archivos que has verificado. "
                "Recuerda que la firma digital es única para cada archivo."
            )
            try:
                user_data = users_table.get_entity(
                    "usuario", st.session_state.current_user
                )
                private_key_data = user_data["PrivateKey"].encode()

                st.download_button(
                    label="📥 Descargar Clave Privada Nuevamente",
                    data=private_key_data,
                    file_name=f"{st.session_state.current_user}_clave_privada.pem",
                    mime="text/plain",
                )
            except Exception:
                st.error("No se pudo recuperar la clave privada desde la tabla ❌")

# Pie de página con HTML y CSS embebido
footer = """
<style>
.footer {
    border-top: 2.5px solid #888; /* Línea separadora gris */
    padding: 40px 0 20px 0;
    font-family: 'Segoe UI', sans-serif;
    display: flex;
    justify-content: space-around;
    flex-wrap: wrap;
    background-color: transparent; /* Sin fondo oscuro */
    margin-top: 60px;
}

.footer-column {
    flex: 1 1 200px;
    margin: 15px;
}

.footer h4 {
    margin-bottom: 10px;
    font-size: 16px;
}

.footer a {
    color: #164D99 ;  /* Mantiene el color original de los enlaces */
    text-decoration: none;
    display: block;
    margin-bottom: 6px;
    font-size: 14px;
}

.footer a:hover {
    color: #2471FF; /* Al pasar el cursor, mantiene efecto claro */
}
</style>

<div class="footer">
    <div class="footer-column">
        <h2>Prep@Net 🔒</h2>
        <p>Esta plataforma es creada por estudiantes del Tecnológico de Monterrey para la creación de llaves digitales y verificación de las mismas</p>
    </div>
    <div class="footer-column">
        <h2>Tecnológico de Monterrey</h2>
        <p>Insitituto Tecnológico y de Estudios Superiores de Monterrey, Ave. Eugenio Garza Sada 2501 Sur </p>
        <p>Col. Tecnológico de Monterrey, Nuevo León 64849, México, 8183582000</p>
    </div>
    <div class="footer-column">
        <h2>Uso de álgebras modernas para seguridad y criptografía (Gpo 601)</h2>
        <p>Este proyecto es parte de la materia de álgebras modernas para seguridad y criptografía</p>
        <p>Profesores</p>
        <p>Eliseo Sarmiento</p>
        <p>Fernando Vallejo</p>
    </div>
</div>
"""
st.markdown(footer, unsafe_allow_html=True)
