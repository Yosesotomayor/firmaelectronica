# === LIBRERÍAS ===
import streamlit as st
import pandas as pd
import bcrypt
import os
import base64
import pytz
from azure.storage.blob import BlobServiceClient
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
from datetime import datetime
from azure.data.tables import TableServiceClient
from PIL import Image
import plotly.express as px

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
def generate_keys():
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
    private_key, public_key = generate_keys()
    tz = pytz.timezone("America/Mexico_City")
    fecha_creacion = datetime.now(tz).strftime("%d/%m/%Y %H:%M")
    users_table.upsert_entity(
        {
            "PartitionKey": "usuario",
            "RowKey": username,
            "Password": password,
            "PrivateKey": private_key,
            "PublicKey": public_key,
            "FechaCreacion": fecha_creacion,
        }
    )


def insert_access_log(username):
    tz = pytz.timezone("America/Mexico_City")
    fecha_acceso = datetime.now(tz).strftime("%d/%m/%Y %H:%M")
    acces_table.upsert_entity(
        {
            "PartitionKey": "acceso",
            "RowKey": username,
            "FechaAcceso": fecha_acceso,
        }
    )

def guardar_archivo_firmado(username, filename, firma_base64, file_bytes=None):
    firma_blob_path = f"firmas/{username}/{filename}.firma"
    metadata_blob_path = f"firmas/{username}/{filename}.meta.txt"
    original_blob_path = f"firmas/{username}/{filename}"

    # Subir firma
    firma_blob = blob_service_client.get_blob_client(container=FILES_CONTAINER, blob=firma_blob_path)
    firma_blob.upload_blob(firma_base64, overwrite=True)

    # Subir archivo original (si se proporciona)
    if file_bytes:
        original_blob = blob_service_client.get_blob_client(container=FILES_CONTAINER, blob=original_blob_path)
        original_blob.upload_blob(file_bytes, overwrite=True)

    # Subir metadatos
    metadata_content = (
        f"Usuario dueño: {username}\n"
        f"Firmado por: {st.session_state.current_user}\n"
        f"Archivo: {filename}\n"
        f"Fecha: {datetime.now()}\n"
    )
    meta_blob = blob_service_client.get_blob_client(container=FILES_CONTAINER, blob=metadata_blob_path)
    meta_blob.upload_blob(metadata_content, overwrite=True)

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
    user = df[df["username"].str.upper() == username.upper()]
    if not user.empty:
        stored = user.iloc[0]["password"]
        if isinstance(stored, str) and "," in stored:
            try:
                hashed = bytes(map(int, stored.split(",")))
            except Exception:
                return False
        elif isinstance(stored, bytes):
            hashed = stored
        else:
            try:
                hashed = stored.encode()
            except Exception:
                return False

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
            st.info(f"Firma inválida con {username}")
            continue
        except Exception as e:
            st.error(f"{username} falló por: {e}")
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
    "<h1 style='text-align: center;'>Firma Digital PrepaNet 🔐</h1>",
    unsafe_allow_html=True,
)
st.markdown(
    "<div style='text-align: center;'>Bienvenido a la aplicación para la producción de <span style='color:#1f77b4'><b>firmas digitales</b></span></div>",
    unsafe_allow_html=True,
)


# === Aux password=== #
def parse_password(raw):
    if isinstance(raw, str):
        try:
            return bytes(map(int, raw.split(","))).decode()
        except Exception as e:
            return f"⚠️ Error: {e}"
    elif isinstance(raw, bytes):
        try:
            return raw.decode()
        except Exception as e:
            return f"⚠️ Error: {e}"
    else:
        return "❌ Tipo no compatible"
    

# === MENU PRINCIPAL ===
if not st.session_state.logged_in:
    tabs = st.tabs(["Iniciar Sesión", "Crear Cuenta"])
    # === INICIAR SESIÓN ===
    with tabs[0]:
        st.session_state.role = "IniciarSesion"
        st.markdown("<h2>Iniciar Sesión 🔑</h2>", unsafe_allow_html=True)

        with st.form("login_form"):
            login_user = st.text_input("Nombre de Usuario", key="login_user")
            login_pass = st.text_input("Contraseña", type="password", key="login_pass")
            submitted_login = st.form_submit_button("Iniciar Sesión")
            if submitted_login:
                if verify_user(login_user, login_pass):
                    st.session_state.logged_in = True
                    st.session_state.current_user = login_user
                    registrar_acceso(login_user)
                    st.rerun()
                else:
                    st.error("Usuario o contraseña incorrectos ❌")

    # === CREAR CUENTA ===
    with tabs[1]:
        st.session_state.role = "CrearCuenta"
        st.markdown("<h2>Crear Cuenta 💼</h2>", unsafe_allow_html=True)

        with st.form("register_form"):
            new_user = st.text_input("Nombre de Usuario", key="new user")
            new_pass = st.text_input("Contraseña", type="password", key="new_pass")
            new_pass_confirm = st.text_input("Confirmar Contraseña", type="password", key="new_pass_confirm")
            submitted_register = st.form_submit_button("Crear Cuenta")

            if submitted_register:
                if new_pass != new_pass_confirm:
                    st.error("Las contraseñas no coinciden ❌")
                elif user_exists(new_user):
                    st.warning("El nombre de usuario ya está registrado ⚠️")
                elif len(new_pass) < 8:
                    st.error("La contraseña debe tener al menos 8 caracteres ❌")
                else:
                    st.success("Las contraseñas coinciden ✅")
                    hashed_password = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt())
                    insert_user(new_user, hashed_password)
                    st.session_state["creado"] = True
                    st.session_state["nuevo_usuario"] = new_user
                    st.session_state["private_key_data"] = hashed_password
                    st.rerun()

# === MENU DE PERFIL ===
else:
    st.write("")
    st.markdown(
        f"<div style='text-align: center; color: green; font-weight: bold; background-color: #d4edda; "
        "padding: 10px; border-radius: 5px; border: 1px solid #c3e6cb;'>"
        f"Bienvenido {st.session_state.current_user}, estás en línea."
        "</div>",
        unsafe_allow_html=True,
    )
    st.write("")

    if st.button("Cerrar Sesión"):
        st.session_state.logged_in = False
        st.session_state.current_user = ""
        st.rerun()

    if st.session_state.current_user.capitalize() == "Tecdemonterrey":  
        # === TABS PARA ADMINISTRADOR ===
        admin_tabs = st.tabs(
            [
                "📋 Usuarios Registrados",
                "📂 Firmar Archivos",
                "🔍 Verificar Firma",
                "📁 Archivos Firmados",
                "📈 Gráfico de Accesos",
                "🔑 Cambiar Contraseña",
            ]
        )

        # === TAB 1: Usuarios Registrados ===
        with admin_tabs[0]:
            st.subheader("📋 Usuarios Registrados")
            users = users_table.query_entities("PartitionKey eq 'usuario'")
            st.write(users)
            for user in users:
                username = user["RowKey"]
                col1, col2 = st.columns([5, 1])
                with col1:
                    if username.capitalize() == "Tecdemonterrey":
                        st.markdown(f"**👤 ADMINISTRADOR:** {username}")
                    else:
                        st.markdown(f"**👤 Usuario:** {username}")
                with col2:
                    if username.capitalize() != "Tecdemonterrey":
                        if st.button("Eliminar", key=f"delete_{username}"):
                            try:
                                users_table.delete_entity(partition_key="usuario", row_key=username)
                                st.success(f"Usuario '{username}' eliminado correctamente.")
                                st.rerun()
                            except Exception as e:
                                st.error(f"No se pudo eliminar el usuario: {e}")
                    else:
                        pass
                
        # === TAB 2: Firmar Archivos ===
        with admin_tabs[1]:
            st.subheader("Firma de Archivo 📁")
            
            uploaded_file = st.file_uploader(
                "Selecciona un archivo para firmar", key="file_firma"
            )
            
            usuarios = load_users()['username'].to_list()

            usuario_objetivo = st.selectbox("Selecciona el destinatario del documento firmado:", usuarios)
            
            if uploaded_file:
                file_bytes = uploaded_file.read()
                firma_base64 = firmar_archivo(file_bytes)
                st.text_area("Firma generada (Base64):", value=firma_base64, height=150)

                destinatario = (
                    st.session_state.current_user
                    if usuario_objetivo.startswith("(")
                    else usuario_objetivo
                )

                if st.button("✅ Confirmar Firma"):
                    guardar_archivo_firmado(destinatario, uploaded_file.name, firma_base64, file_bytes)

                    st.download_button(
                        label="Descargar archivo .firma 📥",
                        data=firma_base64,
                        file_name=f"{uploaded_file.name}.firma",
                        mime="text/plain",
                    )
        # === TAB 3: Verificar Firmas ===
        with admin_tabs[2]:
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
                        guardar_archivo_firmado(
                            firmante, original_file.name, signature_b64
                        )
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

        # === TAB 4: Archivos Firmados ===
        with admin_tabs[3]:
            st.subheader("📁 Archivos Firmados")
            all_firmas = []

            try:
                blob_list = files_container_client.list_blobs(name_starts_with="firmas/")
                for blob in blob_list:
                    if blob.name.endswith(".firma"):
                        parts = blob.name.split("/")
                        if len(parts) == 3:
                            usuario = parts[1]
                            archivo = parts[2].replace(".firma", "")
                            all_firmas.append({"Usuario": usuario, "Archivo": archivo})
            except Exception as e:
                st.error(f"Error al recuperar archivos firmados desde Azure: {e}")

            if all_firmas:
                df = pd.DataFrame(all_firmas)

                for i, row in df.iterrows():
                    col1, col2, col3, col4, col5 = st.columns([4, 1.5, 1.5, 1.5, 1])
                    usuario = row["Usuario"]
                    archivo = row["Archivo"]

                    with col1:
                        st.markdown(f"**📄 {archivo}** — Propietario: `{usuario}`")

                    # Descargar .firma
                    with col2:
                        try:
                            firma_blob = files_container_client.get_blob_client(
                                f"firmas/{usuario}/{archivo}.firma"
                            )
                            firma_data = firma_blob.download_blob().readall()
                            st.download_button(
                                label="📥 .firma",
                                data=firma_data,
                                file_name=f"{archivo}.firma",
                                mime="text/plain",
                                key=f"dl_firma_admin_{usuario}_{archivo}"
                            )
                        except Exception:
                            st.error("Error al obtener .firma")

                    # Descargar .meta.txt
                    with col3:
                        try:
                            meta_blob = files_container_client.get_blob_client(
                                f"firmas/{usuario}/{archivo}.meta.txt"
                            )
                            meta_data = meta_blob.download_blob().readall()
                            st.download_button(
                                label="📋 .meta",
                                data=meta_data,
                                file_name=f"{archivo}.meta.txt",
                                mime="text/plain",
                                key=f"dl_meta_admin_{usuario}_{archivo}"
                            )
                        except Exception:
                            st.error("Error al obtener .meta")

                    # Descargar archivo original
                    with col4:
                        try:
                            original_blob = files_container_client.get_blob_client(
                                f"firmas/{usuario}/{archivo}"
                            )
                            original_data = original_blob.download_blob().readall()
                            st.download_button(
                                label="📎 Archivo",
                                data=original_data,
                                file_name=archivo,
                                mime="application/octet-stream",
                                key=f"dl_file_admin_{usuario}_{archivo}"
                            )
                        except Exception:
                            st.error("Error al obtener archivo original")

                    # Botón eliminar
                    with col5:
                        if st.button("🗑 Eliminar", key=f"del_{usuario}_{archivo}"):
                            try:
                                firma_blob.delete_blob()
                                meta_blob.delete_blob()
                                original_blob.delete_blob()
                                st.success(f"Archivo '{archivo}' eliminado correctamente.")
                                st.rerun()
                            except Exception as e:
                                st.error(f"No se pudo eliminar el archivo: {e}")
            else:
                st.info("No hay archivos firmados todavía.")

        # === TAB 5: Accesos por Día ===
        with admin_tabs[4]:
            st.subheader("📈 Accesos por Día")

            try:
                access_entities = acces_table.query_entities("PartitionKey eq 'acceso'")
                access_data = []

                for entry in access_entities:
                    access_data.append(
                        {
                            "username": entry["RowKey"],
                            "timestamp": pd.to_datetime(entry["FechaAcceso"]),
                        }
                    )

                access_df = pd.DataFrame(access_data)
                access_df["date"] = access_df["timestamp"].dt.date

                daily_counts = (
                    access_df.groupby("date")["username"].count().reset_index()
                )
                daily_counts.columns = ["Fecha", "Accesos"]

                fig = px.line(
                    daily_counts,
                    x="Fecha",
                    y="Accesos",
                    title="Accesos por Día",
                    markers=True,
                )
                st.plotly_chart(fig)

            except Exception as e:
                st.error(f"No se pudo cargar el historial de accesos desde Azure: {e}")

        # === TAB 6:  CAMBIAR CONTRASEÑA ===
        with admin_tabs[5]:
            st.subheader("🔑 Cambiar Contraseña")

            old_pass = st.text_input("Contraseña actual", type="password", key="old_pass")
            new_pass = st.text_input("Nueva contraseña", type="password", key="new_pass_user")
            confirm_new_pass = st.text_input("Confirmar nueva contraseña", type="password", key="confirm_new_pass_user")

            if st.button("Actualizar Contraseña"):
                if new_pass != confirm_new_pass:
                    st.error("Las nuevas contraseñas no coinciden ❌")
                elif not verify_user(st.session_state.current_user, old_pass):
                    st.error("La contraseña actual es incorrecta ❌")
                elif len(new_pass) < 8:
                    st.error("La contraseña debe tener al menos 8 caracteres ❌")
                else:
                    new_hashed = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt())
                    try:
                        # Obtener entidad actual
                        user_data = users_table.get_entity("usuario", st.session_state.current_user)
                        user_data["Password"] = new_hashed

                        # Reemplazar sin usar 'mode'
                        users_table.upsert_entity(user_data)

                        st.success("Contraseña actualizada correctamente ✅")
                    except Exception as e:
                        st.error(f"No se pudo actualizar la contraseña: {e}")


    else:

        # === TABS PARA USUARIOS REGULARES ===
        signed_tabs = st.tabs(
            ["Verificar Firma ✅", "Visualizar Archivos Verificados por el Administrador 📁", "🔑 Cambiar Contraseña"]
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
                        guardar_archivo_firmado(
                            firmante, original_file.name, signature_b64
                        )
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

        # === Checar mis archivos firmados por el administrador ===
        with signed_tabs[1]:
            st.subheader("📁 Mis Archivos Firmados")

            archivos_usuario = []
            try:
                blob_list = files_container_client.list_blobs(
                    name_starts_with=f"firmas/{st.session_state.current_user}/"
                )
                for blob in blob_list:
                    if blob.name.endswith(".firma"):
                        archivo = blob.name.split("/")[-1].replace(".firma", "")
                        archivos_usuario.append({"Archivo": archivo})
            except Exception as e:
                st.error(f"Error al obtener archivos firmados: {e}")

            if archivos_usuario:
                for item in archivos_usuario:
                    col1, col2, col3 = st.columns([5, 2, 2])
                    with col1:
                        st.markdown(f"**📄 {item['Archivo']}**")
                    with col2:
                        firma_path = f"firmas/{st.session_state.current_user}/{item['Archivo']}.firma"
                        try:
                            firma_blob = files_container_client.get_blob_client(firma_path)
                            firma_data = firma_blob.download_blob().readall()
                            st.download_button(
                                label="📥 .firma",
                                data=firma_data,
                                file_name=f"{item['Archivo']}.firma",
                                mime="text/plain",
                                key=f"dl_firma_{item['Archivo']}"
                            )
                        except Exception:
                            st.error("Error al obtener archivo .firma")
                    with col3:
                        original_path = f"firmas/{st.session_state.current_user}/{item['Archivo']}"
                        try:
                            original_blob = files_container_client.get_blob_client(original_path)
                            original_data = original_blob.download_blob().readall()
                            st.download_button(
                                label="📎 Archivo",
                                data=original_data,
                                file_name=item["Archivo"],
                                mime="application/octet-stream",
                                key=f"dl_original_{item['Archivo']}"
                            )
                        except Exception:
                            st.error("Error al obtener archivo original")
            else:
                st.info("No tienes archivos firmados todavía.")
                                            
        # CAMBIAR CONTRASEÑA ===
        with signed_tabs[2]:
            st.subheader("🔑 Cambiar Contraseña")

            old_pass = st.text_input("Contraseña actual", type="password", key="old_pass")
            new_pass = st.text_input("Nueva contraseña", type="password", key="new_pass_user")
            confirm_new_pass = st.text_input("Confirmar nueva contraseña", type="password", key="confirm_new_pass_user")

            if st.button("Actualizar Contraseña"):
                if new_pass != confirm_new_pass:
                    st.error("Las nuevas contraseñas no coinciden ❌")
                elif not verify_user(st.session_state.current_user, old_pass):
                    st.error("La contraseña actual es incorrecta ❌")
                else:
                    new_hashed = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt())
                    try:
                        user_data = users_table.get_entity("usuario", st.session_state.current_user)
                        user_data["Password"] = new_hashed
                        users_table.upsert_entity(user_data)

                        st.success("Contraseña actualizada correctamente ✅")
                    except Exception as e:
                        st.error(f"No se pudo actualizar la contraseña: {e}")

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
