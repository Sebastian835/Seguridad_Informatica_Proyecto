# Importar las bibliotecas necesarias
import pandas as pd  # Biblioteca para el manejo y análisis de datos
import sqlite3       # Biblioteca para interactuar con bases de datos SQLite
import shutil        # Biblioteca para operaciones de copia de archivos
import os            # Biblioteca para operaciones del sistema operativo

# Definir las rutas de los archivos de origen y destino
archivo_origen = "C:\\Users\\User\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies"
archivo_destino = "C:\\Users\\User\\Desktop\\Seguridad_Informatica_Proyecto\\source\\Chrome\\Cookies.sqlite"

# Copiar el archivo de origen a la ubicación de destino con una nueva extensión
shutil.copyfile(archivo_origen, archivo_destino)

# Conectar a la base de datos SQLite que contiene las cookies de Chrome
ch = sqlite3.connect("C:\\Users\\User\\Desktop\\Seguridad_Informatica_Proyecto\\source\\Chrome\\Cookies.sqlite")

# Leer las cookies de la base de datos SQLite y almacenarlas en un DataFrame de Pandas
df_c = pd.read_sql_query("SELECT * from cookies", ch)

# Función para calcular el número total de cookies en el DataFrame
def Numero_Cookies(df):
    num_cookies = len(df)  # Obtener la longitud del DataFrame, que corresponde al número de filas (cookies)
    return num_cookies

# Función para calcular el número total de páginas web únicas en el DataFrame
def numero_paginas_web(df):
    # Seleccionar las columnas relevantes que identifican las páginas web
    website_columns = ["host_key", "top_frame_site_key"]
    # Concatenar las columnas relevantes y encontrar el número de valores únicos
    websites = pd.concat([df[col] for col in website_columns])
    num_unique_websites = websites.nunique()  # Contar los valores únicos, que corresponden al número de páginas web únicas
    return num_unique_websites

# Función para encontrar las top 5 páginas web con más visitas
def top_paginas(df):
    # Contar las visitas para cada página y ordenarlas en orden descendente
    visitas_por_pagina = df["host_key"].value_counts().reset_index()
    # Renombrar las columnas para mayor claridad
    visitas_por_pagina.columns = ["Pagina", "Visitas"]
    # Seleccionar las primeras 5 páginas con más visitas
    top_5_paginas = visitas_por_pagina.head(5)
    return top_5_paginas
