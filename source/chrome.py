import pandas as pd
import sqlite3

import shutil
import os

# Rutas de los archivos
archivo_origen = "C:\\Users\\sebas\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies"
archivo_destino = "C:\\Users\\sebas\\Desktop\\Proyecto_SI\\Chrome\\Cookies.sqlite"

# Copiar el archivo con la nueva extensión
shutil.copyfile(archivo_origen, archivo_destino)

ch = sqlite3.connect("C:\\Users\\sebas\\Desktop\\Proyecto_SI\\Chrome\\Cookies.sqlite")
df_c = pd.read_sql_query("SELECT * from cookies", ch)


def Numero_Cookies(df):
    num_cookies = len(df)
    return num_cookies


def numero_paginas_web(df):
    website_columns = ["host_key", "top_frame_site_key"]
    websites = pd.concat([df[col] for col in website_columns])
    num_unique_websites = websites.nunique()
    return num_unique_websites


def top_paginas(df):
    visitas_por_pagina = df["host_key"].value_counts().reset_index()
    visitas_por_pagina.columns = ["Pagina", "Visitas"]
    top_5_paginas = visitas_por_pagina.head(5)

    return top_5_paginas
