from flask import Flask, render_template, Response
import os
import sqlite3
import pandas as pd
import chrome
import firefox
import json
import base64

app = Flask(__name__, template_folder="templates")
app._static_folder = os.path.abspath("templates/static/")

# Conexión a la base de datos de cookies de Chrome
ch = sqlite3.connect("C:\\Users\\User\\Desktop\\Seguridad_Informatica_Proyecto\\source\\Chrome\\Cookies.sqlite")
df_c = pd.read_sql_query("SELECT * from cookies", ch)

# Conexión a la base de datos de cookies de Firefox
fx = sqlite3.connect(
    "C:\\Users\\User\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\fmouarnu.default-release\\cookies.sqlite"
)
df_f = pd.read_sql_query("SELECT * from moz_cookies", fx)

# Codificar los datos de las cookies de Chrome
df_c_encoded = df_c.applymap(lambda x: base64.b64encode(x).decode('utf-8') if isinstance(x, bytes) else x)

# Codificar los datos de las cookies de Firefox
df_f_encoded = df_f.applymap(lambda x: base64.b64encode(x).decode('utf-8') if isinstance(x, bytes) else x)

@app.route("/dashboard.js")
def dashboard_data():
    # Obtener los datos
    suma_paginas_web = chrome.numero_paginas_web(df_c) + firefox.numero_paginas_web(df_f)
    num_cookies_chrome = chrome.Numero_Cookies(df_c)
    num_cookies_firefox = firefox.numero_total_cookies(df_f)

    top_paginas_chrome = chrome.top_paginas(df_c)
    top_paginas_firefox = firefox.top_paginas(df_f)
    top_paginas = pd.concat([top_paginas_chrome, top_paginas_firefox])
    firefox_Users = firefox.main()

    # Preparar los datos para la respuesta
    data = {
        "suma_paginas_web": suma_paginas_web,
        "num_cookies_chrome": num_cookies_chrome,
        "num_cookies_firefox": num_cookies_firefox,
        "top_ten_paginas": top_paginas.to_dict(orient="records"),
        "firefox_Users": firefox_Users.to_dict(orient="records"),
        "Cookies_Fire": df_f_encoded.to_dict(orient="records"),
        "Cookies_Chr": df_c_encoded.to_dict(orient="records"),
    }

    # Crear una respuesta JSON
    response = Response(json.dumps(data), mimetype="application/json")
    return response

@app.route("/", methods=["GET", "POST"])
def home():
    return render_template("layouts/index.html")

# Main del programa
if __name__ == "__main__":
    app.run(debug=True)