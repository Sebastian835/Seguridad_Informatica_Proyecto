from flask import Flask, render_template, Response
import os
import sqlite3
import pandas as pd
import chrome
import firefox
import json
import io
import sys


app = Flask(__name__, template_folder="templates")
app._static_folder = os.path.abspath("templates/static/")

# COOKIES CHROME
ch = sqlite3.connect("C:\\Users\\sebas\\Desktop\\Proyecto_SI\\Chrome\\Cookies.sqlite")
df_c = pd.read_sql_query("SELECT * from cookies", ch)

# COOKIES FIREFOX
fx = sqlite3.connect(
    "C:\\Users\\sebas\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\odo3fkvm.default-release\\cookies.sqlite"
)
df_f = pd.read_sql_query("SELECT * from moz_cookies", fx)
print(df_f.columns)


@app.route("/dashboard.js")
def dashboard_data():
    # Obtener los datos
    suma_paginas_web = chrome.numero_paginas_web(df_c) + firefox.numero_paginas_web(
        df_f
    )
    num_cookies_chrome = chrome.Numero_Cookies(df_c)
    num_cookies_firefox = firefox.numero_total_cookies(df_f)

    top_paginas_chrome = chrome.top_paginas(df_c)
    top_paginas_firefox = firefox.top_paginas(df_f)
    top_paginas = pd.concat([top_paginas_chrome, top_paginas_firefox])
    firefox_Users = firefox.main()

    data = {
        "suma_paginas_web": suma_paginas_web,
        "num_cookies_chrome": num_cookies_chrome,
        "num_cookies_firefox": num_cookies_firefox,
        "top_ten_paginas": top_paginas.to_dict(orient="records"),
        "firefox_Users": firefox_Users.to_dict(orient="records"),
        "Cookies_Fire": df_f.to_dict(orient="records"),
    }

    response = Response(json.dumps(data), mimetype="application/json")
    return response


@app.route("/", methods=["GET", "POST"])
def home():
    return render_template("layouts/index.html")


# main del programa
if __name__ == "__main__":
    app.run(debug=True)
