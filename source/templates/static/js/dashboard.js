$(document).ready(function () {
  $.ajax({
    url: "/dashboard.js",
    type: "GET",
    dataType: "json",
    success: function (data) {
      console.log("Numero de paginas Web:", data.suma_paginas_web);
      console.log("Número de cookies de Chrome:", data.num_cookies_chrome);
      console.log("Número de cookies de Firefox:", data.num_cookies_firefox);
      console.log("Top 10 paginas", data.top_ten_paginas);
      console.log("Usuarios de Firefox", data.firefox_Users);
      console.log("Cookies Firefox", data.Cookies_Fire);
      console.log("Cookies Chrome", data.Cookies_Chr);

      // Configurar y renderizar el gráfico para cookies de Chrome
      var chromeCookiesChart = new Chart(
        document.getElementById("chromeCookiesChart").getContext("2d"),
        {
          type: "bar",
          data: {
            labels: ["Cookies de Chrome"],
            datasets: [
              {
                label: "Cookies de Chrome",
                data: [data.num_cookies_chrome],
                backgroundColor: "rgba(255, 99, 132, 0.2)",
                borderColor: "rgba(255, 99, 132, 1)",
                borderWidth: 1,
              },
            ],
          },
          options: {
            scales: {
              y: {
                beginAtZero: true,
              },
            },
          },
        }
      );

      // Configurar y renderizar el gráfico para cookies de Firefox
      var firefoxCookiesChart = new Chart(
        document.getElementById("firefoxCookiesChart").getContext("2d"),
        {
          type: "bar",
          data: {
            labels: ["Cookies de Firefox"],
            datasets: [
              {
                label: "Cookies de Firefox",
                data: [data.num_cookies_firefox],
                backgroundColor: "rgba(54, 162, 235, 0.2)",
                borderColor: "rgba(54, 162, 235, 1)",
                borderWidth: 1,
              },
            ],
          },
          options: {
            scales: {
              y: {
                beginAtZero: true,
              },
            },
          },
        }
      );

      // Configurar y renderizar el gráfico para numero total de paginas web
      var NumPagesChart = new Chart(
        document.getElementById("NumPagesChart").getContext("2d"),
        {
          type: "bar",
          data: {
            labels: ["Numero de paginas web"],
            datasets: [
              {
                label: "Numero de paginas web",
                data: [data.suma_paginas_web],
                backgroundColor: "rgba(162, 241, 14, 0.2)",
                borderColor: "rgba(162, 241, 14, 1)",
                borderWidth: 1,
              },
            ],
          },
          options: {
            scales: {
              y: {
                beginAtZero: true,
              },
            },
          },
        }
      );

      // Configurar y renderizar el gráfico para top ten paginas
      var labels = data.top_ten_paginas.map(function (item) {
        return item.Pagina;
      });
      var visitsData = data.top_ten_paginas.map(function (item) {
        return item.Visitas;
      });
      var topTenPagesChart = new Chart(
        document.getElementById("topTenPagesChart").getContext("2d"),
        {
          type: "bar",
          data: {
            labels: labels,
            datasets: [
              {
                label: "Visitas",
                data: visitsData,
                backgroundColor: "rgba(206, 14, 241, 0.2)",
                borderColor: "rgba(206, 14, 241, 1)",
                borderWidth: 1,
              },
            ],
          },
          options: {
            scales: {
              y: {
                beginAtZero: true,
              },
            },
          },
        }
      );

      // Configurar y renderizar el gráfico para los Usuarios de Firefox
      var userListTable = $(".user-list-table");

      var headerRow = $("<tr>");
      headerRow.append($("<th>").text("Usuario"));
      headerRow.append($("<th>").text("Contraseña"));
      userListTable.append(headerRow);
      data.firefox_Users.forEach(function (item) {
        var row = $("<tr>");
        row.append($("<td>").text(item.user));
        row.append($("<td>").text(item.password));
        userListTable.append(row);
      });

      // Configurar y renderizar el gráfico de los usuarios
      var backgroundColor;
      if (data.firefox_Users.length === 0) {
        backgroundColor = ["black"];
      } else if (
        data.firefox_Users.length >= 1 &&
        data.firefox_Users.length <= 3
      ) {
        backgroundColor = ["red"];
      } else if (
        data.firefox_Users.length >= 4 &&
        data.firefox_Users.length <= 6
      ) {
        backgroundColor = ["yellow"];
      } else {
        backgroundColor = ["green"];
      }

      var data = {
        labels: ["Usuarios Encontrados"],
        datasets: [
          {
            data: [data.firefox_Users.length],
            backgroundColor: backgroundColor,
          },
        ],
      };

      // Configurar las opciones del gráfico de pastel
      var options = {
        responsive: true,
        maintainAspectRatio: false,
      };

      // Obtener el contexto del lienzo del gráfico de pastel
      var ctx = document
        .getElementById("firefoxUsersPieChart")
        .getContext("2d");

      // Crear el gráfico de pastel
      var firefoxUsersPieChart = new Chart(ctx, {
        type: "pie",
        data: data,
        options: options,
      });
    },
    error: function (xhr, status, error) {
      console.error("Error al obtener los datos del dashboard:", error);
    },
  });
});

$(document).ready(function () {
  // Manejar el envío del formulario
  $("#browserForm").submit(function (event) {
    // Prevenir la acción predeterminada del formulario
    event.preventDefault();

    // Obtener el valor seleccionado del select
    var selectedBrowser = $("#browserSelect").val();

    // Verificar si se seleccionó Firefox
    if (selectedBrowser === "firefox") {
      // Obtener los datos del dashboard
      $.ajax({
        url: "/dashboard.js",
        type: "GET",
        dataType: "json",
        success: function (data) {
          // Obtener el modal y la tabla dentro del modal
          var modal = $("#exampleModal");
          var table = $('<table class="table"></table>');

          // Crear la cabecera de la tabla
          var thead = $("<thead></thead>").appendTo(table);
          var headerRow = $("<tr></tr>").appendTo(thead);
          $("<th>ID</th>").appendTo(headerRow);
          $("<th>Nombre</th>").appendTo(headerRow);
          $("<th>Host</th>").appendTo(headerRow);
          $("<th>Path</th>").appendTo(headerRow);
          $("<th>Expiración</th>").appendTo(headerRow);

          // Crear el cuerpo de la tabla
          var tbody = $("<tbody></tbody>").appendTo(table);

          // Iterar sobre los datos de las cookies y agregar filas a la tabla
          data.Cookies_Fire.forEach(function (cookie) {
            var row = $("<tr></tr>").appendTo(tbody);
            $("<td>" + cookie.id + "</td>").appendTo(row);
            $("<td>" + cookie.name + "</td>").appendTo(row);
            $("<td>" + cookie.host + "</td>").appendTo(row);
            $("<td>" + cookie.path + "</td>").appendTo(row);
            $(
              "<td>" + new Date(cookie.expiry * 1000).toLocaleString() + "</td>"
            ).appendTo(row);
          });

          // Limpiar el contenido del modal y agregar la tabla
          modal.find(".modal-body").empty().append(table);

          // Mostrar el modal
          modal.modal("show");
        },
        error: function (xhr, status, error) {
          console.error("Error al obtener los datos del dashboard:", error);
        },
      });
    }
  });
});

$(document).ready(function () {
  // Manejar el envío del formulario
  $("#browserForm").submit(function (event) {
      event.preventDefault();
      var selectedBrowser = $("#browserSelect").val();
      if (selectedBrowser === "chrome") {
          $.ajax({
              url: "/dashboard.js",
              type: "GET",
              dataType: "json",
              success: function (data) {
                  // Obtener el modal y la tabla dentro del modal
                  var modal = $("#cookiesModal");
                  var table = $('<table class="table"></table>');

                  // Crear la cabecera de la tabla
                  var thead = $("<thead></thead>").appendTo(table);
                  var headerRow = $("<tr></tr>").appendTo(thead);
                  $("<th>Nombre</th>").appendTo(headerRow);
                  $("<th>Valor</th>").appendTo(headerRow);
                  $("<th>Host</th>").appendTo(headerRow);
                  $("<th>Path</th>").appendTo(headerRow);
                  $("<th>Expira</th>").appendTo(headerRow);
                  $("<th>Último acceso</th>").appendTo(headerRow);

                  // Crear el cuerpo de la tabla
                  var tbody = $("<tbody></tbody>").appendTo(table);
                  // Agregar fila con datos de la cookie
                  data.Cookies_Chr.forEach(function (cookie) {
                    var row = $("<tr></tr>").appendTo(tbody);
                    $("<td>" + (cookie.name.length > 15 ? cookie.name.substring(0, 15) + '...' : cookie.name) + "</td>").appendTo(row);
                    $("<td>" + (cookie.encrypted_value.length > 15 ? cookie.encrypted_value.substring(0, 15) + '...' : cookie.encrypted_value) + "</td>").appendTo(row);
                    $("<td>" + cookie.host_key + "</td>").appendTo(row);
                    $("<td>" + cookie.path + "</td>").appendTo(row);
                    $("<td>" + new Date(cookie.expires_utc).toLocaleString() + "</td>").appendTo(row);
                    $("<td>" + new Date(cookie.last_access_utc).toLocaleString() + "</td>").appendTo(row);
                  });
                  

                  // Limpiar el contenido del modal y agregar la tabla
                  modal.find(".modal-body").empty().append(table);

                  // Mostrar el modal
                  modal.modal("show");
              },
              error: function (xhr, status, error) {
                  console.error("Error al obtener los datos del dashboard:", error);
              },
          });
      }
  });
});