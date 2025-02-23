// Función para manejar la redirección sin interrumpir el carrusel
function handleRedirect(url) {
    setTimeout(function () {
        window.location.href = url; // Redirección con pequeño retraso
    }, 200);
}

// Mostrar el formulario para ingresar el token
function showTokenInput(targetPage = "graficador/graficador.html") {
    const tokenContainer = document.getElementById("token-input-container");
    const storedToken = localStorage.getItem("authToken");
    const tokenExpiration = localStorage.getItem("tokenExpiration");

    if (storedToken && new Date() < new Date(tokenExpiration)) {
        // Si el token ya está almacenado y no ha caducado, redirigir directamente a la sección protegida
        window.location.href = targetPage;
    } else {
        // Si no hay token o ha caducado, mostrar el formulario y guardar la página de destino
        if (tokenContainer) {
            tokenContainer.style.display = "block";
            localStorage.setItem("redirectAfterLogin", targetPage); // Guardar página de destino
        } else {
            console.error("Elemento 'token-input-container' no encontrado en el DOM.");
        }
    }
}

// Verificar si el usuario está autenticado antes de redirigirlo
const isDevelopment = location.hostname === "localhost" || location.hostname === "127.0.0.1";
const serverUrl = isDevelopment ? "http://localhost:4000" : "https://skytrend.icu";

// Función para verificar el token ingresado
async function verifyToken() {
    const tokenInput = document.getElementById("token-input").value;
    const errorMessage = document.getElementById("error-message");

    if (!tokenInput) {
        errorMessage.style.display = "block";
        errorMessage.textContent = "Por favor, ingresa un token.";
        return;
    }

    try {
        const response = await fetch(`${serverUrl}/verify-token`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${tokenInput}`
            },
            credentials: "include"
        });

        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }

        const data = await response.json();

        if (data.valid) {
            // Guardar el token y su fecha de caducidad en localStorage
            localStorage.setItem("authToken", tokenInput);
            localStorage.setItem("tokenExpiration", data.expiration);

            // Redirigir a la página almacenada
            const targetPage = localStorage.getItem("redirectAfterLogin");
            if (targetPage) {
                window.location.href = targetPage;
                localStorage.removeItem("redirectAfterLogin"); // Limpiar el valor guardado
            } else {
                window.location.href = "graficador/graficador.html"; // Redirigir a una página por defecto
            }
        } else {
            errorMessage.style.display = "block";
            errorMessage.textContent = "Token inválido o expirado.";
        }
    } catch (error) {
        console.error("Error verificando el token:", error);
        errorMessage.style.display = "block";
        errorMessage.textContent = "Error al conectar con el servidor.";
    }
}

// Verificar si el formulario de generación de token existe antes de agregar el event listener
const generateTokenForm = document.getElementById("generateTokenForm");
if (generateTokenForm) {
    generateTokenForm.addEventListener("submit", async function (e) {
        e.preventDefault();

        const username = document.getElementById("username").value;
        const device_id = document.getElementById("device_id").value;
        const expiration = document.getElementById("expiration").value;

        try {
            const response = await fetch(`${serverUrl}/generate-token`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                credentials: "include",
                body: JSON.stringify({ username, device_id, expiration }),
            });

            if (response.ok) {
                const data = await response.json();
                console.log('Token generado:', data.token);
                document.getElementById('generatedToken').textContent = data.token;
                // Guardar el token y la fecha de caducidad en localStorage
                localStorage.setItem('authToken', data.token);
                localStorage.setItem('tokenExpiration', expiration); 
            } else {
                const errorData = await response.json();
                alert(`Error: ${errorData.message || 'Error al generar el token'}`);
            }
        } catch (error) {
            console.error('Error en la solicitud:', error);
            alert('Hubo un error al generar el token');
        }
    });
} else {
    console.warn("El formulario de generación de token no está presente en la página.");
}

// Llamar la verificación de autenticación al cargar la página
async function checkAuth() {
    const storedToken = localStorage.getItem("authToken");
    const tokenExpiration = localStorage.getItem("tokenExpiration");

    if (!storedToken || !tokenExpiration || new Date() >= new Date(tokenExpiration)) {
        // Si no hay token, no hay fecha de caducidad, o el token ha caducado, eliminar y no hacer nada
        localStorage.removeItem("authToken");
        localStorage.removeItem("tokenExpiration");
        return;
    }

    try {
        const response = await fetch(`${serverUrl}/verify-token`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${storedToken}`
            },
            credentials: "include"
        });

        const data = await response.json();
        if (!data.valid) {
            // Si el token no es válido, eliminarlo del localStorage
            localStorage.removeItem("authToken");
            localStorage.removeItem("tokenExpiration");
        }
    } catch (error) {
        console.error("Error verificando el token:", error);
    }
}

async function deleteToken(tokenToDelete) {
    if (!tokenToDelete) {
        alert("Por favor, ingresa un token válido para eliminar.");
        return;
    }

    try {
        const response = await fetch(`${serverUrl}/delete-token`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ tokenToDelete })
        });

        const data = await response.json();

        if (response.ok) {
            alert(data.message);
        } else {
            alert(`Error: ${data.error}`);
        }
    } catch (error) {
        console.error("Error eliminando el token:", error);
        alert("Hubo un error al eliminar el token.");
    }
}

// Función para cerrar el formulario de ingreso de token
function closeTokenForm() {
    const tokenContainer = document.getElementById("token-input-container");
    if (tokenContainer) {
        tokenContainer.style.display = "none";
    }
}

checkAuth();