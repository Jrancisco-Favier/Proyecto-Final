<?php
$host = 'localhost';
$usuario = 'root';
$clave = '';
$bd = 'iliana';

$conn = new mysqli($host, $usuario, $clave, $bd);

if ($conn->connect_error) {
    die("Error de conexión: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {

    $correo = trim($_POST['correo'] ?? '');
    $contrasena = trim($_POST['contraseña'] ?? '');
    $nombre_completo = trim($_POST['nombre'] ?? '');

    if ($correo == '' || $contrasena == '' || $nombre_completo == '') {
        echo "<script>alert('Faltan datos en el formulario');window.location.href='registro.html';</script>";
        exit;
    }

    if (!filter_var($correo, FILTER_VALIDATE_EMAIL)) {
        echo "<script>alert('Correo no válido');window.location.href='registro.html';</script>";
        exit;
    }

    $verificar = $conn->prepare("SELECT id FROM usuarios WHERE correo = ?");
    $verificar->bind_param("s", $correo);
    $verificar->execute();
    $verificar->store_result();

    if ($verificar->num_rows > 0) {
        echo "<script>alert('Este correo ya está registrado');window.location.href='index.html';</script>";
    } else {
        $contrasena_segura = password_hash($contrasena, PASSWORD_DEFAULT);
        $ya_voto_personeria = 0;
        $ya_voto_contraloria = 0;

        $stmt = $conn->prepare("INSERT INTO usuarios (correo, contrasena, nombre_completo, ya_voto_personeria, ya_voto_contraloria) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("sssii", $correo, $contrasena_segura, $nombre_completo, $ya_voto_personeria, $ya_voto_contraloria);

        if ($stmt->execute()) {
            echo "<script>alert('Registro exitoso');window.location.href='index.html';</script>";
        } else {
            echo "<script>alert('Error al registrar');window.location.href='registro.html';</script>";
        }

        $stmt->close();
    }

    $verificar->close();
}

$conn->close();
?>