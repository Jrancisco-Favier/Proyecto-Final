<?php
$host = 'localhost';
$usuario = 'root';
$clave = '';
$bd = 'iana';

$conn = new mysqli($host, $usuario, $clave, $bd);

if ($conn->connect_error) {
    die("Error de conexión: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {

    $nombre = trim($_POST['nombre'] ?? '');
    $correo = trim($_POST['correo'] ?? '');
    $contrasena = trim($_POST['contrasena'] ?? '');
    $numero = trim($_POST['numero'] ?? '');
    $direccion = trim($_POST['direccion'] ?? '');

    if ($nombre == '' || $correo == '' || $contrasena == '' || $numero == '' || $direccion == '') {
        echo "<script>alert('Faltan datos en el formulario');window.location.href='registro.html';</script>";
        exit;
    }

    if (!filter_var($correo, FILTER_VALIDATE_EMAIL)) {
        echo "<script>alert('Correo no válido');window.location.href='registro.html';</script>";
        exit;
    }

    $verificar = $conn->prepare("SELECT id FROM usuario WHERE correo = ?");
    $verificar->bind_param("s", $correo);
    $verificar->execute();
    $verificar->store_result();

    if ($verificar->num_rows > 0) {
        echo "<script>alert('Este correo ya está registrado');window.location.href='index.html';</script>";
    } else {
        $contrasena_segura = password_hash($contrasena, PASSWORD_DEFAULT);

        $stmt = $conn->prepare("INSERT INTO usuario (nombre, numero, direccion, correo, contrasena) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("sssss", $nombre, $numero, $direccion, $correo, $contrasena_segura);

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