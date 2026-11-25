# Windows Firewall Guard

Herramienta defensiva para auditar Microsoft Defender Firewall sin sustituirlo. Hace una consulta puntual y termina: no instala servicios, controladores ni un proxy, no captura paquetes y no transmite datos. No se ha medido el impacto de las reglas en un PC real; este proyecto no añade un proceso al tráfico diario.

## Uso seguro

Requiere Python 3.10+. La auditoría real requiere Windows y el módulo NetSecurity. No cambia ninguna regla.

```text
python firewall_guard.py --demo
python -m unittest -v
python firewall_guard.py
```

Cada informe lista los tres perfiles de configuración de ActiveStore, no cuáles redes están conectadas. Reporta firewall desactivado, entrada permitida por defecto, salida permitida por defecto, valores desconocidos y conteos de reglas. Una regla de entrada aplicable a cualquier perfil puede estar limitada a ciertos puertos, apps o direcciones: el conteo pide revisión, no demuestra exposición. Un resultado limpio no demuestra ausencia de fugas. Salidas: 0 sin hallazgo alto (puede haber revisiones); 1 con hallazgo alto; 2 si la consulta o los datos fallan.

No se recopilan nombres de reglas, rutas de programas, IP, usuarios, contenido de tráfico ni datos de la empresa. Aun así, el informe real revela postura de seguridad: mantenlo local. Para GitHub usa exclusivamente la salida de `--demo`.

## Aplicar una regla real, solo en una VM personal de prueba

Audita primero. Si el equipo está administrado, no cambies sus políticas: pide aprobación a TI. Durante el lab, usa una consola local elevada, toma una instantánea de la VM y usa únicamente una aplicación de prueba propia. No uses navegador, VPN, Windows Update, sincronización ni un servicio del sistema como aplicación de prueba.

1. Confirma que la app de prueba llega a un servicio propio/autorizado y que la red de prueba está en perfil **Private**. Mantén constantes la app, el destino y la red.
2. En PowerShell, cambia la ruta de ejemplo por la ruta absoluta de tu aplicación de prueba. Usa vista previa antes de aplicar. Si ya existe una regla con ese nombre, **detente**: no la borres ni la sobrescribas.

```powershell
$id = 'Portfolio-WFG-Lab-Outbound-Block'
$app = 'C:\Lab\demo-app.exe'
if (-not (Test-Path -LiteralPath $app -PathType Leaf)) { throw 'Ruta de prueba no válida' }
if (Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object Name -eq $id) {
    throw 'Ya existe una regla con este nombre; no se hicieron cambios'
}
$rule = @{
    Name = $id; DisplayName = $id; Program = $app
    Direction = 'Outbound'; Action = 'Block'; Profile = 'Private'
    PolicyStore = 'PersistentStore'
}
New-NetFirewallRule @rule -WhatIf
# Solo después de revisar la vista previa, en la VM:
# New-NetFirewallRule @rule
```

3. Reinicia solo la aplicación de prueba para que abra una conexión nueva. Comprueba que falla mientras una app de control sigue funcionando. Si la política administrada no acepta reglas locales, no intentes modificarla. Revierte únicamente si tú creaste la regla en el paso anterior:

```powershell
Remove-NetFirewallRule -PolicyStore PersistentStore -Name $id -WhatIf
# Si coincide exactamente con tu regla de laboratorio:
# Remove-NetFirewallRule -PolicyStore PersistentStore -Name $id
```

4. Comprueba que la app vuelve a conectar. Registra antes/bloqueo/reversión y tiempo de ejecución de la auditoría, con datos de prueba. No publiques capturas de un endpoint real.

## Protección de información

Para el PC de trabajo, empieza por mantener el firewall activo, revisar permisos, usar cifrado de disco y MFA, y acordar con TI qué servicios y carpetas pueden sincronizarse. Si necesitas impedir envíos de archivos por aplicaciones autorizadas o HTTPS, evalúa controles DLP con la empresa. No bloquees toda la salida sin inventario, pruebas y reversión: puedes cortar DNS, actualizaciones, VPN y trabajo. El firewall no sustituye DLP ni protege por sí solo contra todas las filtraciones.

[Microsoft: funcionamiento del firewall](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/) · [Microsoft: administración desde PowerShell](https://learn.microsoft.com/es-es/windows/security/operating-system-security/network-security/windows-firewall/configure-with-command-line)

**Validación:** unit tests y demo sintética; el funcionamiento en Windows y la prueba de una regla real deben verificarse en una VM antes de usar este proyecto como evidencia de implementación.
