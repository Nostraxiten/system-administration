# system-administration

[![CI](https://github.com/Nostraxiten/system-administration/actions/workflows/ci.yml/badge.svg)](https://github.com/Nostraxiten/system-administration/actions/workflows/ci.yml)
[![Licencia: MIT](https://img.shields.io/badge/licencia-MIT-blue.svg)](LICENSE)
[![Lenguaje: Rust](https://img.shields.io/badge/rust-edici%C3%B3n%202021-orange.svg)](https://www.rust-lang.org)
[![Plataformas](https://img.shields.io/badge/plataformas-Linux%20%7C%20Windows%20Server-lightgrey.svg)](#compatibilidad)

Escáner interactivo de superficie de ataque y salud del sistema para un único
servidor Linux o Windows Server. Lee lo que la máquina ya sabe de sí misma,
clasifica lo que encuentra y devuelve un informe accionable sin obligar a leer
el volcado completo.

Read this in English: [README.md](README.md).

> [!CAUTION]
> **SIN SOPORTE PARA TERMUX.** Compilar desde el código fuente en
> Termux/Android falla con `error: crate `std` required to be available in
> rlib format, but was not found in this form` — una limitación del propio
> empaquetado de Rust en Termux (su `std` se distribuye solo como biblioteca
> dinámica, sin archivos `.rlib`), no algo que este proyecto pueda arreglar
> desde su código. Sigue el problema aguas arriba:
> [termux/termux-packages issues](https://github.com/termux/termux-packages/issues).
> No abras issues aquí sobre compilaciones en Termux; se cerrarán como no
> soportadas.

## Tabla de contenidos

- [Descripción](#descripción)
- [Alcance](#alcance)
- [Instalación](#instalación)
- [Uso](#uso)
- [Informes](#informes)
- [Módulos](#módulos)
- [Base de vulnerabilidades](#base-de-vulnerabilidades)
- [Privilegios](#privilegios)
- [Compatibilidad](#compatibilidad)
- [Compilación desde fuente](#compilación-desde-fuente)
- [Decisiones de diseño](#decisiones-de-diseño)
- [Limitaciones](#limitaciones)
- [Licencia](#licencia)

## Descripción

`system-administration` es un binario único y autocontenido, sin dependencias
de runtime. Está pensado para el momento en que un administrador hereda un
servidor y necesita saber deprisa qué hay expuesto, qué se está ejecutando,
quién puede entrar y si alguien ha dejado algo detrás.

Nueve módulos de diagnóstico se ejecutan en secuencia. Cada uno declara qué
revisó, qué encontró y con qué severidad, en una escala de tres niveles:
informativo, atención, crítico. El resumen sube al principio todos los
hallazgos de atención y críticos, de forma que leer el informe entero es
opcional y no obligatorio.

No hay flags, ni subcomandos, ni un `--help` que memorizar. Lanzar el
ejecutable inicia un recorrido guiado: elegir idioma, confirmar el sistema
detectado, ver el progreso del escaneo y decidir dónde va el informe.

## Alcance

La herramienta analiza la máquina en la que se ejecuta y nada más. No contiene
escaneo remoto, ni explotación, ni prueba de credenciales, ni movimiento
lateral, y no está construida para obtener un acceso que no se le haya dado.

La única operación de red de todo el programa es una petición HTTP `HEAD` a
`127.0.0.1` en los puertos donde ya hay un servidor web local escuchando, para
leer las cabeceras que ese servidor envía a cualquier visitante. No se contacta
con ningún otro equipo y ningún dato sale de la máquina.

## Instalación

### Una línea

Linux, cualquier distribución:

```
curl -fsSL https://raw.githubusercontent.com/Nostraxiten/system-administration/main/install.sh | sh
```

Windows Server, desde PowerShell:

```
irm https://raw.githubusercontent.com/Nostraxiten/system-administration/main/install.ps1 | iex
```

Cualquiera de los dos deja un único ejecutable en tu `PATH`, así que a partir de
ahí la herramienta se lanza por su nombre desde donde sea:

```
system-administration
```

El instalador descarga el binario publicado para tu plataforma cuando existe, y
si no compila el código fuente, que es lo que hace que funcione en
distribuciones y arquitecturas sin binario publicado. El binario de Linux está
enlazado estáticamente contra musl, así que no depende de la glibc de la
distribución. No se instala nada más: no se registra ningún servicio y no se
escribe ningún fichero hasta que se guarda un informe.

Dónde queda el ejecutable:

| Plataforma | Instalado por | Directorio |
| --- | --- | --- |
| Linux | `root` | `/usr/local/bin` |
| Linux | cualquier otro usuario | `~/.local/bin` |
| Windows | cualquier usuario | `%LOCALAPPDATA%\Programs\system-administration` |

### Opciones del instalador

En Linux son flags, después de `sh -s --`:

```
curl -fsSL https://raw.githubusercontent.com/Nostraxiten/system-administration/main/install.sh | sh -s -- --dir /opt/bin
```

| Flag | Variable de entorno | Efecto |
| --- | --- | --- |
| `--dir DIR` | `SYSADM_INSTALL_DIR` | instalar en otro directorio |
| `--version TAG` | `SYSADM_VERSION` | instalar una release concreta en vez de la última |
| `--source` | `SYSADM_FROM_SOURCE=1` | compilar siempre, sin descargar nunca |

En Windows solo valen las variables de entorno, porque `iex` no puede pasar
argumentos:

```
$env:SYSADM_INSTALL_DIR = 'C:\tools'
irm https://raw.githubusercontent.com/Nostraxiten/system-administration/main/install.ps1 | iex
```

### Instalación manual

Descarga el archivo de tu plataforma desde
[Releases](https://github.com/Nostraxiten/system-administration/releases),
compruébalo contra el `.sha256` publicado y coloca el ejecutable en cualquier
sitio que esté en el `PATH`:

```
# Linux
tar -xzf system-administration-x86_64-unknown-linux-musl.tar.gz
sudo install -m 755 system-administration /usr/local/bin/

# Windows Server
Expand-Archive system-administration-x86_64-pc-windows-msvc.zip -DestinationPath .
```

### Cómo desinstalarlo

El instalador añade un solo fichero, así que borrar ese fichero es toda la
desinstalación:

```
# Linux
rm -f /usr/local/bin/system-administration

# Windows Server
Remove-Item "$env:LOCALAPPDATA\Programs\system-administration" -Recurse
```

Ejecutarlo como `root` o como administrador es opcional pero recomendable;
consulta [Privilegios](#privilegios).

## Uso

Todo el recorrido es una secuencia de prompts, cada uno con un valor por
defecto seguro, así que el escaneo se puede completar pulsando Enter.

1. **Idioma.** Español o inglés. Todo lo que viene después, informe incluido,
   se genera en el idioma elegido.
2. **Confirmación del sistema.** El sistema se detecta automáticamente, desde
   `/etc/os-release` en Linux y desde `Win32_OperatingSystem` en Windows, y se
   muestra la evidencia en la que se basa la detección. Responder *no* abre un
   catálogo de sistemas soportados cuya primera entrada es una recomendación
   derivada de esa evidencia: gestor de paquetes, kernel o número de build,
   sistema de arranque. La elección nunca depende de reconocer una distribución
   por su nombre.
3. **Diagnóstico.** Los nueve módulos se ejecutan tras una barra de progreso
   que indica el módulo y la fase en curso.
4. **Informe.** Responder *sí* a guardar pide un nombre de carpeta (por defecto
   `sys`) y una ruta de destino; dejar la ruta vacía crea la carpeta junto al
   ejecutable. Responder *no* imprime el informe en pantalla, paginado por
   módulo.

## Informes

Guardar en una carpeta escribe texto plano UTF-8:

| Fichero | Contenido |
| --- | --- |
| `00-resumen-general.<idioma>.txt` | Cabecera, totales, índice de módulos y todos los hallazgos de atención y críticos |
| `01-users.<idioma>.txt` … `09-hosts.<idioma>.txt` | Un fichero por módulo: qué se revisó, qué se encontró, evidencia |
| `hallazgos.<idioma>.csv` | Cada hallazgo como una fila, los más graves primero, para un sistema de tickets o una hoja de cálculo |

El informe en pantalla contiene exactamente el mismo texto, coloreado por
severidad y paginado para que nada se escape sin leer.

Todos los informes llevan una cabecera con el equipo, el sistema detectado, el
kernel o build, la arquitectura, el tiempo encendido, la cuenta del operador,
si el escaneo tuvo privilegios elevados y cuánto duró.

## Módulos

| Módulo | Qué revisa |
| --- | --- |
| **Usuarios del sistema** | Cuentas locales y su shell, UID 0 o pertenencia al grupo de administradores, estado de la contraseña, grupos con privilegios y reglas de elevación sin contraseña, últimos accesos y cuentas dormidas, permisos de los directorios personales, claves SSH autorizadas |
| **Procesos en ejecución** | Inventario de procesos con propietario y línea de comandos, ruta real del binario, procesos cuyo binario fue borrado tras arrancar, ejecución desde rutas escribibles o temporales, nombres que imitan procesos del sistema, patrones de shell inversa en la línea de comandos, consumo anómalo de CPU y memoria, procesos ocultos del listado estándar |
| **Shells y persistencia** | Tareas programadas del sistema y por usuario, temporizadores y unidades, servicios fuera del conjunto empaquetado, entradas de autoarranque y scripts de inicio, ficheros de configuración de shell, histórico de comandos en busca de shells inversas, histórico deshabilitado o redirigido, bibliotecas precargadas globalmente, claves autorizadas como mecanismo de persistencia |
| **Archivos peligrosos o disfrazados** | Recorrido en profundidad de las rutas críticas, dobles extensiones, caracteres bidireccionales e invisibles en los nombres, espacios finales, binarios SUID/SGID fuera de la lista base, rutas críticas escribibles por todos, ficheros ocultos en directorios del sistema, ejecutables en directorios temporales, ficheros sin propietario válido, flujos de datos alternativos |
| **Puertos y red** | Puertos TCP y UDP en escucha con su dirección de enlace y proceso propietario, puertos expuestos en todas las interfaces, servicios de riesgo accesibles, conexiones establecidas y su extremo remoto, interfaces con direcciones, MAC, MTU y contadores, modo promiscuo, reenvío de paquetes IP, estado del cortafuegos local |
| **Servicios web** | Servidores web en ejecución y sus puertos, versión obtenida del binario, cabeceras leídas en bucle local, divulgación de versión, cabeceras de endurecimiento ausentes, listado de directorios habilitado, sitios por defecto sin personalizar, permisos de los ficheros de configuración, ajustes de PHP que filtran información |
| **Comprobador de versiones** | Versión del kernel o número de build, versión de la distribución y estado de soporte, inventario de paquetes del gestor nativo, versiones de los servicios expuestos, coincidencias con la base local de vulnerabilidades, actualizaciones pendientes, reinicio pendiente |
| **Logs de autenticación** | Localización y accesibilidad de cada fuente de log, autenticaciones fallidas agrupadas por origen, patrones de fuerza bruta y su desenlace, accesos correctos tras una ráfaga de fallos, accesos directos como root o administrador, uso y fallos de elevación de privilegios, creación de cuentas, logs vacíos, truncados o borrados |
| **IPs conectadas a la red** | Tabla ARP/NDP del propio equipo, puerta de enlace y subredes locales, nombres resueltos únicamente con ficheros locales, direcciones MAC repetidas en varias IP, entradas sin resolver, extremos remotos de las conexiones establecidas |

Los módulos viven en `src/modules/`, uno por fichero, tras un trait `Scanner`
común. Añadir uno consiste en escribir ese fichero y listarlo en
`modules::all()`.

## Base de vulnerabilidades

El comprobador de versiones contrasta contra `data/vuln-db.txt`, que se compila
dentro del binario. La comprobación funciona por tanto en una red aislada y no
consulta ningún servicio externo.

Para usar datos más recientes sin recompilar, coloca un fichero con el mismo
formato junto al ejecutable con el nombre `vuln-db.txt`, o apunta
`SYSADM_VULN_DB` a uno. Los registros externos tienen precedencia sobre los
incorporados con el mismo producto e identificador.

El formato es un registro por línea, separado por barras verticales:

```
tipo|producto|corregido_en|severidad|id|descripción
```

`tipo` es `pkg` para un paquete instalado, `svc` para un servicio en ejecución
identificado por su banner de versión, u `os` para una versión de distribución.
`corregido_en` es la primera versión no afectada; usa `desde..corregido` cuando
solo una ventana de versiones está afectada, para que una rama de soporte
prolongado que nunca tuvo el fallo no se marque solo por ser numéricamente
anterior a la corrección.

La coincidencia es por número de versión. Las distribuciones corrigen
habitualmente una vulnerabilidad con un parche retroportado sin subir la
versión, así que una coincidencia es un aviso para revisar el changelog del
paquete, no un veredicto. El informe lo indica en cada ejecución.

## Privilegios

El escaneo funciona sin privilegios elevados y lo indica en el informe,
listando las fuentes que no ha podido leer. Con privilegios elevados ve además:

- el estado de la contraseña en `/etc/shadow` y las ACL de las cuentas Windows;
- el proceso propietario de cada socket en escucha;
- las tareas programadas por usuario y los directorios personales ajenos;
- los logs de autenticación en la mayoría de configuraciones.

Los hallazgos que dependen del privilegio se redactan en consecuencia: un
puerto en escucha sin proceso identificable es informativo en un escaneo sin
privilegios y un hallazgo de atención en uno con ellos, porque solo en el
segundo caso significa algo.

## Compatibilidad

| Plataforma | Estado |
| --- | --- |
| Linux, glibc o musl, kernel 3.x en adelante | Soportado |
| Windows Server 2012 R2 en adelante | Soportado |
| Windows 10 y 11 | Soportado |
| Android (Termux), aarch64 y x86_64 | **No soportado.** La compilación desde el código fuente falla en el toolchain de Rust de Termux; ver el aviso al inicio |
| macOS, BSD | No soportado; la compilación falla con un mensaje explícito |

El recolector de Linux lee `/proc` y `/etc` directamente, así que se comporta
igual en un contenedor mínimo que en un servidor completo y sigue funcionando
cuando faltan `ss`, `netstat` o `systemctl`. Las herramientas externas se usan
solo como alternativa.

El recolector de Windows usa PowerShell para las consultas estructuradas, el
registro para los ganchos de arranque y las herramientas de consola clásicas
donde son más rápidas. Lee el inventario de software desde el registro de
desinstalación y no mediante `Win32_Product`, que reconfiguraría todos los
paquetes MSI instalados.

## Compilación desde fuente

Requiere Rust 1.82 o posterior.

```
git clone https://github.com/Nostraxiten/system-administration.git
cd system-administration
cargo build --release
```

El binario queda en `target/release/system-administration`.

Compilación cruzada y verificación de la otra plataforma:

```
rustup target add x86_64-pc-windows-msvc
cargo check --target x86_64-pc-windows-msvc
```

Pruebas, lints y formato, los mismos tres que ejecuta la CI:

```
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Decisiones de diseño

- **Una única superficie compartida.** `src/platform/mod.rs` declara los tipos
  y las firmas que ambos recolectores implementan. Los módulos se escriben una
  sola vez contra ella y `cfg(target_os)` decide qué recolector se compila, de
  forma que una compilación para Linux no contiene código de Windows ni al
  revés.
- **La traducción es un contrato de compilación.** Cada cadena visible es un
  campo de un catálogo `const` en `src/i18n/`. Añadir un idioma es un error de
  compilación hasta que están todos los campos, y ninguna cadena puede faltar
  en tiempo de ejecución.
- **Los hallazgos se agrupan antes de reportarse.** Cien entradas de un mismo
  directorio descomprimido entierran la única que importa, así que las
  categorías que aparecen en masa se resumen con un contador y una muestra.
- **Un falso positivo es un defecto.** Los enlaces simbólicos quedan fuera de
  las comprobaciones de permisos porque su modo siempre es `0777` y no
  significa nada; los identificadores de hilo quedan fuera de la detección de
  procesos ocultos porque todo hilo es direccionable pero no aparece en el
  listado; una cuenta bloqueada accesible por clave SSH es la configuración
  recomendada y no se reporta como problema.

## Limitaciones

- La comparación de versiones no ve los parches retroportados; consulta
  [Base de vulnerabilidades](#base-de-vulnerabilidades).
- El acceso en NTFS lo decide una ACL por fichero, y evaluar una por cada
  fichero de un servidor no es práctico, así que el recorrido de ficheros en
  Windows revisa nombres, ubicación y flujos, mientras que las ACL se
  comprueban individualmente en las rutas que importan.
- El inventario de vecinos es pasivo: informa de lo que el equipo ya conoce. Un
  host de la misma red con el que esta máquina nunca ha hablado no aparecerá,
  que es la consecuencia deliberada de no escanear la red.
- El análisis de logs lee los ficheros actuales y el journal; un archivo rotado
  y comprimido no se descomprime.

## Licencia

MIT. Consulta [LICENSE](LICENSE).
