# Manifiesto QuantumSSH

> *Por qué construimos esto, para quién lo construimos, y qué esperamos que se convierta.*

---

## El punto de partida

SSH es el protocolo invisible que sostiene internet. Cada despliegue, cada servidor, cada pipeline de CI, cada dispositivo embebido con un plano de control habla SSH. La implementación dominante —OpenSSH— es una obra maestra de la ingeniería en C. Le debemos décadas de internet funcional.

Pero OpenSSH carga dos pesos que crecen juntos:

**El primero es el lenguaje.** Son aproximadamente 120.000 líneas de C escritas con disciplina ejemplar, pero el ecosistema del que dependen —shells, módulos PAM, librerías de compresión, primitivas del sistema operativo— ha producido una secuencia constante de CVEs. La puerta trasera de `xz-utils` en 2024, que apuntaba directamente al camino de autenticación de OpenSSH a través de una dependencia de compresión, dejó claro lo frágil que se ha vuelto la cadena de confianza.

**El segundo es el reloj cuántico.** Hoy, el intercambio de claves SSH se apoya en Diffie-Hellman sobre curvas elípticas y RSA. Ambos caen frente al algoritmo de Shor en una computadora cuántica suficientemente capaz. La amenaza que importa hoy no es *"las computadoras cuánticas existirán mañana"*. La amenaza es **harvest-now-decrypt-later**: agencias de inteligencia de varios gobiernos están grabando tráfico SSH cifrado en este momento, apostando a poder descifrarlo en 10 o 15 años. Cualquier sesión que proteja información de larga duración —código fuente, secretos de infraestructura, datos bancarios regulados, correspondencia personal— ya está comprometida.

OpenSSH está respondiendo. Desde la versión 9.0 incluye `sntrup761x25519-sha512@openssh.com` como intercambio híbrido. La 10.0 hizo de ML-KEM el default. GitHub habilitó SSH post-cuántico híbrido (el mismo `sntrup761x25519-sha512@openssh.com`, no ML-KEM) el 17 de septiembre de 2025, seleccionado automáticamente sin configuración para clientes modernos. La dirección es correcta. Pero la implementación es agregar criptografía post-cuántica encima de una base de 25 años, en un lenguaje sin garantías de memoria, arrastrando algoritmos heredados, superficies de configuración y casos límite que ningún equipo —por bueno que sea— puede auditar exhaustivamente.

Pensamos que existe espacio para una respuesta diferente. Y pensamos que esa respuesta tiene que ser **genuinamente abierta** desde su primera línea de código.

---

## La hipótesis

QuantumSSH no es un fork de OpenSSH. No es una alternativa drop-in. No queremos competir con OpenSSH en su terreno.

QuantumSSH es la respuesta a una pregunta distinta: **si tuviéramos que construir un servidor SSH desde cero hoy, sabiendo lo que sabemos sobre criptografía post-cuántica, sabiendo lo que sabemos sobre seguridad de memoria, sabiendo lo que sabemos sobre los próximos treinta años de infraestructura crítica, ¿qué construiríamos?**

La respuesta corta: un servidor escrito en Rust, post-cuántico por defecto, sin legacy, y permanentemente abierto.

La respuesta larga es este proyecto.

---

## Cinco compromisos

**Memoria segura por construcción.** Rust no es una opinión estética. Es el primer lenguaje de sistemas con el rendimiento de C, garantías de seguridad de memoria en tiempo de compilación, y herramientas modernas. El `borrow checker` no es un impuesto: es la diferencia entre dormir tranquilo y leer notas de seguridad cada lunes.

**Post-cuántico por defecto, no por opción.** El intercambio de claves híbrido (ML-KEM + X25519) es lo único que soportamos. Quien usa QuantumSSH no necesita saber qué significa post-cuántico. La cosa correcta pasa sola.

**Cero legacy.** Sin SSH-1. Sin RSA-1024. Sin DSA. Sin modos CBC. Sin `diffie-hellman-group1-sha1`. Sin autenticación por contraseña en el perfil por defecto. Nos rehusamos a heredar 25 años de *"sigue ahí porque el router de alguien lo necesita"*. Y "legacy" no es solo esta lista fija: es el **piso permanente**, y sobre él, todo primitivo criptográfico que NIST o IETF haya **prohibido** (*disallowed*). La **deprecación** de un algoritmo activa su migración gestionada; la **prohibición** marca la línea de legacy que no cruzamos. La mitad clásica de un híbrido (X25519, Ed25519) **no** es legacy mientras el híbrido sea el mecanismo: cero legacy prohíbe lo clásico-*solo*, no lo clásico-*más*-PQ. El procedimiento de migración está en [RFC-0007](docs/rfcs/0007-cryptographic-primitive-migration-procedure.md); esta definición, en [RFC-0009](docs/rfcs/0009-zero-legacy-moving-frontier.md).

**Superficie pequeña, bordes afilados.** El MVP soporta autenticación por llave pública, ejecución de comandos, shell interactiva con PTY, y SFTP. Punto. Port forwarding, X11 forwarding, agent forwarding y todo lo demás son opt-in explícitos, detrás de feature flags y configuración. Cada feature es un compromiso permanente de mantener, auditar, y razonar.

**Abierto, y permaneciendo abierto.** Apache 2.0 desde el primer commit. Sin source-available. Sin NDAs. Sin "edición enterprise" con código distinto. Sin relicensing futuro. Esto no es un detalle de licencia, es estructural al proyecto. La infraestructura criptográfica gana confianza con tiempo, escrutinio, y la posibilidad de que cualquier persona pueda verificar las afirmaciones. La tercera condición no es negociable.

---

## Lo que no somos

Para que las expectativas estén alineadas:

- **No somos un drop-in de OpenSSH.** Los archivos de configuración, las flags de línea de comandos y los comportamientos van a divergir donde divergir produzca un sistema más seguro o más simple.
- **No somos compatibles con clientes viejos.** Si tu cliente no habla SSH moderno con híbrido post-cuántico, no se conecta. Punto.
- **No somos el SSH más rápido.** OpenSSH es lo suficientemente rápido. Nuestro objetivo es corrección, después seguridad, después ergonomía. El rendimiento viene después.
- **No somos un vehículo de investigación académica.** Usamos los algoritmos que NIST estandarizó y a los que la comunidad converge. No inventamos criptografía. Implementarla es difícil; inventarla está fuera de discusión.
- **No somos un producto comercial disfrazado de open source.** Si algún día existe un servicio comercial alrededor del proyecto —soporte, hosting, integración— vivirá *alrededor* del código abierto, no *encima* de un código cerrado. El servidor mismo se queda libre. Para siempre.

---

## Por qué ahora

Tres ventanas se están abriendo al mismo tiempo:

**La ventana técnica.** Rust llegó a la madurez para sistemas críticos. Cloudflare reemplazó nginx con Pingora (Rust) y reportó reducciones significativas de CPU y memoria. Microsoft reescribe partes de Windows en Rust. El kernel de Linux acepta drivers en Rust. ISRG —la fundación detrás de Let's Encrypt— financia reescrituras de `sudo`, `ntpd` y el stack DNS a través de su proyecto [Prossimo](https://www.memorysafety.org/). SSH todavía no ha tenido su momento como infraestructura abierta, segura por construcción y post-cuántica. Pensamos que llegó tarde.

**La ventana regulatoria.** La NSA, en su guía CNSA 2.0, exige criptografía post-cuántica en sistemas de seguridad nacional para 2033. ENISA recomienda migración antes de 2030. Reguladores bancarios en UK, EU y Estados Unidos están emitiendo guías de "preparación cuántica". En Latinoamérica esto va a llegar. Cuando llegue, los equipos van a estar buscando herramientas diseñadas para ese mundo.

**La ventana de oportunidad.** Hay esfuerzos previos en este espacio. OpenSSH integra post-cuántico incrementalmente. Open Quantum Safe mantiene forks de investigación. Microsoft tiene un fork experimental para Azure. Existe también `qssh`, otro proyecto en Rust con foco post-cuántico, distribuido bajo un modelo source-available con NDA. Cada uno toma una ruta válida. Ninguno ocupa el espacio que QuantumSSH apunta a llenar: **un servidor SSH post-cuántico, en Rust, genuinamente abierto, con gobernanza pública y comunidad real desde el primer día**. Ese espacio está abierto.

---

## Para quién es esto

QuantumSSH se escribe pensando en cuatro audiencias:

**Equipos de infraestructura crítica** que necesitan SSH y quieren un camino que no requiera explicar cada año por qué su CVE más reciente no los afectó.

**Industrias reguladas** —banca, salud, energía, gobierno— que ya están recibiendo presión para tener planes de transición post-cuántica y no encuentran herramientas pensadas para ese mundo, abiertas y auditables sin firmar acuerdos de confidencialidad.

**La comunidad Rust de sistemas**, que sigue ampliando su catálogo de infraestructura segura por construcción y donde un servidor SSH es una pieza que falta.

**Latinoamérica.** Hemos sido consumidores de software de sistemas durante décadas. Es momento de ser productores. Que un proyecto de esta naturaleza nazca en Chile, con documentación bilingüe desde el primer día, charlas en español, y participación activa en comunidades hispanohablantes, no es un detalle decorativo. Es parte del propósito.

---

## Lo que estamos dispuestos a aceptar

Sería deshonesto pretender que este proyecto no tiene costos.

**Curva de adopción larga.** El software de seguridad gana confianza lentamente. Nadie va a poner QuantumSSH en producción el primer año. Esto es como debe ser.

**Necesidad de auditoría profesional.** En algún momento del Phase 3, una auditoría de seguridad seria es indispensable. Esto cuesta entre 50 mil y 200 mil dólares. Vamos a postular a programas de financiamiento como Prossimo, Sovereign Tech Fund y NLnet.

**Comunidad pequeña al inicio.** Rust de sistemas en Latinoamérica es un nicho dentro de un nicho. Los primeros meses van a ser solitarios. Esa es la naturaleza del trabajo fundacional.

**Tentación de cerrar el código.** Vamos a recibir, eventualmente, ofertas o sugerencias de licenciamiento "enterprise", source-available, BUSL, AGPL conversions. Vamos a decir que no. La promesa de apertura es el activo más valioso del proyecto, no una restricción que nos limita.

---

## Cómo medimos el éxito

No vamos a medir el éxito por estrellas en GitHub. Lo medimos así:

1. **Antes del año uno:** un binario funcional, demo público, primer post de blog técnico, primera charla aceptada en una conferencia.
2. **Antes del año dos:** primera auditoría de seguridad, primera adopción documentada en producción (probablemente en un entorno de bajo riesgo), comunidad de contribuyentes establecida con governance documentada.
3. **Antes del año cinco:** alternativa creíble a OpenSSH para cargas de trabajo nuevas con requerimientos post-cuánticos. Referencia en discusiones de quantum-readiness en la región. Distribución vía paquetes de sistemas operativos mainstream.

Si en cinco años QuantumSSH es una opción que ingenieros de infraestructura consideran seriamente al elegir SSH, este proyecto fue exitoso. Si además fue construido con transparencia, abierto desde el primer commit, y abrió camino para que más proyectos de sistemas serios nazcan en Latinoamérica, fue mucho más que exitoso.

---

## Una invitación

Este manifiesto es una declaración de intención, no una promesa de resultados. La criptografía cuesta. Los protocolos cuestan. La confianza cuesta. Construir software que vive treinta años cuesta. Mantenerlo abierto cuando hay incentivos para cerrarlo cuesta más.

Pero las cosas que importan suelen costar.

Si lo que lees aquí te resuena —si te interesa la criptografía post-cuántica aplicada, si te apasionan los sistemas seguros por construcción, si te importa que Latinoamérica produzca software fundacional, si crees que la infraestructura crítica del futuro debe ser auditable por cualquiera sin pedir permiso, o si simplemente piensas que en treinta años nuestras sesiones SSH deberían seguir siendo privadas— hay lugar para ti en este proyecto.

Abre un issue. Manda un correo. Comenta en una charla. Sin NDAs. La invitación es genuina.

---

*Construido en Chile. Escrito para el mundo. Diseñado para los próximos treinta años. Abierto, y permaneciendo abierto.*

**— Gonzalo Fleming Garrido**
Fleming Science and Technologies SpA
Machalí, Chile · 2026
