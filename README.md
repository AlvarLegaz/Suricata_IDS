# Suricata Tutorial
Tutorial to configurate and deploy the Suricata IDS.

## Introduction

Suricata is an open source signature-based IDS.

* **Host-based intrusion detection system (HIDS):** an application that monitors the activity of the host on which it’s installed.
* **Network-based intrusion detection system (NIDS):** an application that collects and monitors network traffic and network data. It works as sniffer.

### Suricata features
There are three main ways Suricata can be used:
* **Intrusion detection system (IDS):** As a network-based IDS, Suricata can monitor network traffic and alert on suspicious activities and intrusions. Suricata can also be set up as a host-based IDS to monitor the system and network activities of a single host like a computer.
* **Intrusion prevention system (IPS):** Suricata can also function as an intrusion prevention system (IPS) to detect and block malicious activity and traffic. Running Suricata in IPS mode requires additional configuration such as enabling IPS mode.
* **Network security monitoring (NSM):** In this mode, Suricata helps keep networks safe by producing and saving relevant network logs. Suricata can analyze live network traffic, existing packet capture files, and create and save full or conditional packet captures. This can be useful for forensics, incident response, and for testing signatures. For example, you can trigger an alert and capture the live network traffic to generate traffic logs, which you can then analyze to refine detection signatures.

## Suricata on Linux.

### Instalation
1. ```sudo apt update & sudo apt upgrade```
2. ```sudo apt install suricata```

### Configuration
* **/etc/suricata/suricata.yaml**: is the configuration file. Here, you can set the home network, internet adapter or default rules
* ```sudo nano suricata.yaml```
* Dentro del archivo podemos establecer la ip de nuestra red
```HOME_NET: por mi ip. HOME_NET: "[192.168.18.87/24]"```
* Establecemos la interza (se encuentra a la mitad del archivo)
```
af-packet:
- interface: wlan0
```
* Por ultimo podemos establecer las reglas. En este caso usaré una regla propia definida en **/etc/suricata/rules/**
```
default-rule-path: /etc/suricata/rules
rule-files:
  - suricata.rules

```

### Detection Rules:
Rules or signatures are used to identify specific patterns, behavior, and conditions of network traffic that might indicate malicious activity.

These can be found in **/etc/suricata/rules/**:

You can create your own rules as well.

#### SSH Brute Force Attack Rule
Para crear una regla de Suricata que genere una alerta cuando se produzcan tres intentos fallidos de conexión a SSH en menos de 1 minuto, puedes usar la siguiente regla:

```
alert tcp any any -> any 22 (msg:"SSH Brute Force Attempt"; flow:established,to_server; content:"Failed password"; threshold:type threshold, track by_src, count 3, seconds 60; sid:1000001; rev:1;)
```

Explicación de la regla:
- alert tcp any any -> any 22: Esta parte define que la regla se aplica a cualquier tráfico TCP dirigido al puerto 22 (SSH).
- msg:"SSH Brute Force Attempt": Este es el mensaje que se mostrará cuando se active la alerta.
- flow:established,to_server: Esto especifica que la regla se aplica a conexiones establecidas hacia el servidor.
- content:"Failed password": Esto busca el contenido “Failed password” en el tráfico, que es típico de un intento fallido de conexión SSH.
- threshold:type threshold, track by_src, count 3, seconds 60: Esto define el umbral para activar la alerta, en este caso, tres intentos fallidos en 60 segundos.
- sid:1000001: Este es el ID único de la regla.
- rev:1: Esta es la versión de la regla.
- Asegúrate de agregar esta regla al archivo de reglas de Suricata, generalmente ubicado en /etc/suricata/rules/local.rules, y luego reinicia Suricata para que los cambios surtan efecto.

#### Port Scan Alert Rule

```
alert tcp any any -> any any (msg:"Port Scan Detected"; flags:S; threshold:type both, track by_src, count 20, seconds 60; sid:1000003; rev:1;)
```

```
alert tcp any any -> any any (msg:"XMAS Port Scan Detected"; flags: FPU; threshold:type both, track by_src, count 20, seconds 60; sid:1000005; rev:1;)
```

```
alert tcp any any -> any any (msg:"FIN Port Scan Detected"; flags:F; threshold:type both, track by_src, count 20, seconds 60; sid:1000004; rev:1;)
```

```
alert tcp any any -> any any (msg:"XMAS Port Scan Detected"; flags: FPU; threshold:type both, track by_src, count 20, seconds 60; sid:1000005; rev:1;)
```

Explicación de la regla:
- alert tcp any any -> any any: Esta parte define que la regla se aplica a cualquier tráfico TCP desde cualquier dirección IP de origen a cualquier dirección IP de destino.
- msg:"Port Scan Detected": Este es el mensaje que se mostrará cuando se active la alerta.
- flags:S: Esto especifica que la regla se aplica a paquetes TCP con el flag SYN activado. Los escaneos de puertos suelen enviar paquetes SYN para identificar puertos abiertos.
- flags:F, flags:FPU, flags:0: Estas partes de las reglas especifican los diferentes tipos de paquetes utilizados en los escaneos de puertos. Los escaneos FIN utilizan el flag FIN, los escaneos XMAS utilizan los flags FIN, PSH y URG, y los escaneos NULL no utilizan ningún flag.
- threshold:type both, track by_src, count 20, seconds 60: Esto define el umbral para activar la alerta. En este caso, si se detectan 20 paquetes SYN desde la misma dirección IP de origen en un periodo de 60 segundos, se activará la alerta. El tipo “both” indica que se cuenta tanto el tráfico entrante como el saliente.
- sid:1000003: Este es el ID único de la regla.
- rev:1: Esta es la versión de la regla.
¿Cómo funciona?
Detección de Paquetes SYN: La regla monitorea el tráfico TCP en busca de paquetes con el flag SYN activado. Estos paquetes son típicos de los intentos de establecer una conexión TCP.
Umbral de Activación: Si se detectan 20 paquetes SYN desde la misma dirección IP de origen en un periodo de 60 segundos, se considera que se está realizando un escaneo de puertos.
Generación de Alerta: Cuando se cumple el umbral, Suricata genera una alerta con el mensaje “Port Scan Detected”.


### Running Suricata

* **Ejecutar suricata en modo normal:**
```
sudo suricata -c /etc/suricata/suricata.yaml -i wlan0
```
Si queremos ejecutarlo en segundo plano simplemente añadimos & el problema es que cuando se cierra el terminal esta aplicacion tambien se cierra.
```
sudo suricata -c /etc/suricata/suricata.yaml -i wlan0 &
```
Con comando nohup no se cierra al cerrar terminal.
```
sudo nohup suricata -c /etc/suricata/suricata.yaml -i wlan0 &
```
El proceso se puede ver con ```pidof suricata``` y eliminar con  ```kill [id]```.

* **Ejecutar suricata como servicio:**
```
sudo systemctl start suricata
```
#### Output log files
* **Directory:** /var/log/suricata/

**Log Format:** EVE JSON - Extensible Event Format JavaScrip Object Notation.
**Suricata log types:**
* **Alert logs:** usually this is the output of signatures which have triggered an alert. For example, a signature that detects suspicious traffic across the network.
* **Network telemetry logs:** information about network traffic flows, it is not always security relevant, it’s simply recording what’s happening on a network, such as a connection being made to a specific port.

