# Sistema HCE – Registro Clínico en Blockchain (Demo Educativa)

## Descripción general
Este proyecto implementa un **sistema de registro de eventos clínicos** basado en blockchain con almacenamiento descentralizado de datos cifrados.  
El objetivo es demostrar cómo garantizar **integridad, trazabilidad y privacidad** en Historias Clínicas Electrónicas (HCE) mediante:

- **Cifrado local (AES-GCM)** de archivos y metadatos.
- **Almacenamiento descentralizado** en IPFS (Pinata).
- **Registro on-chain** de hashes y CIDs en un contrato inteligente Ethereum.
- **Construcción de transacciones EIP-1559** y modo “dry-run” para simulación.
- **Interacción real con la red Sepolia** a través de Alchemy.

> ⚠️ Este proyecto es con fines educativos. No debe usarse con datos reales de pacientes.

Para la ejecución local de este código, se utilizo cuentas reales delos diferentes servicios que se mencionan más adelante para comprobar todo el flujo, no datos simulados. Se elimino el archivo .env original con las llaves de esas cuentas por seguridad.

---

## Requisitos previos
- Python 3.10 o superior  
- Entorno virtual (recomendado)  
- Cuenta gratuita en:
  - [Alchemy](https://alchemy.com) → nodo RPC Sepolia
  - [Pinata](https://app.pinata.cloud) → servicio IPFS
  - [MetaMask](https://metamask.io) → cartera con ETH de prueba
- Contrato `HCE_Registro` desplegado en Sepolia (ver ejemplo abajo)

---

## Instalación
```bash
git clone <repo>
cd Proyecto
python -m venv venv
venv\Scripts\activate  # (Windows)
pip install -r requirements.txt
```

---

## Configuración
Crea un archivo `.env` en el directorio del proyecto:

```bash
ALCHEMY_URL=https://eth-sepolia.g.alchemy.com/v2/TU_API_KEY
PINATA_JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
PRIVATE_KEY=0xCLAVE_PRIVADA_DE_PRUEBA
WALLET_ADDRESS=0xDIRECCION_PUBLICA
CONTRACT_ADDRESS=0xDIRECCION_CONTRATO_DESPLEGADO
CHAIN_ID=11155111
```

> Nunca publiques `.env` en repositorios.

---

## Contrato inteligente de ejemplo
Contrato `HCE_Registro.sol` desplegado en Remix (Solidity 0.8.x):

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract HCE_Registro {
    struct Evento {
        string patientId;
        string eventType;
        string ipfsCid;
        string detailHash;
        uint256 timestamp;
    }

    Evento[] public eventos;

    function registrarEvento(
        string memory patientId,
        string memory eventType,
        string memory ipfsCid,
        string memory detailHash
    ) public {
        eventos.push(Evento(patientId, eventType, ipfsCid, detailHash, block.timestamp));
    }

    function totalEventos() public view returns (uint256) {
        return eventos.length;
    }
}
```

Copia el **ABI** desde Remix y guárdalo como `abi.json` en la misma carpeta que `app.py`.

---

## Uso
```bash
python app.py
```

Menú principal:
```
1) Probar cifrado local y subida simulada a IPFS
2) Registrar evento clínico (dry-run)
3) Registrar evento clínico (enviar tx real)
4) Probar decrypt roundtrip
0) Salir
```

### Flujo sugerido
1. Ejecuta opción **1** para validar cifrado y subida a IPFS.  
2. Prueba opción **2** para simular una transacción sin firmarla.  
3. Si todo es correcto y tienes ETH de prueba, ejecuta **3** para enviar la transacción real.  
4. Consulta el hash de la transacción en [Sepolia Etherscan](https://sepolia.etherscan.io).  
5. En Remix, usa `totalEventos()` para verificar que se registró correctamente.

---

## Estructura del proyecto
```
Proyecto/
│
├── app.py              # Lógica principal de la aplicación
├── abi.json            # ABI del contrato
├── .env                # Variables de entorno
├── requirements.txt    # Dependencias Python
├── README.md           # Este archivo
└── /data               # Archivos adjuntos opcionales
```

---

## Seguridad y buenas prácticas
- Los datos clínicos **se cifran localmente** con AES-GCM antes de salir del entorno del cliente.  
- Solo se publican **hashes y CIDs**, nunca contenido sensible.  
- El archivo `.env` debe permanecer privado.  
- Claves de descifrado y privadas no se deben exponer ni versionar.

---

## Pruebas y validación
- **Dry-run**: simula transacciones sin enviarlas.  
- **Conexión RPC**: confirmada mediante `Web3.is_connected()`.  
- **Cifrado-descifrado**: probado con `encrypt_bytes_aes_gcm()` y `decrypt_bytes_aes_gcm()`.  
- **IPFS**: verificación de CID real vía [gateway.pinata.cloud](https://gateway.pinata.cloud).  
- **On-chain**: confirmación de `status: 1` en recibo de transacción.

---

## Limitaciones
- No implementa rotación automática de claves.  
- No gestiona identidades o roles de usuarios.  
- No realiza interoperabilidad FHIR; se enfoca en la capa técnica blockchain/IPFS.

---

## Autor y licencia
Proyecto desarrollado con fines académicos por **Carlos Lopez y Jairo Iriarte** apoyandonos de la herramienta CharGPT. para práctica de integración blockchain y seguridad de datos en sistemas HCE.  

Licencia MIT.
