"""
Estudiantes: Carlos Lopez y Jairo Iriarte
Asignatura: Redes y Sistemas de Comunicación

"""

import os, json, re, time, logging, hashlib
from decimal import Decimal
from typing import Optional
import requests
from web3 import Web3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Compatibilidad Web3 v6 / v7
try:
    from web3.middleware.proof_of_authority import ExtraDataToPOAMiddleware as geth_poa_middleware
except ImportError:
    from web3.middleware import geth_poa_middleware

# Cargar .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# Variables de entorno
ALCHEMY_URL = os.getenv("ALCHEMY_URL", "").strip()
PINATA_JWT = os.getenv("PINATA_JWT", "").strip()
PRIVATE_KEY = os.getenv("PRIVATE_KEY", "").strip()
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS", "").strip()
WALLET_ADDRESS = os.getenv("WALLET_ADDRESS", "").strip()

if not all([ALCHEMY_URL, PINATA_JWT, PRIVATE_KEY, CONTRACT_ADDRESS, WALLET_ADDRESS]):
    raise RuntimeError("Config incompleta: defina las variables de entorno requeridas en .env")

# Conexión Web3
w3 = Web3(Web3.HTTPProvider(ALCHEMY_URL, request_kwargs={"timeout": 30}))
w3.middleware_onion.inject(geth_poa_middleware, layer=0)

if not w3.is_connected():
    raise ConnectionError("No hay conexión con el nodo RPC (verifique ALCHEMY_URL)")

if w3.eth.chain_id != 11155111:
    raise RuntimeError(f"ChainID inesperado: {w3.eth.chain_id} (debe ser 11155111 para Sepolia)")

contract_address = w3.to_checksum_address(CONTRACT_ADDRESS)
wallet = w3.to_checksum_address(WALLET_ADDRESS)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# === EIP-1559 y nonce ===
def eip1559_fees(multiplier: Decimal = Decimal("1.25")) -> dict:
    base = w3.eth.get_block("latest").baseFeePerGas
    tip = w3.eth.max_priority_fee
    max_fee = int(Decimal(base + tip) * multiplier)
    return {"maxFeePerGas": max_fee, "maxPriorityFeePerGas": tip}

def next_nonce(address) -> int:
    n_pending = w3.eth.get_transaction_count(address, "pending")
    n_latest = w3.eth.get_transaction_count(address, "latest")
    return max(n_pending, n_latest)

# === Validaciones ===
ID_RE = re.compile(r"^[A-Za-z0-9._-]{6,64}$")
EVENTOS = {"Admision", "Alta", "Receta", "Laboratorio", "Evolucion", "Consentimiento"}

def pedir_patient_id() -> str:
    s = input("ID del paciente (seudónimo, sin datos reales): ").strip()
    if not ID_RE.match(s):
        raise ValueError("ID inválido. Use 6–64 caracteres alfanuméricos, guión o punto.")
    return s

def pedir_evento() -> str:
    e = input(f"Tipo de evento {EVENTOS}: ").strip().title()
    if e not in EVENTOS:
        raise ValueError("Evento no permitido.")
    return e

# === HTTP con reintentos ===
def http_post_with_retry(url, headers=None, files=None, data=None, max_tries=3, timeout=60):
    backoff = 1.5
    for i in range(max_tries):
        try:
            r = requests.post(url, headers=headers, files=files, data=data, timeout=timeout)
            if r.status_code // 100 == 2:
                return r
            logging.warning("HTTP %s: %s", r.status_code, r.text[:200])
        except requests.RequestException as e:
            logging.warning("Intento %d fallido: %s", i + 1, e)
        time.sleep(backoff**i)
    raise RuntimeError("Fallo al llamar al endpoint tras varios intentos.")

# === Cifrado AES-GCM + IPFS ===
def encrypt_bytes_AESGCM(key32: bytes, data: bytes) -> bytes:
    nonce = get_random_bytes(12)
    cipher = AES.new(key32, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce + tag + ciphertext

def cifrar_y_subir_ipfs(ruta_archivo: str, key32: bytes) -> tuple:
    with open(ruta_archivo, "rb") as f:
        raw = f.read()
    payload = encrypt_bytes_AESGCM(key32, raw)
    url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    headers = {"Authorization": f"Bearer {PINATA_JWT}"}
    files_up = {"file": (os.path.basename(ruta_archivo) + ".enc", payload)}
    resp = http_post_with_retry(url, headers=headers, files=files_up)
    cid = resp.json().get("IpfsHash")
    cipher_hash = hashlib.sha256(payload).hexdigest()
    print(f"Archivo cifrado y subido a IPFS con éxito.")
    print(f"CID: {cid}")
    print(f"SHA256 del cifrado: {cipher_hash}")
    return cid, cipher_hash

# === Envío de transacciones ===
def send_tx(tx_func, gas_limit: int, simulate: bool = False):
    nonce = next_nonce(wallet)
    fees = eip1559_fees()
    tx = tx_func.build_transaction({
        "chainId": 11155111,
        "from": wallet,
        "nonce": nonce,
        "gas": gas_limit,
        **fees
    })

    if simulate:
        print("\n--- SIMULACIÓN (dry-run) ---")
        print(json.dumps(tx, indent=2, default=str))
        print("-----------------------------")
        return None

    signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"\nTransacción enviada. Esperando confirmación...")
    rcpt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"✓ Confirmada en bloque {rcpt.blockNumber}")
    print(f"Ver en: https://sepolia.etherscan.io/tx/{tx_hash.hex()}\n")
    return rcpt

# === Registrar evento clínico ===
def registrar_evento_clinico(contract):
    print("\n=== REGISTRO DE EVENTO CLÍNICO ===")
    print("Checklist de privacidad:")
    print("1. Ningún dato identificable se enviará a la blockchain.")
    print("2. Adjuntos se cifrarán antes de subirse a IPFS.\n")

    patient_id = pedir_patient_id()
    event_type = pedir_evento()
    resumen_no_sensible = input("Resumen breve (NO sensible): ").strip()

    detalle_privado = {
        "t": time.time(),
        "summary": resumen_no_sensible,
        "author": wallet
    }
    plaintext_json = json.dumps(detalle_privado, ensure_ascii=False)
    detail_hash = hashlib.sha256(plaintext_json.encode("utf-8")).hexdigest()

    ruta_adjunto = input("Ruta del archivo clínico (Enter para omitir): ").strip()
    attachment_cid, cipher_hash = "", ""
    if ruta_adjunto:
        key32 = os.urandom(32)
        attachment_cid, cipher_hash = cifrar_y_subir_ipfs(ruta_adjunto, key32)

    version = int(input("Versión del registro (1 por defecto): ").strip() or "1")
    print("\nRegistrando evento en blockchain...")
    return send_tx(
        contract.functions.registrarEvento(patient_id, event_type, detail_hash, attachment_cid, version),
        gas_limit=330000
    )

# === Consentimiento informado ===
def actualizar_consentimiento(contract):
    print("\n=== ACTUALIZAR / REGISTRAR CONSENTIMIENTO ===")
    patient_id = pedir_patient_id()
    estado = input("Consentimiento (Si/No): ").strip().title()
    if estado not in {"Si", "No"}:
        raise ValueError("Debe ser Si o No.")
    print(f"Consentimiento recibido: {estado}")

    ruta_pdf = input("Ruta del PDF firmado (Enter para omitir): ").strip()
    evid_cid, evid_hash = "", ""
    if ruta_pdf:
        key32 = os.urandom(32)
        evid_cid, evid_hash = cifrar_y_subir_ipfs(ruta_pdf, key32)

    print("Enviando actualización de consentimiento a la blockchain...")
    rcpt = send_tx(
        contract.functions.actualizarConsentimiento(patient_id, estado == "Si", evid_hash, evid_cid),
        gas_limit=230000
    )
    print(f"✓ Consentimiento actualizado correctamente (Estado: {estado})")
    return rcpt

# === Menú principal ===
def menu(contract):
    while True:
        print("\n=== HISTORIA CLÍNICA ELECTRÓNICA (HCE) ===")
        print("1. Registrar evento clínico")
        print("2. Actualizar/Registrar consentimiento")
        print("3. Simulación (dry-run) de evento")
        print("0. Salir")
        op = input("Seleccione una opción: ").strip()
        if op == "1":
            registrar_evento_clinico(contract)
        elif op == "2":
            actualizar_consentimiento(contract)
        elif op == "3":
            print("\n--- Simulando transacción de ejemplo ---")
            patient_id = "PacienteDemo01"
            txf = contract.functions.registrarEvento(patient_id, "Evolucion", "hashdemo", "", 1)
            send_tx(txf, gas_limit=300000, simulate=True)
        elif op == "0":
            print("Finalizado.")
            break
        else:
            print("Opción inválida.")

# === Punto de entrada ===
if __name__ == "__main__":
    print("Conectando con contrato HCE...")
    abi_path = "abi.json"
    if not os.path.exists(abi_path):
        raise FileNotFoundError("No se encontró abi.json en el directorio actual.")
    with open(abi_path, "r", encoding="utf-8") as f:
        abi = json.load(f)
    contract = w3.eth.contract(address=contract_address, abi=abi)
    print("Conexión exitosa. Listo para operar.\n")
    menu(contract)
