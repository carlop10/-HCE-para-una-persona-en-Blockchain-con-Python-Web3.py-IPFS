#!/usr/bin/env python3
"""
app.py - Implementación mínima funcional para practicar HCE (cifrado local, IPFS upload stub,
construcción de transacciones EIP-1559 y modo dry-run).

Requisitos:
  pip install web3 python-dotenv pycryptodome requests eth-account
Uso:
  python app.py
"""
import os
import sys
import json
import time
import hashlib
import argparse
from dataclasses import dataclass
from decimal import Decimal

from dotenv import load_dotenv
try:
    # Web3.py v7 o superior
    from web3.middleware.proof_of_authority import ExtraDataToPOAMiddleware as geth_poa_middleware
except ImportError:
    # Web3.py v6 o inferior
    from web3.middleware import geth_poa_middleware

import requests
from web3 import Web3
from eth_account import Account

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ---------- Config / carga .env ----------
load_dotenv()

ALCHEMY_URL = os.getenv("ALCHEMY_URL", "").strip()
PINATA_JWT = os.getenv("PINATA_JWT", "").strip()  # opcional para pruebas IPFS
PRIVATE_KEY = os.getenv("PRIVATE_KEY", "").strip()
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS", "").strip()
WALLET_ADDRESS = os.getenv("WALLET_ADDRESS", "").strip()
CHAIN_ID = int(os.getenv("CHAIN_ID", "11155111"))  # Sepolia por defecto en el ejemplo

MINIMAL_CONFIG_OK = True
if not ALCHEMY_URL:
    MINIMAL_CONFIG_OK = False

# ---------- Helpers ----------
def check_config(min_requirements: bool = True):
    if min_requirements and not MINIMAL_CONFIG_OK:
        raise RuntimeError("Falta ALCHEMY_URL en .env. Añádelo y vuelve a ejecutar.")
    if PRIVATE_KEY and not WALLET_ADDRESS:
        # derive address if not provided
        acct = Account.from_key(PRIVATE_KEY)
        print(f"Derived wallet address from PRIVATE_KEY: {acct.address}")
    return True

# ---------- Web3 conexión ----------
w3 = None
def connect_w3():
    global w3
    if w3 is not None:
        return w3
    if not ALCHEMY_URL:
        raise RuntimeError("ALCHEMY_URL no configurado")
    w3 = Web3(Web3.HTTPProvider(ALCHEMY_URL, request_kwargs={"timeout": 30}))
    try:
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    except Exception:
        pass
    if not w3.is_connected():
        raise ConnectionError("No se pudo conectar al RPC")
    net_chain_id = w3.eth.chain_id
    if CHAIN_ID and net_chain_id != CHAIN_ID:
        print(f"Advertencia: chain_id del nodo {net_chain_id} distinto a CHAIN_ID {CHAIN_ID}")
    return w3

# ---------- Nonce y fees ----------
def next_nonce(address: str) -> int:
    w3 = connect_w3()
    n_pending = w3.eth.get_transaction_count(address, "pending")
    n_latest = w3.eth.get_transaction_count(address, "latest")
    return max(n_pending, n_latest)

def eip1559_fees(multiplier: Decimal = Decimal("1.3")) -> dict:
    w3 = connect_w3()
    latest = w3.eth.get_block("latest")
    base = getattr(latest, "baseFeePerGas", None)
    # fallback if node doesn't expose baseFeePerGas
    if base is None:
        base = w3.eth.gas_price
    # tip estimation
    try:
        tip = w3.eth.max_priority_fee
    except Exception:
        tip = int(2_000_000_000)  # 2 gwei fallback
    max_fee = int(Decimal(base + tip) * multiplier)
    return {"maxFeePerGas": max_fee, "maxPriorityFeePerGas": int(tip)}

# ---------- Crypto: AES-GCM ----------
def encrypt_bytes_aes_gcm(key32: bytes, data: bytes) -> bytes:
    if len(key32) != 32:
        raise ValueError("key32 debe tener 32 bytes")
    nonce = get_random_bytes(12)
    cipher = AES.new(key32, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    # formato: nonce(12) | tag(16) | ciphertext
    return nonce + tag + ciphertext

def decrypt_bytes_aes_gcm(key32: bytes, payload: bytes) -> bytes:
    if len(payload) < 28:
        raise ValueError("payload demasiado corto")
    nonce = payload[:12]
    tag = payload[12:28]
    ciphertext = payload[28:]
    cipher = AES.new(key32, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

# ---------- IPFS / Pinata upload (simple) ----------
def upload_to_pinata_bytes(ciphertext: bytes, filename: str = "blob.bin") -> dict:
    """
    Sube bytes a Pinata (si PINATA_JWT está presente).
    Devuelve dict con keys: cid, status_code, response.
    Si no hay PINATA_JWT, simula y devuelve cid falso basado en sha256.
    """
    if not PINATA_JWT:
        # simulación local para pruebas
        fake_cid = "fa-ke-cid-" + sha256_bytes(ciphertext)[:20]
        return {"cid": fake_cid, "simulated": True, "sha256": sha256_bytes(ciphertext)}
    url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    headers = {"Authorization": f"Bearer {PINATA_JWT}"}
    files = {"file": (filename, ciphertext)}
    try:
        r = requests.post(url, files=files, headers=headers, timeout=30)
        if r.status_code == 200:
            j = r.json()
            return {"cid": j.get("IpfsHash"), "simulated": False, "response": j, "sha256": sha256_bytes(ciphertext)}
        else:
            return {"error": r.text, "status_code": r.status_code}
    except Exception as e:
        return {"error": str(e)}

# ---------- Contrato wrapper (cargar ABI si existe) ----------
def load_contract(abi_path: str = "abi.json"):
    w3 = connect_w3()
    if not CONTRACT_ADDRESS:
        raise RuntimeError("CONTRACT_ADDRESS no está configurado en .env")
    if os.path.exists(abi_path):
        with open(abi_path, "r", encoding="utf-8") as f:
            abi = json.load(f)
    else:
        raise FileNotFoundError("ABI no encontrada. coloca abi.json en el directorio")
    return w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=abi)

# ---------- Construcción y envío de transacciones ----------
def build_tx_dict(to: str = None,
                  value: int = 0,
                  data: bytes = b"",
                  gas_limit: int = 300_000,
                  from_addr: str = None,
                  chain_id: int = CHAIN_ID,
                  simulate: bool = True) -> dict:
    w3 = connect_w3()
    if not from_addr:
        if WALLET_ADDRESS:
            from_addr = Web3.to_checksum_address(WALLET_ADDRESS)
        elif PRIVATE_KEY:
            acct = Account.from_key(PRIVATE_KEY)
            from_addr = acct.address
        else:
            raise RuntimeError("No hay from address configurada")
    nonce = next_nonce(from_addr)
    fees = eip1559_fees()
    tx = {
        "chainId": chain_id,
        "from": Web3.to_checksum_address(from_addr),
        "nonce": nonce,
        "maxPriorityFeePerGas": fees["maxPriorityFeePerGas"],
        "maxFeePerGas": fees["maxFeePerGas"],
        "gas": gas_limit,
        "to": Web3.to_checksum_address(to) if to else None,
        "value": int(value),
        "data": data,
        "type": 2,
    }
    if simulate:
        return {"simulate": True, "tx": tx}
    # firmar
    if not PRIVATE_KEY:
        raise RuntimeError("PRIVATE_KEY no disponible para firmar transaccion real")
    signed = Account.sign_transaction(tx, PRIVATE_KEY)
    raw = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction", None)
    if raw is None:
        raise RuntimeError("La versión de Web3 cambió la estructura de SignedTransaction")
    tx_hash = w3.eth.send_raw_transaction(raw)

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
    # Convertir HexBytes a str para que sea serializable
    def clean_hex(obj):
        if isinstance(obj, bytes):
            return obj.hex()
        if isinstance(obj, dict):
            return {k: clean_hex(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [clean_hex(x) for x in obj]
        return obj

    clean_receipt = clean_hex(dict(receipt))
    return {"simulate": False, "tx_hash": tx_hash.hex(), "receipt": clean_receipt}

# ---------- Funciones públicas del contrato (stubs genéricos) ----------
def registrar_evento_clinico(contract, patient_id: str, event_type: str, detail_json: dict,
                             attached_file_path: str = None, key32: bytes = None, simulate: bool = True):
    """
    Flujo:
      - valida inputs mínimos
      - cifra detail_json y archivo adjunto (si hay)
      - sube ciphertext a IPFS (o simula)
      - construye data call al contrato con ABI (necesita método en ABI)
      - construye tx y la retorna o envía
    """
    # validaciones simples
    if not isinstance(patient_id, str) or len(patient_id) == 0:
        raise ValueError("patient_id inválido")
    if not isinstance(event_type, str) or len(event_type) == 0:
        raise ValueError("event_type inválido")
    # serializar detail_json y cifrar
    detail_bytes = json.dumps(detail_json, ensure_ascii=False).encode("utf-8")
    if key32 is None:
        # derive key from patient_id (solo para pruebas). En producción usa KMS.
        key32 = hashlib.sha256(patient_id.encode("utf-8")).digest()
    ciphertext_detail = encrypt_bytes_aes_gcm(key32, detail_bytes)
    detail_hash = sha256_bytes(ciphertext_detail)
    detail_ipfs = upload_to_pinata_bytes(ciphertext_detail, filename="detail.json.enc")
    attached_info = None
    if attached_file_path:
        with open(attached_file_path, "rb") as f:
            file_bytes = f.read()
        ciphertext_file = encrypt_bytes_aes_gcm(key32, file_bytes)
        attached_info = upload_to_pinata_bytes(ciphertext_file, filename=os.path.basename(attached_file_path))
    # preparar los argumentos que el contrato espera.
    # Aquí asumimos que el contrato tiene una funcion `registrarEvento(string patientId, string eventType, string ipfsCid, string detailHash)`
    # Ajusta esto a la ABI real.
    try:
        fn = contract.get_function_by_name("registrarEvento")
    except Exception:
        raise RuntimeError("ABI no contiene registrarEvento. Ajusta el nombre o la ABI.")
    args = [patient_id, event_type, detail_ipfs["cid"], detail_hash]
    tx_data = fn(*args).build_transaction({"from": WALLET_ADDRESS})["data"]
    built = build_tx_dict(to=CONTRACT_ADDRESS, data=tx_data, from_addr=WALLET_ADDRESS, simulate=simulate)
    result = {
        "detail_sha256": detail_ipfs.get("sha256"),
        "detail_cid": detail_ipfs.get("cid"),
        "attached": attached_info,
        "tx": built,
    }
    return result

# ---------- CLI ----------
def menu():
    check_config(min_requirements=True)
    w3 = connect_w3()
    print("Conectado a nodo. chain_id:", w3.eth.chain_id)
    # cargar contrato si existe ABI
    contract = None
    try:
        contract = load_contract()
        print("Contrato cargado en", CONTRACT_ADDRESS)
    except Exception as e:
        print("No se pudo cargar contrato ABI:", e)
        # el usuario puede seguir probando cifrado/IPFS/simulate
    while True:
        print("\nOpciones:")
        print("1) Probar cifrado local y subida simulada a IPFS")
        print("2) Registrar evento clínico (dry-run)")
        print("3) Registrar evento clínico (enviar tx real) -- cuidado")
        print("4) Probar decrypt roundtrip")
        print("0) Salir")
        opt = input("Seleccione opción: ").strip()
        if opt == "0":
            print("Saliendo.")
            return
        if opt == "1":
            patient = input("patient_id de ejemplo: ").strip() or "patient-test-001"
            detail = {"note": "Prueba de detalle", "ts": int(time.time())}
            key = hashlib.sha256(patient.encode()).digest()
            ct = encrypt_bytes_aes_gcm(key, json.dumps(detail).encode("utf-8"))
            print("SHA256(ciphertext):", sha256_bytes(ct))
            up = upload_to_pinata_bytes(ct, filename="detail-test.enc")
            print("Upload result:", up)
            continue
        if opt == "2" or opt == "3":
            if not contract:
                print("No hay contrato cargado. Añade abi.json y vuelve a ejecutar.")
                continue
            patient = input("patient_id: ").strip() or "patient-test-001"
            event_type = input("event_type: ").strip() or "CONSULTA"
            detail_text = input("Breve nota (o dejar vacio para ejemplo): ").strip()
            if not detail_text:
                detail = {"note": "evento demo", "ts": int(time.time())}
            else:
                detail = {"note": detail_text, "ts": int(time.time())}
            attached = input("Ruta archivo adjunto (opcional): ").strip() or None
            simulate = True if opt == "2" else False
            try:
                resp = registrar_evento_clinico(contract, patient, event_type, detail,
                                                attached_file_path=attached, key32=None, simulate=simulate)
                print(json.dumps(resp, indent=2, ensure_ascii=False))
            except Exception as e:
                print("Error:", e)
            continue
        if opt == "4":
            text = input("Texto a cifrar: ").strip().encode("utf-8")
            key = get_random_bytes(32)
            ct = encrypt_bytes_aes_gcm(key, text)
            pt = decrypt_bytes_aes_gcm(key, ct)
            print("Original:", text.decode())
            print("Roundtrip OK:", pt.decode() == text.decode())
            continue
        print("Opción no válida.")

if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print("\ninterrupción por usuario.")
        sys.exit(0)
