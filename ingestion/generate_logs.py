import json
import os
import random
import uuid
from datetime import datetime, timedelta, timezone
from azure.identity import ClientSecretCredential
from azure.storage.blob import BlobServiceClient
from dotenv import load_dotenv

load_dotenv()

USERS = [
    ("cumali.karaali@sec-lab.de", "DE", "AS3320", "Deutsche Telekom AG"),
    ("anna.weber@sec-lab.de", "DE", "AS3209", "Vodafone GmbH"),
    ("lukas.meyer@sec-lab.de", "DE", "AS3320", "Deutsche Telekom AG"),
    ("svc-deploy-pipeline@sec-lab.de", "DE", "AS8075", "Microsoft Corporation"),
]

NORMAL_OPS = [
    "Microsoft.Storage/storageAccounts/blobServices/containers/read",
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.Resources/subscriptions/resourceGroups/read",
    "Microsoft.KeyVault/vaults/secrets/getSecret/action",
]


def build_event(ts: datetime, user: str, country: str, asn: str, org: str,
                category: str, operation: str, status_code: int,
                ip: str, role_assigned: str = None) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": ts.isoformat(),
        "category": category,
        "user_principal_name": user,
        "source_ip": ip,
        "geo_country": country,
        "asn": asn,
        "asn_org": org,
        "operation_name": operation,
        "status_code": status_code,  # 0 = Success, 50126 = Invalid Password, 403 = Forbidden
        "target_role": role_assigned,
    }


def generate_batch(num_normal: int = 250) -> list[dict]:
    now = datetime.now(timezone.utc)
    events = []

    # 1. Normales Grundrauschen (Tagsüber aus Deutschland)
    for _ in range(num_normal):
        user, country, asn, org = random.choice(USERS)
        ts = now - timedelta(minutes=random.randint(1, 1440))
        ts = ts.replace(hour=random.randint(8, 18))
        is_signin = random.random() < 0.4
        op = "SignInActivity" if is_signin else random.choice(NORMAL_OPS)
        status = 0 if random.random() < 0.97 else 50126
        ip = f"84.152.{random.randint(1, 254)}.{random.randint(1, 254)}"
        events.append(build_event(ts, user, country, asn, org,
                                  "SignInLogs" if is_signin else "ActivityLogs",
                                  op, status, ip))

    # 2. Angriffsszenario A: Password Spraying auf anna.weber
    spray_time = now - timedelta(minutes=45)
    for i in range(18):
        events.append(build_event(
            spray_time + timedelta(seconds=i * 15),
            "anna.weber@sec-lab.de", "RU", "AS12389", "Rostelecom",
            "SignInLogs", "SignInActivity", 50126, f"95.165.44.{10 + i}"
        ))
    # Ein erfolgreicher Login direkt nach den Fehlversuchen
    events.append(build_event(
        spray_time + timedelta(minutes=5),
        "anna.weber@sec-lab.de", "RU", "AS12389", "Rostelecom",
        "SignInLogs", "SignInActivity", 0, "95.165.44.29"
    ))

    # 3. Angriffsszenario B: Impossible Travel (DE -> US in 12 Minuten)
    travel_time = now - timedelta(minutes=30)
    events.append(build_event(
        travel_time, "lukas.meyer@sec-lab.de", "DE", "AS3320",
        "Deutsche Telekom AG", "SignInLogs", "SignInActivity", 0, "84.152.19.88"
    ))
    events.append(build_event(
        travel_time + timedelta(minutes=12), "lukas.meyer@sec-lab.de", "US",
        "AS14061", "DigitalOcean LLC", "SignInLogs", "SignInActivity", 0, "167.99.142.11"
    ))

    # 4. Angriffsszenario C: Nächtliche Privilege Escalation (Owner-Rolle vergeben)
    priv_time = now.replace(hour=3, minute=14)
    events.append(build_event(
        priv_time, "lukas.meyer@sec-lab.de", "US", "AS14061", "DigitalOcean LLC",
        "ActivityLogs", "Microsoft.Authorization/roleAssignments/write",
        0, "167.99.142.11", role_assigned="Owner"
    ))

    random.shuffle(events)
    return events


def upload_to_azure(events: list[dict]) -> str:
    credential = ClientSecretCredential(
        tenant_id=os.environ["AZURE_TENANT_ID"],
        client_id=os.environ["AZURE_CLIENT_ID"],
        client_secret=os.environ["AZURE_CLIENT_SECRET"],
    )
    account_url = f"https://{os.environ['AZURE_STORAGE_ACCOUNT']}.blob.core.windows.net"
    service_client = BlobServiceClient(account_url=account_url, credential=credential)
    container_client = service_client.get_container_client(os.environ["AZURE_CONTAINER_NAME"])

    ts_slug = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    blob_name = f"azure_security_logs_{ts_slug}.jsonl"
    payload = "\n".join(json.dumps(e) for e in events)

    container_client.upload_blob(name=blob_name, data=payload, overwrite=True)
    return blob_name


if __name__ == "__main__":
    batch = generate_batch()
    uploaded = upload_to_azure(batch)
    print(f"[OK] {len(batch)} Security-Events hochgeladen nach Azure Blob: {uploaded}")