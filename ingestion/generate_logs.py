import os
import json
import uuid
import random
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from azure.identity import ClientSecretCredential
from azure.storage.blob import BlobServiceClient

load_dotenv()

USERS = [
    ("anna.weber@sec-lab.de", "DE", "Deutsche Telekom AG"),
    ("lukas.meyer@sec-lab.de", "DE", "Vodafone GmbH"),
    ("sophie.schneider@sec-lab.de", "DE", "Telefonica Germany"),
    ("max.fischer@sec-lab.de", "DE", "Deutsche Telekom AG"),
    ("elena.hoffmann@sec-lab.de", "AT", "A1 Telekom Austria"),
    ("jonas.keller@sec-lab.de", "CH", "Swisscom AG"),
    ("marie.laurent@sec-lab.de", "FR", "Orange S.A."),
    ("david.smith@sec-lab.de", "GB", "BT Group plc"),
    ("sarah.connor@sec-lab.de", "US", "AT&T Corp."),
    ("erik.lindqvist@sec-lab.de", "SE", "Telia Company"),
    ("nina.richter@sec-lab.de", "DE", "1&1 Versatel"),
    ("thomas.bauer@sec-lab.de", "DE", "Deutsche Telekom AG"),
    ("claire.dubois@sec-lab.de", "NL", "KPN B.V."),
    ("marco.rossi@sec-lab.de", "IT", "TIM S.p.A."),
    ("admin.secops@sec-lab.de", "DE", "Deutsche Telekom AG"),
]

APPS = [
    "Microsoft 365 Portal",
    "Azure Portal",
    "Microsoft Teams",
    "SharePoint Online",
    "Exchange Online",
    "GitHub Enterprise SSO",
    "Databricks Workspace",
]

NORMAL_ERRORS = [
    (50074, "MFA_REQUIRED"),
    (50140, "KEEP_ME_SIGNED_IN_INTERRUPT"),
    (50055, "PASSWORD_EXPIRED"),
]


def random_ip(prefix: str) -> str:
    return f"{prefix}.{random.randint(1, 254)}.{random.randint(1, 254)}"


def build_signin(ts: datetime, upn: str, ip: str, country: str, asn: str, status: int, app: str) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "log_source": "EntraID_SignInLogs",
        "event_ts": ts.isoformat(),
        "user_principal_name": upn,
        "source_ip": ip,
        "geo_country": country,
        "asn_org": asn,
        "application": app,
        "status_code": status,
        "operation_name": "Sign-in activity",
        "resource_name": app,
        "role_assigned": None,
    }


def build_activity(ts: datetime, upn: str, ip: str, country: str, asn: str, op: str, resource: str, role: str | None) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "log_source": "Azure_ActivityLogs",
        "event_ts": ts.isoformat(),
        "user_principal_name": upn,
        "source_ip": ip,
        "geo_country": country,
        "asn_org": asn,
        "application": "Azure Resource Manager",
        "status_code": 0,
        "operation_name": op,
        "resource_name": resource,
        "role_assigned": role,
    }


def generate_telemetry(days: int = 7) -> list[dict]:
    events = []
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    start = now - timedelta(days=days)

    # 1. Realistic 7-day baseline traffic (higher during business hours, lower at night/weekends)
    cursor = start
    while cursor < now:
        hour = cursor.hour
        is_weekend = cursor.weekday() >= 5
        if is_weekend:
            volume = random.randint(4, 12)
        elif 7 <= hour <= 18:
            volume = random.randint(28, 55)
        else:
            volume = random.randint(3, 10)

        for _ in range(volume):
            upn, country, asn = random.choice(USERS)
            ev_ts = cursor + timedelta(minutes=random.randint(0, 59), seconds=random.randint(0, 59))
            ip = random_ip("84.152" if country == "DE" else "195.201")
            app = random.choice(APPS)
            status = 0 if random.random() < 0.94 else random.choice(NORMAL_ERRORS)[0]
            events.append(build_signin(ev_ts, upn, ip, country, asn, status, app))

            # Occasional normal Azure ARM read/list operations
            if status == 0 and random.random() < 0.08:
                events.append(
                    build_activity(
                        ev_ts + timedelta(seconds=15),
                        upn,
                        ip,
                        country,
                        asn,
                        "Microsoft.Resources/subscriptions/resourceGroups/read",
                        "/subscriptions/prod-sec-01/resourceGroups/rg-lakehouse",
                        None,
                    )
                )
        cursor += timedelta(hours=1)

    # 2. Attack Scenario A: Password Spraying from Russia (Day 2)
    t_spray_1 = now - timedelta(days=5, hours=3)
    for i in range(24):
        events.append(
            build_signin(
                t_spray_1 + timedelta(minutes=i * 2),
                "anna.weber@sec-lab.de",
                random_ip("91.214"),
                "RU",
                "Rostelecom PJSC",
                50126,
                "Microsoft 365 Portal",
            )
        )

    # 3. Attack Scenario B: Distributed Brute Force from China & Brazil (Day 5)
    t_spray_2 = now - timedelta(days=2, hours=6)
    for i in range(19):
        country, prefix, asn = random.choice([("CN", "223.71", "China Mobile"), ("BR", "177.54", "Vivo S.A.")])
        events.append(
            build_signin(
                t_spray_2 + timedelta(minutes=i * 3),
                "thomas.bauer@sec-lab.de",
                random_ip(prefix),
                country,
                asn,
                50126,
                "Azure Portal",
            )
        )

    # 4. Attack Scenario C: Impossible Travel DE -> US + Privilege Escalation (Day 6)
    t_imp_1 = now - timedelta(days=1, hours=4)
    events.append(build_signin(t_imp_1, "lukas.meyer@sec-lab.de", "84.152.44.19", "DE", "Vodafone GmbH", 0, "Azure Portal"))
    events.append(build_signin(t_imp_1 + timedelta(minutes=14), "lukas.meyer@sec-lab.de", "167.99.142.11", "US", "DigitalOcean LLC", 0, "Azure Portal"))
    events.append(
        build_activity(
            t_imp_1 + timedelta(minutes=19),
            "lukas.meyer@sec-lab.de",
            "167.99.142.11",
            "US",
            "DigitalOcean LLC",
            "Microsoft.Authorization/roleAssignments/write",
            "/subscriptions/prod-sec-01",
            "Owner",
        )
    )

    # 5. Attack Scenario D: Impossible Travel CH -> SG + Contributor Escalation (Today)
    t_imp_2 = now - timedelta(hours=3)
    events.append(build_signin(t_imp_2, "jonas.keller@sec-lab.de", "195.186.12.88", "CH", "Swisscom AG", 0, "Databricks Workspace"))
    events.append(build_signin(t_imp_2 + timedelta(minutes=22), "jonas.keller@sec-lab.de", "139.59.218.44", "SG", "DigitalOcean Singapore", 0, "Azure Portal"))
    events.append(
        build_activity(
            t_imp_2 + timedelta(minutes=27),
            "jonas.keller@sec-lab.de",
            "139.59.218.44",
            "SG",
            "DigitalOcean Singapore",
            "Microsoft.Authorization/roleAssignments/write",
            "/subscriptions/prod-sec-01/resourceGroups/rg-production",
            "Contributor",
        )
    )

    events.sort(key=lambda x: x["event_ts"])
    return events


def upload_to_blob(events: list[dict]) -> str:
    credential = ClientSecretCredential(
        tenant_id=os.environ["AZURE_TENANT_ID"],
        client_id=os.environ["AZURE_CLIENT_ID"],
        client_secret=os.environ["AZURE_CLIENT_SECRET"],
    )
    account_url = f"https://{os.environ['AZURE_STORAGE_ACCOUNT']}.blob.core.windows.net"
    blob_service = BlobServiceClient(account_url=account_url, credential=credential)
    container_client = blob_service.get_container_client(os.environ["AZURE_CONTAINER_NAME"])

    filename = f"security_events_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.jsonl"
    payload = "\n".join(json.dumps(e) for e in events)
    container_client.upload_blob(name=filename, data=payload, overwrite=True)
    return filename


if __name__ == "__main__":
    batch = generate_telemetry(days=7)
    blob_name = upload_to_blob(batch)
    print(f"Uploaded {len(batch)} events across 7 days to Azure Blob: {blob_name}")