import io
import os
from azure.identity import ClientSecretCredential
from azure.storage.blob import BlobServiceClient
from databricks.sdk import WorkspaceClient
from dotenv import load_dotenv

load_dotenv()


def sync_azure_to_databricks() -> None:
    credential = ClientSecretCredential(
        tenant_id=os.environ["AZURE_TENANT_ID"],
        client_id=os.environ["AZURE_CLIENT_ID"],
        client_secret=os.environ["AZURE_CLIENT_SECRET"],
    )
    account_url = f"https://{os.environ['AZURE_STORAGE_ACCOUNT']}.blob.core.windows.net"
    blob_service = BlobServiceClient(account_url=account_url, credential=credential)
    container_client = blob_service.get_container_client(os.environ["AZURE_CONTAINER_NAME"])

    w = WorkspaceClient(
        host=os.environ["DATABRICKS_HOST"],
        token=os.environ["DATABRICKS_TOKEN"],
    )
    volume_path = os.environ["DATABRICKS_VOLUME_PATH"].rstrip("/")

    existing_files = {
        entry.name for entry in w.files.list_directory_contents(volume_path)
    }

    transferred = 0
    for blob in container_client.list_blobs():
        filename = os.path.basename(blob.name)
        if filename in existing_files:
            continue

        raw_bytes = container_client.download_blob(blob.name).readall()
        target_path = f"{volume_path}/{filename}"
        w.files.upload(file_path=target_path, contents=io.BytesIO(raw_bytes), overwrite=True)
        print(f"[SYNC] {blob.name} -> {target_path}")
        transferred += 1

    print(f"[FERTIG] {transferred} neue Datei(en) ins Databricks Volume übertragen.")


if __name__ == "__main__":
    sync_azure_to_databricks()