import os
from dotenv import load_dotenv
import chromadb
load_dotenv()

VULNSYNTH_ROOT_DIR = os.path.join(os.path.dirname(__file__), "..")


    

PROJECT_INFO = f"{VULNSYNTH_ROOT_DIR}/data/project_info.csv"
CVES_PATH = f"{VULNSYNTH_ROOT_DIR}/cves"
LOGS_DIR = f"{VULNSYNTH_ROOT_DIR}/logs"
# CVES_PATH = f"{VULNSYNTH_ROOT_DIR}/cves"
CVES_PATH = f"{VULNSYNTH_ROOT_DIR}/cves"


CODEQL_HOME = os.environ.get("CODEQL_HOME")
CODEQL_PATH = os.environ.get("CODEQL_PATH")


JAVA_SECURITY_QLPACK_PATH= os.environ.get("JAVA_SECURITY_QLPACK_PATH", f"{CODEQL_HOME}/qlpacks/codeql/java-queries/")
JAVA_LIBRARY_QLPACK_PATH = os.environ.get("JAVA_LIBRARY_QLPACK_PATH", f"{CODEQL_HOME}/qlpacks/codeql/java-all/")

CPP_SECURITY_QLPACK_PATH = os.environ.get("CPP_SECURITY_QLPACK_PATH", f"{CODEQL_HOME}/qlpacks/codeql/cpp-queries/")

CPP_LIBRARY_QLPACK_PATH = os.environ.get("CPP_LIBRARY_QLPACK_PATH", f"{CODEQL_HOME}/qlpacks/codeql/cpp-all/")


CVES_PATH = f"{VULNSYNTH_ROOT_DIR}/cves"
# chroma db collection for retrieving CVE descriptions 
NVD_CACHE="nist_cve_cache"
# chroma db collection for retrieving ASTs of CVE diffs. 
AST_CACHE = "cve_ast_cache"


# ChromaDB connection settings
# Set CHROMA_HOST to use HTTP client (Docker/remote), unset for local PersistentClient
CHROMA_HOST = os.environ.get("CHROMA_HOST") or None
CHROMA_PORT = int(os.environ.get("CHROMA_PORT", "8000"))
CHROMA_AUTH_TOKEN = os.environ.get("CHROMA_AUTH_TOKEN", "test")
# Treat empty-string env vars as unset to avoid writing invalid paths.
CHROMA_DB_PATH = os.environ.get("CHROMA_DB_PATH") or os.path.join(VULNSYNTH_ROOT_DIR, "chroma_db")


def get_chroma_client() -> chromadb.ClientAPI:
    """Return a ChromaDB client based on environment configuration.

    - If CHROMA_HOST is set: returns HttpClient (for Docker / remote ChromaDB server)
    - Otherwise: returns PersistentClient (for local development)
    """
    if CHROMA_HOST:
        return chromadb.HttpClient(
            host=CHROMA_HOST,
            port=CHROMA_PORT,
            headers={"Authorization": f"Bearer {CHROMA_AUTH_TOKEN}"} if CHROMA_AUTH_TOKEN else None,
        )
    else:
        os.makedirs(CHROMA_DB_PATH, exist_ok=True)
        return chromadb.PersistentClient(path=CHROMA_DB_PATH)
