#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

import chromadb


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_DB_PATH = os.path.join(REPO_ROOT, "chroma_db")


def build_client(mode: str, data_dir: str, host: str, port: int, auth_token: str) -> chromadb.ClientAPI:
    if mode == "http":
        headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else None
        return chromadb.HttpClient(host=host, port=port, headers=headers)

    os.makedirs(data_dir, exist_ok=True)
    return chromadb.PersistentClient(path=data_dir)


def short_preview(value: Any, limit: int = 220) -> str:
    if value is None:
        return "None"
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False)
    value = value.replace("\n", " ")
    return value if len(value) <= limit else value[:limit] + " ..."


def main() -> int:
    parser = argparse.ArgumentParser(description="Test read access to the Chroma vector database.")
    parser.add_argument(
        "--mode",
        choices=["persistent", "http"],
        default="persistent" if not os.environ.get("CHROMA_HOST") else "http",
        help="Client mode. Defaults to persistent unless CHROMA_HOST is set.",
    )
    parser.add_argument("--data-dir", default=os.environ.get("CHROMA_DB_PATH", DEFAULT_DB_PATH))
    parser.add_argument("--host", default=os.environ.get("CHROMA_HOST", "localhost"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("CHROMA_PORT", "8000")))
    parser.add_argument("--auth-token", default=os.environ.get("CHROMA_AUTH_TOKEN", "test"))
    parser.add_argument(
        "--collection",
        default="",
        help="Optional collection name to inspect in detail, for example nist_cve_cache.",
    )
    parser.add_argument(
        "--query-text",
        default="",
        help="Optional query text for similarity search. Requires --collection.",
    )
    parser.add_argument(
        "--where",
        default="",
        help="Optional JSON filter string for get(), for example '{\"cve_id\": \"CVE-2025-27818\"}'. Requires --collection.",
    )
    parser.add_argument("--limit", type=int, default=3)
    args = parser.parse_args()

    try:
        client = build_client(args.mode, args.data_dir, args.host, args.port, args.auth_token)
        collections = client.list_collections()
    except Exception as exc:
        print("FAILED: could not connect to Chroma")
        print(f"error: {exc}")
        return 1

    print("CONNECTED")
    print(f"mode: {args.mode}")
    if args.mode == "persistent":
        print(f"data_dir: {args.data_dir}")
    else:
        print(f"http: {args.host}:{args.port}")
    print(f"collections: {len(collections)}")

    for collection in collections[:20]:
        try:
            name = collection.name
            count = collection.count()
        except Exception:
            name = getattr(collection, "name", str(collection))
            count = "unknown"
        print(f"- {name}: {count}")

    if not args.collection:
        return 0

    try:
        collection = client.get_collection(args.collection)
    except Exception as exc:
        print(f"FAILED: collection '{args.collection}' not found")
        print(f"error: {exc}")
        return 2

    print(f"\nINSPECTING COLLECTION: {args.collection}")
    print(f"count: {collection.count()}")

    where = None
    if args.where:
        try:
            where = json.loads(args.where)
        except json.JSONDecodeError as exc:
            print(f"FAILED: invalid --where JSON: {exc}")
            return 3

    try:
        if args.query_text:
            result = collection.query(
                query_texts=[args.query_text],
                n_results=args.limit,
                where=where,
            )
        else:
            result = collection.get(
                where=where,
                limit=args.limit,
                include=["documents", "metadatas"],
            )
    except Exception as exc:
        print("FAILED: collection read/query failed")
        print(f"error: {exc}")
        return 4

    print("QUERY_OK")
    ids = result.get("ids") or []
    docs = result.get("documents") or []
    metas = result.get("metadatas") or []

    # query() returns nested lists
    if ids and isinstance(ids[0], list):
        ids = ids[0]
        docs = docs[0] if docs else []
        metas = metas[0] if metas else []

    for idx, doc_id in enumerate(ids):
        print(f"\n[{idx}] id: {doc_id}")
        if idx < len(metas):
            print(f"metadata: {short_preview(metas[idx], 300)}")
        if idx < len(docs):
            print(f"document: {short_preview(docs[idx], 300)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
