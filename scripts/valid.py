#!/usr/bin/env python3

import sys
import json
import random
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import get_chroma_client

OUTPUT_DIR = Path(__file__).parent / 'doc_example'
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

SAMPLE_SIZE = 5


def sample_collection(client, collection_name: str) -> None:
    try:
        collection = client.get_collection(name=collection_name)
    except Exception as e:
        print(f"[SKIP] Collection '{collection_name}' not found: {e}")
        return

    total = collection.count()
    print(f"[INFO] '{collection_name}': {total} documents")

    if total == 0:
        print(f"[SKIP] '{collection_name}' is empty")
        return

    # Fetch all IDs then randomly pick up to SAMPLE_SIZE
    all_results = collection.get(include=[])
    all_ids = all_results['ids']

    sample_ids = random.sample(all_ids, min(SAMPLE_SIZE, len(all_ids)))

    results = collection.get(
        ids=sample_ids,
        include=['documents', 'metadatas', 'embeddings']
    )

    items = []
    for i, doc_id in enumerate(results['ids']):
        item = {
            'id': doc_id,
            'document': results['documents'][i] if results['documents'] else None,
            'metadata': results['metadatas'][i] if results['metadatas'] else None,
        }
        # Only include embeddings if present (they can be large; truncate to first 8 dims)
        if results.get('embeddings') is not None and results['embeddings'][i] is not None:
            emb = results['embeddings'][i]
            emb_list = emb.tolist() if hasattr(emb, 'tolist') else list(emb)
            item['embedding_preview'] = emb_list[:8]
            item['embedding_dim'] = len(emb_list)
        items.append(item)

    out_path = OUTPUT_DIR / f'{collection_name}.json'
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump({
            'collection': collection_name,
            'total_count': total,
            'sample_size': len(items),
            'items': items,
        }, f, ensure_ascii=False, indent=2)

    print(f"[DONE] Saved {len(items)} samples -> {out_path}")


def main():
    client = get_chroma_client()
    collections = client.list_collections()
    names = [c.name for c in collections]
    print(f"[INFO] Found {len(names)} collections: {names}")
    for name in names:
        sample_collection(client, name)


if __name__ == '__main__':
    main()
