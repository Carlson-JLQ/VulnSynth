#!/usr/bin/env python3
"""
Script to delete all Chroma collections prefixed with 'cve_analysis_'
"""

import sys
from typing import List
from src.config import CHROMA_DB_PATH, get_chroma_client

def get_all_collections() -> List[str]:
    """Get all collection names from Chroma database"""
    try: 
        # Initialize Chroma client (adjust path if needed)
        client = get_chroma_client 
        
        # Get all collections
        collections = client.list_collections()
        return [collection.name for collection in collections]
    except Exception as e:
        print(f"Error getting collections: {e}")
        return []


def delete_cve_analysis_collections(dry_run: bool = True) -> None:
    """Delete all collections prefixed with 'cve_analysis_'"""
    try: 
        # Initialize Chroma client
        client = get_chroma_client 
        
        # Get all collections
        all_collections = get_all_collections()
        
        # Filter for cve_analysis collections
        cve_analysis_collections = [name for name in all_collections if name.startswith('cve_analysis_')]
        
        print(f"Found {len(cve_analysis_collections)} CVE analysis collections")
        
        if not cve_analysis_collections:
            print("No CVE analysis collections found to delete")
            return
        
        if dry_run:
            print("\n--- DRY RUN MODE ---")
            print("Collections that would be deleted:")
            for collection_name in cve_analysis_collections:
                print(f"  - {collection_name}")
            print(f"\nTotal: {len(cve_analysis_collections)} collections")
            print("\nTo actually delete these collections, run with --confirm")
            return
        
        # Confirm deletion
        print(f"\nAbout to delete {len(cve_analysis_collections)} collections:")
        for i, collection_name in enumerate(cve_analysis_collections[:5]):
            print(f"  - {collection_name}")
        
        if len(cve_analysis_collections) > 5:
            print(f"  ... and {len(cve_analysis_collections) - 5} more")
        
        response = input(f"\nAre you sure you want to delete all {len(cve_analysis_collections)} CVE analysis collections? (yes/no): ")
        
        if response.lower() not in ['yes', 'y']:
            print("Deletion cancelled")
            return
        
        # Delete collections
        deleted_count = 0
        failed_deletions = []
        
        for collection_name in cve_analysis_collections:
            try:
                client.delete_collection(collection_name)
                deleted_count += 1
                print(f"Deleted: {collection_name}")
            except Exception as e:
                failed_deletions.append((collection_name, str(e)))
                print(f"Failed to delete {collection_name}: {e}")
        
        print(f"\n--- Summary ---")
        print(f"Successfully deleted: {deleted_count} collections")
        
        if failed_deletions:
            print(f"Failed to delete: {len(failed_deletions)} collections")
            for collection_name, error in failed_deletions:
                print(f"  - {collection_name}: {error}")
        
    except Exception as e:
        print(f"Error during deletion: {e}")
        sys.exit(1)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Delete CVE analysis collections from Chroma database")
    parser.add_argument("--confirm", action="store_true", 
                       help="Actually delete collections (without this flag, runs in dry-run mode)")
    parser.add_argument("--db-path", default=CHROMA_DB_PATH,
                       help=f"Path to Chroma database (default: {CHROMA_DB_PATH})")
    
    args = parser.parse_args()

    dry_run = not args.confirm
    delete_cve_analysis_collections(dry_run=dry_run)


if __name__ == "__main__":
    main()