
import os
import json
import time
import asyncio
import logging
import tempfile
import subprocess
from typing import Dict, List, Tuple, Set
from collections import defaultdict
import re
import csv
try:
    from .config import (
        AST_CACHE,
        CODEQL_PATH,
        CODEQL_SEARCH_PATH,
        QL_CODER_ROOT_DIR,
        get_chroma_client,
    )
except ImportError:
    from config import (
        AST_CACHE,
        CODEQL_PATH,
        CODEQL_SEARCH_PATH,
        QL_CODER_ROOT_DIR,
        get_chroma_client,
    )

def parse_diff_for_line_changes(diff_content: str) -> Dict[str, Set[int]]:
    """Parse diff to extract changed line numbers per file
    
    Returns:
        Dict mapping filename to set of changed line numbers
    """
    changes = defaultdict(set)
    current_file = None
    current_line = 0
    
    for line in diff_content.split('\n'):
        # File header
        if line.startswith('diff --git'):
            match = re.search(r'b/(.+)$', line)
            if match:
                current_file = os.path.basename(match.group(1))
                
        # Hunk header: @@ -start,count +start,count @@
        elif line.startswith('@@'):
            match = re.match(r'@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@', line)
            if match and current_file:
                current_line = int(match.group(2))
                
        # Added or modified lines
        elif current_file and (line.startswith('+') or line.startswith('-')):
            if not line.startswith('+++') and not line.startswith('---'):
                changes[current_file].add(current_line)
                if line.startswith('+'):
                    current_line += 1
        elif current_file and line.startswith(' '):
            current_line += 1
            
    return changes


def parse_codeql_csv_output(csv_content: str) -> List[Dict]:
    """Parse CodeQL CSV output
    
    Expected format
    col0,col1,col2,col3,col4,col5,col6,col7
    "e" (same as col1),"element","elementType","file","startLine","endLine","startColumn","endColumn"
    """
    nodes = []
    lines = csv_content.strip().split('\n')
    
    if len(lines) < 2:  # Need header and at least one row
        return nodes
    
    import csv
    from io import StringIO
    
    reader = csv.reader(StringIO(csv_content))
    
    for row in reader:
        if len(row) >= 8:
            try:
                node = {
                    'element': row[1],
                    'node_type': row[2],
                    'file': row[3],
                    'start_line': int(row[4]),
                    'end_line': int(row[5]),
                    'start_column': int(row[6]),
                    'end_column': int(row[7])
                }
                nodes.append(node)
            except (ValueError, IndexError) as e:
                continue
                
    return nodes

def filter_nodes_by_diff(nodes: List[Dict], changed_lines: Dict[str, Set[int]]) -> List[Dict]:
    """Filter AST nodes to only include those on changed lines"""
    filtered = []
    
    for node in nodes:
        file_changed_lines = changed_lines.get(node['file'], set())
        if not file_changed_lines:
            continue
            
        # Check if node overlaps with any changed lines
        node_lines = set(range(node['start_line'], node['end_line'] + 1))
        if node_lines.intersection(file_changed_lines):
            node['changed_lines'] = list(node_lines.intersection(file_changed_lines))
            filtered.append(node)
            
    return filtered

def create_semantic_document(node: Dict, db_type: str) -> str:
    """Create semantic document for AST node

    Args:
        node: AST node dictionary
        db_type: 'vulnerable' or 'fixed' - important for context
    """
    doc_text = f"""
AST Node: {node['node_type']}
AST Node Element: {node['element']}
File: {node['file']}
Lines: {node['start_line']}-{node['end_line']}
Changed Lines: {node.get('changed_lines', [])}
Database: {db_type}
"""

    # Add context about whether this node exists in both versions
    doc_text += f"\nIN_{db_type.upper()}_VERSION: true"

    return doc_text


def analyze_ast_differences(vuln_nodes: List[Dict], fixed_nodes: List[Dict]) -> Dict:
    """Analyze what changed between vulnerable and fixed AST nodes"""
    
    # Create signatures for comparison
    def node_signature(node):
        # Use file, line, and node type for signature 
        return f"{node['file']}:{node['start_line']}:{node['node_type']}"
    
    vuln_sigs = {node_signature(n): n for n in vuln_nodes}
    fixed_sigs = {node_signature(n): n for n in fixed_nodes}
    
    vuln_sig_set = set(vuln_sigs.keys())
    fixed_sig_set = set(fixed_sigs.keys())
    
    return {
        'removed_nodes': [vuln_sigs[sig] for sig in vuln_sig_set - fixed_sig_set],
        'added_nodes': [fixed_sigs[sig] for sig in fixed_sig_set - vuln_sig_set],
        'common_nodes': [(vuln_sigs[sig], fixed_sigs[sig]) for sig in vuln_sig_set & fixed_sig_set],
        'summary': {
            'removed_count': len(vuln_sig_set - fixed_sig_set),
            'added_count': len(fixed_sig_set - vuln_sig_set),
            'common_count': len(vuln_sig_set & fixed_sig_set)
        }
    }


def save_nodes_to_csv(nodes: List[Dict], output_path: str, db_type: str):
    """Save AST nodes to CSV file"""
    if not nodes:
        return
        
    # Add db_type to each node
    for node in nodes:
        node['db_type'] = db_type
    
    # Write CSV
    fieldnames = ['db_type', 'element','node_type', 'file', 'start_line', 'end_line', 
                  'start_column', 'end_column', 'changed_lines']
    
    with open(output_path, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        
        for node in nodes:
            # Convert lists to strings for CSV
            node_copy = node.copy()
            node_copy['changed_lines'] = ','.join(map(str, node.get('changed_lines', [])))
            writer.writerow(node_copy)

async def run_codeql_query_with_bqrs(query_path: str, database_path: str, output_dir: str, logger) -> Tuple[str, str]:
    """Run CodeQL query and export results
    
    Returns:
       returns query results in csv  
    """
    # Generate BQRS file first
    bqrs_file = os.path.join(output_dir, f"results_{os.getpid()}.bqrs")
    
    cmd = [
        CODEQL_PATH, "query", "run",
        "--database", database_path,
    ]
    if CODEQL_SEARCH_PATH:
        cmd.extend(["--search-path", CODEQL_SEARCH_PATH])
    cmd.extend([
        "--output", bqrs_file,
        query_path
    ])
    
    logger.info(f"Running CodeQL query: {' '.join(cmd)}")
    
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=QL_CODER_ROOT_DIR # Run from project root where qlpack.yml is
    )
    
    stdout, stderr = await process.communicate()
    
    if process.returncode != 0:
        logger.error(f"CodeQL query failed: {stderr.decode()}")
        raise Exception(f"CodeQL query failed: {stderr.decode()}")
    
    # Convert BQRS to CSV (problem format - single result set)
    decode_cmd = [
        CODEQL_PATH, "bqrs", "decode",
        "--format=csv",
        bqrs_file
    ]
    
    logger.info("Converting BQRS to CSV...")
    process = await asyncio.create_subprocess_exec(
        *decode_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=QL_CODER_ROOT_DIR  # Run from project root where qlpack.yml is
    )
    
    stdout, stderr = await process.communicate()
    
    if process.returncode != 0:
        logger.error(f"BQRS decode failed: {stderr.decode()}")
        raise Exception(f"BQRS decode failed: {stderr.decode()}")
    
    csv_results = stdout.decode()
    
    
    os.remove(bqrs_file)
    
    return csv_results 


def get_or_create_cve_ast_collection(logger):
    try:
        client = get_chroma_client()
        collection_name = AST_CACHE 
        try:
            collection = client.get_collection(name=collection_name)
            logger.info(f"Using existing CVE AST cache collection: {collection_name}")
        except Exception:
            # Collection doesn't exist, create it
            collection = client.create_collection(
                name=collection_name,
                metadata={"description": "Shared cache for CVE AST analysis results across all experiments"}
            )
            logger.info(f"Created new CVE AST cache collection: {collection_name}")
            
        return collection
    except Exception as e:
        logger.error(f"Failed to get/create CVE AST collection: {e}")
        return None

def check_phase2_cache(cve_id: str, logger) -> Dict:
    """Check if phase 2 results exist in the dedicated CVE AST cache
    
    Returns:
        Dict with 'cached' boolean and results if found
    """
    try:
        collection = get_or_create_cve_ast_collection(logger)
        if not collection:
            return {'cached': False}
            
        # Check for summary document (use CVE ID as the key)
        summary_id = f"{cve_id}_ast_summary"
        results = collection.get(ids=[summary_id])
        
        if results and results['documents']:
            logger.info(f"Found cached Phase 2 results for {cve_id}")
            
            # Get all related phase 2 nodes for this CVE
            phase2_results = collection.get(
                where={
                    "$and": [
                        {"cve_id": {"$eq": cve_id}},
                        {"phase": {"$eq": 2}},
                        {"analysis_type": {"$eq": "ast"}}
                    ]
                }
            )
            
            summary_data = json.loads(results['documents'][0])
            
            return {
                'cached': True,
                'summary': summary_data,
                'nodes_count': len(phase2_results['documents']) if phase2_results['documents'] else 0,
                'cache_id': summary_id,
                'collection': collection
            }
    except Exception as e:
        logger.warning(f"Error checking CVE AST cache: {e}")
    
    return {'cached': False}


def store_ast_in_chromadb(collection, nodes: List[Dict], cve_id: str,
                         db_type: str, logger):

    # Store nodes
    documents = []
    metadatas = []
    ids = []

    for i, node in enumerate(nodes):
        # Create semantic document
        doc_text = create_semantic_document(node, db_type)
        
        metadata = {
            'node_type': node['node_type'],
            'element': node['element'],
            'file': node['file'],
            'start_line': node['start_line'],
            'end_line': node['end_line'],
            'start_column': node['start_column'],
            'end_column': node['end_column'],
            'changed_lines_json': json.dumps(node.get('changed_lines', [])),
            'cve_id': cve_id,
            'db_type': db_type,
            'phase': 2,
            'analysis_type': 'ast',
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        }
        
        doc_id = f"{cve_id}_{db_type}_ast_{i}" 
        
        documents.append(doc_text)
        metadatas.append(metadata)
        ids.append(doc_id)
    
    # Batch store nodes in smaller chunks to prevent segfaults
    if documents:
        batch_size = 25  # Smaller batch size to prevent memory issues
        total_stored = 0
        
        for i in range(0, len(documents), batch_size):
            batch_docs = documents[i:i + batch_size]
            batch_metas = metadatas[i:i + batch_size]
            batch_ids = ids[i:i + batch_size]
            
            try:
                collection.add(
                    documents=batch_docs,
                    metadatas=batch_metas,
                    ids=batch_ids
                )
                total_stored += len(batch_docs)
                logger.info(f"Stored batch {i//batch_size + 1}: {len(batch_docs)} nodes")
            except Exception as e:
                logger.error(f"Failed to store batch {i//batch_size + 1}: {e}")
                # Continue with next batch instead of failing completely
                continue
        
        logger.info(f"Stored {total_stored}/{len(documents)} AST nodes for {db_type} database")


async def run_phase2(ql_agent, task, output_dir: str) -> Dict:
    """Phase 2: Extract AST with line numbers and filter by diff"""
    try:
        ql_agent.logger.info("Starting Phase 2: AST extraction with diff filtering")
        
        # Check cache first in the dedicated CVE AST collection
        cache_check = check_phase2_cache(task.cve_id, ql_agent.logger)
        
        if cache_check['cached']:
            ql_agent.logger.info(f"Using cached Phase 2 results for {task.cve_id}")
            
            # Create comparative analysis from cached data
            summary = cache_check['summary']
            comparative_analysis = f"""# AST Analysis for {task.cve_id} (CACHED)
                    
## Cache Information
Loaded from cache: {cache_check['cache_id']}
Cached nodes: {cache_check['nodes_count']}

## Changed Files and Lines
{json.dumps(summary.get('changed_files', []), indent=2)}


## Summary from Cache
{json.dumps(summary.get('differences'), indent=2)}

Note: This is a cached result. Run with --no-cache-phase-output to regenerate.
"""
            
            # Save cached output to file 
            with open(os.path.join(output_dir, "phase2_output.txt"), 'w') as f:
                f.write(comparative_analysis)
            
            return {
                "success": True,
                "output": comparative_analysis,
                "cached": True,
                "cache_summary": summary,
                "changed_lines": summary.get('changed_files', {}),
                "vuln_nodes": summary.get('vuln_nodes_in_diff', 0),
                "fixed_nodes": summary.get('fixed_nodes_in_diff', 0),
                "differences": summary.get('differences', {}),
                "output_files": {
                    "phase2_output": os.path.join(output_dir, "phase2_output.txt"),
                    "note": "Other files available from cache if needed"
                },
                "phase": 2
            }
        
        # Parse diff to get changed lines
        changed_lines = parse_diff_for_line_changes(task.fix_commit_diff)
        ql_agent.logger.info(f"Identified changes in files: {list(changed_lines.keys())}")
        
        # Use the new query with line numbers
        query_path = os.path.join(output_dir, "print_ast_with_locations.ql")
        
        # Copy the query to output dir if it doesn't exist
        if not os.path.exists(query_path):
            # Extract file names from diff
            file_names = list(changed_lines.keys())
            
            # Extract specific line ranges from diff for filtering
            line_ranges = []
            for fname, lines in changed_lines.items():
                if lines:
                    min_line = min(lines)
                    max_line = max(lines)
                    # Add some context around changed lines
                    context_start = max(1, min_line - 5)  # More context for better relationships
                    context_end = max_line + 5
                    line_ranges.append(f'(l.getFile().getBaseName() = "{fname}" and l.getStartLine() >= {context_start} and l.getEndLine() <= {context_end})')
            
            line_conditions = ' or '.join(line_ranges) if line_ranges else 'false'
            # Use targeted query focusing on expressions and statements useful for queries 
            simple_query = f"""/**
 * @name Expressions and statements for {task.cve_id} changed code areas
 * @description Extract expressions and statements from vulnerability fix areas
 * @id java/expr-stmt-diff-{task.cve_id.replace('-', '_')}
 * @kind problem
 * @problem.severity recommendation
 */

import java

from Element e, Location l
where 
  l = e.getLocation() and ({line_conditions}) 
select e, 
  e.toString() as element,
  e.getAPrimaryQlClass() as elementType,
  l.getFile().getBaseName() as file,
  l.getStartLine() as startLine,
  l.getEndLine() as endLine,
  l.getStartColumn() as startColumn,
  l.getEndColumn() as endColumn""" 
            with open(query_path, 'w') as f:
                f.write(simple_query)
                print(simple_query)
            
            # Copy qlpack.yml to the temp directory so CodeQL can find dependencies
            import shutil
            qlpack_source = f"{QL_CODER_ROOT_DIR}/qlpack.yml"
            qlpack_dest = os.path.join(output_dir, "qlpack.yml")
            if os.path.exists(qlpack_source):
                shutil.copy2(qlpack_source, qlpack_dest)
        
        # Clean up databases BEFORE running any queries to prevent lock issues
        try:
            from .utils import cleanup_codeql_databases
        except ImportError:
            from utils import cleanup_codeql_databases
        await cleanup_codeql_databases(task.vuln_db_path, task.fixed_db_path, ql_agent.logger)
        
        # Run query on vulnerable database
        vuln_nodes_csv = await run_codeql_query_with_bqrs(
            query_path, task.vuln_db_path, output_dir, ql_agent.logger
        )
        
        # Parse and filter vulnerable nodes (using problem format)
        vuln_nodes = parse_codeql_csv_output(vuln_nodes_csv)
        vuln_filtered = filter_nodes_by_diff(vuln_nodes, changed_lines)
        ql_agent.logger.info(f"Vulnerable DB: {len(vuln_nodes)} total nodes, {len(vuln_filtered)} in diff")
         
        # Save vulnerable nodes to CSV
        vuln_csv_path = os.path.join(output_dir, "vulnerable_ast_nodes.csv")
        save_nodes_to_csv(vuln_filtered, vuln_csv_path, 'vulnerable')
        ql_agent.logger.info(f"Saved vulnerable AST nodes to: {vuln_csv_path}")
         
        # Run query on fixed database  
        fixed_nodes_csv = await run_codeql_query_with_bqrs(
            query_path, task.fixed_db_path, output_dir, ql_agent.logger
        )
        
        # Parse and filter fixed nodes (using problem format)
        fixed_nodes = parse_codeql_csv_output(fixed_nodes_csv)
        fixed_filtered = filter_nodes_by_diff(fixed_nodes, changed_lines)
        ql_agent.logger.info(f"Fixed DB: {len(fixed_nodes)} total nodes, {len(fixed_filtered)} in diff")
         
        # Save fixed nodes to CSV
        fixed_csv_path = os.path.join(output_dir, "fixed_ast_nodes.csv")
        save_nodes_to_csv(fixed_filtered, fixed_csv_path, 'fixed')
        ql_agent.logger.info(f"Saved fixed AST nodes to: {fixed_csv_path}")
        
        # Analyze differences
        ast_differences = analyze_ast_differences(vuln_filtered, fixed_filtered)
        
        # Save differences analysis
        diff_analysis_path = os.path.join(output_dir, "ast_differences.json")
        with open(diff_analysis_path, 'w') as f:
            json.dump(ast_differences, f, indent=2, default=str)
        ql_agent.logger.info(f"Saved AST differences analysis to: {diff_analysis_path}")
        
        # Store in dedicated CVE AST ChromaDB collection
        try:
            cve_ast_collection = get_or_create_cve_ast_collection(ql_agent.logger)
            if cve_ast_collection:
                # Store filtered nodes 
                store_ast_in_chromadb(cve_ast_collection, vuln_filtered, task.cve_id,
                                     'vulnerable', ql_agent.logger)
                store_ast_in_chromadb(cve_ast_collection, fixed_filtered, task.cve_id,
                                     'fixed', ql_agent.logger)
                
                # Store summary and differences
                summary = {
                    'cve_id': task.cve_id,
                    'changed_files': list(changed_lines.keys()),
                    'total_changed_lines': sum(len(lines) for lines in changed_lines.values()),
                    'vuln_nodes_in_diff': len(vuln_filtered),
                    'fixed_nodes_in_diff': len(fixed_filtered),
                    'node_types': list(set(n['node_type'] for n in vuln_filtered + fixed_filtered)),
                    'differences': ast_differences['summary']
                }
                
                cve_ast_collection.add(
                    documents=[json.dumps(summary, indent=2)],
                    metadatas=[{
                        'phase': 2,
                        'analysis_type': 'ast',
                        'section': 'ast_diff_summary',
                        'cve_id': task.cve_id,
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                    }],
                    ids=[f"{task.cve_id}_ast_summary"]
                )
                
                ql_agent.logger.info("Saved Phase 2 results to AST cache")
            else:
                ql_agent.logger.warning("Could not access CVE AST collection, results not cached")
        except Exception as e:
            ql_agent.logger.error(f"Failed to save to CVE AST cache: {e}")
        
        # Create comparative analysis
        comparative_analysis = f"""# AST Analysis for {task.cve_id}

## Changed Files and Lines
{json.dumps(changed_lines, indent=2, default=list)}

## Vulnerable Database AST Nodes (in diff)
Total nodes in diff: {len(vuln_filtered)}

## Fixed Database AST Nodes (in diff)
Total nodes in diff: {len(fixed_filtered)}

## Key Differences
{json.dumps(ast_differences['summary'], indent=2)}

## Added Nodes (potential fixes/sanitizers)
{json.dumps(ast_differences['added_nodes'][:5], indent=2) if ast_differences['added_nodes'] else 'None'}

## Removed Nodes (vulnerable patterns)
{json.dumps(ast_differences['removed_nodes'][:5], indent=2) if ast_differences['removed_nodes'] else 'None'}

## Output Files
- Vulnerable AST nodes: {vuln_csv_path}
- Fixed AST nodes: {fixed_csv_path}
- Differences analysis: {diff_analysis_path}
"""
        
        # Save outputs
        with open(os.path.join(output_dir, "phase2_output.txt"), 'w') as f:
            f.write(comparative_analysis)
            
        return {
            "success": True,
            "output": comparative_analysis,
            "changed_lines": changed_lines,
            "vuln_nodes": len(vuln_filtered),
            "fixed_nodes": len(fixed_filtered),
            "differences": ast_differences['summary'],
            "output_files": {
                "vulnerable_ast": vuln_csv_path,
                "fixed_ast": fixed_csv_path,
                "differences": diff_analysis_path
            },
            "phase": 2
        }
        
    except Exception as e:
        ql_agent.logger.error(f"Phase 2 failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "phase": 2
        }
