#!/usr/bin/env python3

import json
import os
import time
import logging
import re
import asyncio
import subprocess
from typing import Dict, Any, Optional, List
try:
    from .config import CODEQL_PATH, get_chroma_client
except ImportError:
    from config import CODEQL_PATH, get_chroma_client

async def cleanup_codeql_databases(vuln_db_path: str, fixed_db_path: str, logger: logging.Logger = None):
    """Clean up CodeQL databases to prevent locking issues"""
    try:
        if logger:
            logger.info("Cleaning up CodeQL databases to prevent locking issues")
        
        # Small delay to ensure processes have released locks
        await asyncio.sleep(2)
        
        # Clean up both databases
        for db_path in [vuln_db_path, fixed_db_path]:
            cmd = [
                CODEQL_PATH, "database", "cleanup",
                "--cache-cleanup=clear",
                db_path
            ]
            
            if logger:
                logger.info(f"Running cleanup on {db_path}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "CODEQL_ALLOW_INSTALLATION_ANYWHERE": "true"}
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                if logger:
                    logger.warning(f"Database cleanup warning: {stderr.decode()}")
                else:
                    print(f"Database cleanup warning: {stderr.decode()}")
            else:
                if logger:
                    logger.info(f"Successfully cleaned up {db_path}")
        
        # Additional delay after cleanup
        await asyncio.sleep(1)
        
    except Exception as e:
        if logger:
            logger.error(f"Error during database cleanup: {e}")
        else:
            print(f"Error during database cleanup: {e}")

def extract_section(text: str, start_marker: str, end_marker: Optional[str]) -> str:
    """Extract a section from text between markers"""
    if start_marker not in text:
        return ""
    
    start_idx = text.find(start_marker)
    if end_marker and end_marker in text[start_idx:]:
        end_idx = text.find(end_marker, start_idx)
        return text[start_idx:end_idx].strip()
    else:
        return text[start_idx:].strip()


def extract_phase1_sections(text: str) -> dict:
    """Extract structured sections from phase 1 output text."""
    research_summary = extract_section(text, "## Vulnerability Research Summary", "## CVE Information")
    vulnerability_summary = extract_section(text, "## Vulnerability Summary", "[PHASE_1_COMPLETE]")

    if research_summary and vulnerability_summary:
        combined_summary = research_summary + "\n\n" + vulnerability_summary
    elif research_summary:
        combined_summary = research_summary
    elif vulnerability_summary:
        combined_summary = vulnerability_summary
    else:
        combined_summary = ""

    return {
        "vulnerability_analysis_summary": combined_summary,
        "cve_info": extract_section(text, "## CVE Information", "## Relevant Files"),
        "relevant_files": extract_section(text, "## Relevant Files", "## Sources"),
        "sources": extract_section(text, "## Sources", "## Sinks"),
        "sinks": extract_section(text, "## Sinks", "## Sanitizers"),
        "sanitizers": extract_section(text, "## Sanitizers", "## Additional"),
        "additional_taint_steps": extract_section(text, "## Additional Taint Steps", "## Vulnerability Summary"),
    }


def extract_codeql_from_text(text: str) -> str:
    """Extract CodeQL query from text"""
    codeql_pattern = r'```(?:codeql|ql)\s*\n(.*?)\n```'
    matches = re.findall(codeql_pattern, text, re.DOTALL | re.IGNORECASE)
    if matches:
        return matches[-1].strip()
    return ""


def save_output_to_chroma(phase_result: Dict, phase_num: int, task: Any, analysis_dir: str, logger: logging.Logger = None, collection_name = "") -> None:
    """Save phase output to ChromaDB for retrieval in subsequent phases
    
    Args:
        phase_result: Dictionary containing phase execution results
        phase_num: Phase number (1, 2, 3, etc.)
        task: Task object with cve_id attribute
        analysis_dir: Directory to save logs in
        logger: Optional logger instance
    """
    
    try:
        # Initialize ChromaDB client - use the same global ChromaDB as MCP server
        # Collections are uniquely named per run to ensure isolation
        client = get_chroma_client()
        cve_id = getattr(task, 'cve_id', None) or 'unknown'
        if collection_name == "":
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            run_id = f"{os.getpid()}_{timestamp}"
            collection_name = f"cve_analysis_{cve_id.lower().replace('-', '_')}_{run_id}"
        
        # Get or create collection
        try:
            collection = client.get_collection(name=collection_name)
        except:
            collection = client.create_collection(
                name=collection_name,
                metadata={
                    "cve_id": cve_id,
                    "analysis_dir": analysis_dir,
                    "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
                }
            )
        
        # Extract key information from phase result
        phase_output = phase_result.get("output", "")
        tool_workflow = []
        assistant_texts = []
        
        # Parse JSON output if available
        try:
            #json_data = json.loads(phase_result.get("stdout", "{}"))
            stdout_content = phase_result.get("stdout") or phase_result.get("output", "{}")
            json_data = json.loads(stdout_content)
            # Process messages in sequence
            for i, msg in enumerate(json_data):
                if msg.get("type") == "assistant":
                    message = msg.get("message", {})
                    content_list = message.get("content", [])
                    
                    # Extract text and tool uses from this message
                    text_parts = []
                    tool_uses = []
                    
                    for content in content_list:
                        if content.get("type") == "text":
                            text = content.get("text", "").strip()
                            if text:
                                text_parts.append(text)
                                assistant_texts.append(text)
                                
                        elif content.get("type") == "tool_use":
                            tool_name = content.get('name', 'Unknown')
                            tool_uses.append({
                                "tool": tool_name,
                                "summary": f"Used {tool_name}"
                            })
                    
                    # Create workflow entry if there are tools used
                    if tool_uses:
                        workflow_entry = {
                            "step": len(tool_workflow) + 1,
                            "context": " ".join(text_parts)[:200] if text_parts else "Continuing analysis...",
                            "tools": tool_uses
                        }
                        tool_workflow.append(workflow_entry)
            
            phase_output = "\n\n".join(assistant_texts)
            
        except Exception as e:
            if logger:
                logger.warning(f"Failed to parse JSON output: {e}")
            # Use raw output if JSON parsing fails
            pass
        
        # Create document ID
        doc_id = f"phase_{phase_num}_output"
        
        # Calculate tool statistics
        tool_stats = {}
        for step in tool_workflow:
            for tool in step["tools"]:
                tool_name = tool["tool"]
                if tool_name not in tool_stats:
                    tool_stats[tool_name] = 0
                tool_stats[tool_name] += 1
        
        # Prepare metadata
        metadata = {
            "phase": phase_num,
            "success": phase_result.get("success", False),
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
            "return_code": phase_result.get("return_code", -1),
            "has_codeql_query": bool(phase_result.get("query_file")),
            "cve_id": cve_id,
            "unique_tools": len(tool_stats),
            "total_tool_calls": sum(tool_stats.values()),
            "workflow_steps": len(tool_workflow)
        }
        
        # Extract specific sections based on phase
        sections_to_store = []
        
        if phase_num == 1:
            # For Phase 1, extract sources, sinks, sanitizers
            # Extract and combine both summary sections
            research_summary = extract_section(phase_output, "## Vulnerability Research Summary", "## CVE Information")
            vulnerability_summary = extract_section(phase_output, "## Vulnerability Summary", "[PHASE_1_COMPLETE]")
            
            combined_summary = ""
            if research_summary and vulnerability_summary:
                combined_summary = research_summary + "\n\n" + vulnerability_summary
                if logger:
                    logger.info("Combined both research and vulnerability summaries")
            elif research_summary:
                combined_summary = research_summary
                if logger:
                    logger.info("Using only research summary")
            elif vulnerability_summary:
                combined_summary = vulnerability_summary
                if logger:
                    logger.info("Using only vulnerability summary")
            else:
                if logger:
                    logger.info("No summaries found")
            extracted_sources = extract_section(phase_output, "## Sources", "## Sinks")
            extracted_sinks = extract_section(phase_output, "## Sinks", "## Sanitizers")
            extracted_sanitizers = extract_section(phase_output, "## Sanitizers", "## Additional")
            extracted_taint_steps = extract_section(phase_output, "## Additional Taint Steps", "#### ANALYSIS TIPS")

            sections = {
                "sources": extracted_sources,
                "sinks": extracted_sinks,
                "sanitizers": extracted_sanitizers,
                "additional_taint_steps": extracted_taint_steps,
                "vulnerability_analysis_summary": combined_summary,
                "cve_info": extract_section(phase_output, "## CVE Information", "## Sources"),
                "relevant_files": extract_section(phase_output, "## Relevant Files", "## Sources")
            }

            # Save extracted sections as JSON files
            json_output_dir = getattr(task, "working_dir", None) or analysis_dir or os.getcwd()
            json_filename = f"phase1_extracted_sections_{cve_id}.json"
            json_path = os.path.join(json_output_dir, json_filename)

            try:
                with open(json_path, 'w') as f:
                    json.dump(sections, f, indent=2)
                if logger:
                    logger.info(f"Saved extracted sections to: {json_path}")
            except Exception as e:
                if logger:
                    logger.error(f"Failed to save extracted sections JSON: {e}")

            for section_name, content in sections.items():
                if content:
                    sections_to_store.append({
                        "id": f"{doc_id}_{section_name}",
                        "document": content,
                        "metadata": {**metadata, "section": section_name}
                    })
        
        elif phase_num == 2:
            # For Phase 2, extract AST patterns
            sections = {
                "ast_query": extract_section(phase_output, "```ql", "```"),
                "vulnerable_ast": extract_section(phase_output, "Vulnerable Database AST Results", "Fixed Database AST Results"),
                "fixed_ast": extract_section(phase_output, "Fixed Database AST Results", "Comparative Analysis"),
                "comparative_analysis": extract_section(phase_output, "Comparative Analysis", "CodeQL AST Mapping"),
                "ast_mapping": extract_section(phase_output, "CodeQL AST Mapping", None)
            }
            
            for section_name, content in sections.items():
                if content:
                    sections_to_store.append({
                        "id": f"{doc_id}_{section_name}",
                        "document": content,
                        "metadata": {**metadata, "section": section_name}
                    })
        
        elif phase_num == 3:
            # For Phase 3, extract CodeQL query and refinements
            sections = {
                "codeql_query": extract_codeql_from_text(phase_output),
                "compilation_results": extract_section(phase_output, "Compilation Results", "Query Results"),
                "query_results": extract_section(phase_output, "Query Results", "Iteration Log"),
                "iteration_log": extract_section(phase_output, "Iteration Log", "Final Working Query"),
                "effectiveness": extract_section(phase_output, "Effectiveness Assessment", None)
            }
            
            for section_name, content in sections.items():
                if content:
                    sections_to_store.append({
                        "id": f"{doc_id}_{section_name}",
                        "document": content,
                        "metadata": {**metadata, "section": section_name}
                    })
        elif phase_num == 4:
            sections = {
                "iteration": extract_section(phase_output, "Phase 3 Query Refinement - Iteration", "## Objective"),
                "codeql_query": extract_section(phase_output, "```ql", "```"),
                "compilation_results": extract_section(phase_output, "Compilation Details", "## Execution Details"),
                "execution_details": extract_section(phase_output, "Query Evaluation Summary", "## Detailed Evaluation Analysis"),
                "evaluation_summary": extract_section(phase_output, "Detailed Evaluation Analysis", "## Next Steps") 
            }
            for section_name, content in sections.items():
                if content:
                    sections_to_store.append({
                        "id": f"{doc_id}_{section_name}",
                        "document": content,
                        "metadata": {**metadata, "section": section_name}
                    }) 
        
        # Create a concise workflow summary
        if tool_workflow:
            workflow_doc = f"# Phase {phase_num} Analysis Workflow\n\n"
            workflow_doc += f"**Tools Used:** {', '.join(tool_stats.keys())}\n"
            workflow_doc += f"**Total Steps:** {len(tool_workflow)}\n\n"
            
            for step in tool_workflow:
                workflow_doc += f"## Step {step['step']}\n"
                if step['context']:
                    workflow_doc += f"Context: {step['context']}\n\n"
                workflow_doc += "Tools:\n"
                for tool in step['tools']:
                    workflow_doc += f"- **{tool['tool']}**: {tool['summary']}\n"
                workflow_doc += "\n"
            
            sections_to_store.append({
                "id": f"{doc_id}_workflow",
                "document": workflow_doc,
                "metadata": {
                    **metadata, 
                    "section": "workflow",
                    "tool_stats": json.dumps(tool_stats)
                }
            })
        
        # Store the complete output (limited size)
        sections_to_store.append({
            "id": doc_id,
            "document": phase_output[:10000],  # Limit size for ChromaDB
            "metadata": {**metadata, "section": "complete_output"}
        })
        
        # Store in ChromaDB
        ids = [s["id"] for s in sections_to_store]
        documents = [s["document"] for s in sections_to_store]
        metadatas = [s["metadata"] for s in sections_to_store]
        
        collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
        
        if logger:
            logger.info(f"Saved phase {phase_num} output to ChromaDB collection: {collection_name}")
            logger.info(f"   Stored {len(sections_to_store)} sections")
            if tool_stats:
                logger.info(f"   Tool usage: {tool_stats}")
            
    except Exception as e:
        if logger:
            logger.error(f"Failed to save phase output to ChromaDB: {e}")
