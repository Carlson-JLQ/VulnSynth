#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
from typing import Any

import anyio
from mcp import ClientSession, StdioServerParameters, stdio_client


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_DB_PATH = os.path.join(REPO_ROOT, "chroma_db")


def preview(value: Any, limit: int = 320) -> str:
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False)
    value = value.replace("\n", " ")
    return value if len(value) <= limit else value[:limit] + " ..."


def build_server_parameters(args: argparse.Namespace) -> StdioServerParameters:
    cmd_args = ["--client-type", args.mode]
    if args.mode == "persistent":
        cmd_args.extend(["--data-dir", args.data_dir])
    else:
        cmd_args.extend(
            [
                "--host",
                args.host,
                "--port",
                str(args.port),
                "--custom-auth-credentials",
                args.auth_token,
                "--ssl",
                str(args.ssl).lower(),
            ]
        )

    return StdioServerParameters(
        command=args.chroma_mcp_path,
        args=cmd_args,
        env=os.environ.copy(),
    )


async def run_test(args: argparse.Namespace) -> int:
    server = build_server_parameters(args)

    print("STARTING_MCP")
    print("command:", " ".join([server.command] + server.args))

    async with stdio_client(server) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            init_result = await session.initialize()
            print("INITIALIZE_OK")
            print("serverInfo:", init_result.serverInfo)
            print("protocolVersion:", init_result.protocolVersion)

            tools_result = await session.list_tools()
            tool_names = [tool.name for tool in tools_result.tools]
            print("TOOLS_LIST_OK")
            print("tool_count:", len(tool_names))
            print("sample_tools:", tool_names[:12])

            if "chroma_get_documents" not in tool_names:
                print("FAILED: chroma_get_documents not exposed by MCP server")
                return 3

            call_result = await session.call_tool(
                "chroma_get_documents",
                {
                    "collection_name": args.collection,
                    "where": {"cve_id": args.cve_id},
                    "include": ["documents", "metadatas"],
                    "limit": 1,
                },
            )

            print("TOOL_CALL_OK")
            print("isError:", call_result.isError)
            if call_result.content:
                first = call_result.content[0]
                first_text = getattr(first, "text", None)
                if first_text:
                    print("tool_content_preview:", preview(first_text))
                else:
                    print("tool_content_type:", type(first).__name__)
                    print("tool_content_preview:", preview(first.model_dump()))
            else:
                print("tool_result: empty content")

    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Test connectivity to chroma-mcp using the official MCP stdio client."
    )
    parser.add_argument(
        "--mode",
        choices=["persistent", "http"],
        default="persistent" if not os.environ.get("CHROMA_HOST") else "http",
    )
    parser.add_argument("--data-dir", default=os.environ.get("CHROMA_DB_PATH", DEFAULT_DB_PATH))
    parser.add_argument("--host", default=os.environ.get("CHROMA_HOST", "localhost"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("CHROMA_PORT", "8000")))
    parser.add_argument("--auth-token", default=os.environ.get("CHROMA_AUTH_TOKEN", "test"))
    parser.add_argument("--ssl", action="store_true", default=False)
    parser.add_argument("--collection", default="nist_cve_cache")
    parser.add_argument("--cve-id", default="CVE-2025-27818")
    parser.add_argument(
        "--chroma-mcp-path",
        default=os.environ.get("CHROMA_MCP_PATH", "chroma-mcp"),
        help="Path to chroma-mcp executable",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    return anyio.run(run_test, args)


if __name__ == "__main__":
    raise SystemExit(main())
