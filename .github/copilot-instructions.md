# FHIR MCP Server - AI Coding Agent Instructions

## Project Overview
This is a **Model Context Protocol (MCP) server** that bridges FHIR (Fast Healthcare Interoperability Resources) APIs with AI/LLM tools. Built with Python 3.12+, it exposes FHIR resources as MCP tools with SMART-on-FHIR OAuth 2.0 authentication support.

## Architecture

### Core Components
- **`src/fhir_mcp_server/server.py`**: Main server using FastMCP framework. Registers 7 MCP tools (`get_capabilities`, `search`, `read`, `create`, `update`, `delete`, `get_user`) and handles OAuth callbacks at `/oauth/callback`.
- **`src/fhir_mcp_server/oauth/`**: SMART-on-FHIR OAuth implementation with PKCE flow (`server_provider.py`), type definitions (`types.py`), and common utilities (`common.py`).
- **`src/fhir_mcp_server/utils.py`**: FHIR client helpers, bundle processing, and OperationOutcome error construction.

### Key Dependencies
- **FastMCP (`mcp[cli]==1.9.1`)**: Provides MCP server framework with auth middleware, tool registration, and transport protocols (stdio/SSE/HTTP).
- **fhirpy (`2.0.15`)**: Async FHIR client library for R4 interactions.
- **pydantic-settings**: Environment-based config via `ServerConfigs` class with `FHIR_` prefix.

## Critical Patterns

### 1. Tool Registration Pattern
All MCP tools follow this structure:
```python
@mcp.tool(description="...")
async def tool_name(
    param: Annotated[Type, Field(description="...", examples=[...])],
) -> Annotated[ReturnType, Field(description="...")]:
    client: AsyncFHIRClient = await get_async_fhir_client()
    # Perform FHIR operation
    # Return resource or OperationOutcome on error
```
**Always** use `Annotated` with `Field` for comprehensive parameter/return descriptions—this informs MCP clients.

### 2. Authentication Flow
- OAuth is **enabled by default**. Disable via `FHIR_SERVER_DISABLE_AUTHORIZATION=True`.
- Token acquisition: `get_user_access_token()` checks `configs.server_access_token` (for static tokens) before querying MCP auth context.
- FHIR client creation: `get_async_fhir_client()` injects Bearer token; raises `ValueError` if unauthenticated when auth is required.

### 3. Error Handling Convention
Always return FHIR `OperationOutcome` instead of raising exceptions in tools:
```python
except ValueError as ex:
    return await get_operation_outcome(code="forbidden", diagnostics="...")
except OperationOutcome as ex:
    return ex.resource.get("issue") or await get_operation_outcome_exception()
```
This ensures MCP clients receive structured error responses.

### 4. Configuration via Environment
Use `ServerConfigs` (Pydantic settings) for all config. Key variables:
- `FHIR_SERVER_BASE_URL`: FHIR endpoint (required)
- `FHIR_SERVER_CLIENT_ID/SECRET/SCOPES`: OAuth credentials
- `FHIR_MCP_HOST/PORT`: Server binding (default: localhost:8000)
- `FHIR_MCP_REQUEST_TIMEOUT`: FHIR request timeout in seconds (default: 30)

### 5. Capability Discovery First
The `get_capabilities` tool **must be called before any resource operation** to discover valid search parameters and operations. This is enforced in tool descriptions.

## Development Workflows

### Running Tests
```bash
# Recommended: Use test runner with coverage
python run_tests.py

# Direct pytest with coverage
PYTHONPATH=src python -m pytest tests/ -v --cov=src/fhir_mcp_server --cov-report=html:htmlcov

# Run specific test suites
PYTHONPATH=src python -m pytest tests/unit/ -v
PYTHONPATH=src python -m pytest tests/integration/ -v
```
**Coverage target**: 53% overall (utils/oauth modules at 99-100%, server.py excluded).

### Running the Server
```bash
# From source with uv (preferred)
uv run fhir-mcp-server --transport streamable-http --log-level INFO

# With custom transport
uv run fhir-mcp-server --transport stdio

# From PyPI package
uvx fhir-mcp-server
```

### Docker Development
```bash
# Full stack (MCP server + HAPI FHIR + PostgreSQL + FHIR Converter)
docker-compose up -d

# Build standalone image
docker build -t fhir-mcp-server .
```
**Note**: When running locally via Docker, set `FHIR_SERVER_DISABLE_AUTHORIZATION=True` to bypass OAuth (known limitation).

### Adding New MCP Tools
1. Define async function in `register_mcp_tools()` with `@mcp.tool()` decorator
2. Use typed `Annotated` parameters with `Field` descriptions
3. Call `get_async_fhir_client()` for FHIR interactions
4. Return resources or OperationOutcomes (never raise exceptions to clients)
5. Add unit tests in `tests/unit/` (mock `AsyncFHIRClient` via `AsyncMock`)
6. Update capability descriptions in tool docstring

### Modifying OAuth Flow
- OAuth metadata discovery happens via `.well-known/smart-configuration` (see `oauth/common.py`).
- PKCE is always used; code verifier/challenge generation in `oauth/server_provider.py`.
- Token mapping stored in-memory (`OAuthServerProvider.token_mapping`); not persistent.

## Project-Specific Quirks

1. **Transport Modes**: MCP clients configure as stdio (for CLI), SSE, or streamable-http (for web). Default is streamable-http on port 8000.

2. **FHIR Resource Returns**: Tools return raw JSON dicts, not `fhirpy` Resource objects. Use `fetch_raw()` on search results.

3. **Bundle Processing**: `get_bundle_entries()` extracts `entry[].resource` from FHIR Bundles. Always check for this structure.

4. **CDA Conversion Integration**: The docker-compose stack includes Microsoft FHIR Converter at `:2019` for CDA-to-FHIR conversion (see README for curl examples).

5. **No Database**: Server is stateless except for in-memory OAuth state. Token/client mappings reset on restart.

6. **Client ID Prefix**: MCP OAuth clients get prefixed with `fhir_mcp_` in `register_client()` for identification.

## Testing Patterns

- **Mocking FHIR calls**: Use `AsyncMock` with `return_value` for `fhirpy` client methods.
- **OAuth tests**: Mock `aiohttp.ClientSession` for external OAuth endpoints.
- **Fixtures**: See `tests/conftest.py` for shared test config (e.g., `mock_server_configs`).
- **Markers**: Use `@pytest.mark.asyncio` for async tests (auto-mode enabled in pytest.ini).

## Files to Reference

- **Integration examples**: `tests/integration/test_integration.py` (full server startup scenarios)
- **OAuth flow**: `src/fhir_mcp_server/oauth/server_provider.py:authorize()` (PKCE implementation)
- **Tool examples**: `src/fhir_mcp_server/server.py:search()` (canonical FHIR search pattern)
- **Error patterns**: `src/fhir_mcp_server/utils.py:get_operation_outcome()` (structured error responses)
