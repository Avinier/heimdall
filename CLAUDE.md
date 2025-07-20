# CLAUDE.md - 0xPPL/eth-insights

## 0. Project overview

0xPPL is a Web3 super-app platform for building cross-chain social experiences and analytics. It helps users discover, track, and interact with blockchain identities across multiple chains while providing real-time social features and comprehensive analytics. Key components:

- **backend/**: Django monolith for cross-chain identities, social graphs, feeds, and notifications. MOST OF YOUR WORK WILL BE IN THIS DIRECTORY.
- **gobase/**: Go microservices for high-throughput blockchain and profile APIs
- **aurora_relayer/**: Node service that syncs Aurora↔NEAR blocks
- **socket-sdk/**: TypeScript SDK for cross-chain swaps and interactions

**Golden rule**: When unsure about implementation details or requirements, ALWAYS consult the developer rather than making assumptions.



---

## 1. Non-negotiable golden rules

| #: | AI *may* do                                                            | AI *must NOT* do                                                                    |
|---|------------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| G-0 | Whenever unsure about something that's related to the project, ask the developer for clarification before making changes.    |  ❌ Write changes or use tools when you are not sure about something project specific, or if you don't have context for a particular feature/decision. |
| G-1 | Generate code **only inside** relevant source directories (e.g., `backend/chaindata/` for core blockchain data processing, `backend/chaindata/feed/` and `backend/chaindata/views.py` for feed functionality, `gobase/` for Go microservices, other Django apps like `backend/_0xppl/`, `backend/activities/`, etc.) or explicitly pointed files.    | ❌ Touch `tests/`, `migrations/`, `http_recordings/`, or any test files (humans own tests & specs). |
| G-2 | REGULARLY add/update **`AIDEV-NOTE:` anchor comments** near non-trivial edited code and after large refactors. | ❌ Delete or mangle existing `AIDEV-` comments.                                     |
| G-3 | Follow lint/style configs (`conf/pyproject.toml`, `conf/.flake8`, `.pre-commit-config.yaml`). Use Black and Flake8 via pre-commit hooks instead of manually re-formatting code. | ❌ Re-format code to any other style or ignore Python 3.8 compatibility.           |
| G-4 | For changes >300 LOC or >3 files, **ask for confirmation**.            | ❌ Refactor large modules without human guidance.                                     |
| G-5 | Only run tests when explicitly requested by user | ❌ Run tests automatically after changes |
| G-6 | Stay within the current task context. Inform the dev if it'd be better to start afresh.                                  | ❌ Continue work from a prior prompt after "new task" – start a fresh session.      |
| G-7 | Always present completion options after task completion | ❌ Auto-commit or auto-test without asking |
| G-8 | Use exact GitHub CLI commands for PRs | ❌ Use generic git instructions |
| G-9 | Test only when explicitly requested | ❌ Create tests proactively |

---

## 2. Build, test & utility commands

Use Docker commands for consistency (all commands must run inside containers to ensure correct database and dependency resolution).

```bash
# Django management commands (always prefix with docker exec)
docker exec eth-insights-backend python /app/manage.py migrate
docker exec eth-insights-backend python /app/manage.py makemigrations
docker exec eth-insights-backend python /app/manage.py shell

# Testing (only run specific tests, avoid full suite)
# IMPORTANT: Never use pytest - only use Django's test runner
docker exec eth-insights-backend python /app/manage.py test <app_name.tests.test_module.TestClass> --gevent --parallel 1 --exclude-tag=flaky --noinput

# Code quality
pre-commit run --files <file>   # Run Black, Flake8, and other pre-commit hooks
./backend/docker_manage.sh shell # Django shell helper (use sparingly)

# Docker environment
docker-compose up -d            # Start services
docker-compose -f docker-compose-test.yml up -d  # Test environment
docker logs -f eth-insights-backend  # View logs
```

**Golden rule**: 
- Always use `docker exec eth-insights-backend ...` for Django commands. Never run Django commands on the host machine.
- CRITICAL: Never open interactive shell in containers (loses tool access)
- ❌ AVOID: docker exec -it eth-insights-backend bash
- ✅ USE: docker exec eth-insights-backend <command>


---

## 3. Coding standards

*   **Python**: 3.8 (avoid PEP 604 `|` unions; use `Union`/`Optional` from `typing`), Django 4.1, Celery 5, web3.py for blockchain interactions.
*   **Formatting**: Black enforces 88-char lines, double quotes. Flake8 for linting. Import organization via `pyflyby` (Docker-based).
*   **Typing**: Strict typing with `typing` module; Pydantic v1.9 for validation models; `from __future__ import annotations` preferred.
*   **Naming**: `snake_case` (functions/variables), `PascalCase` (classes), `SCREAMING_SNAKE` (constants).
*   **Error Handling**: Web3/blockchain-aware exceptions; async patterns for blockchain calls; proper Sentry integration.
*   **Documentation**: Minimal docstrings; code should be self-documenting with clear naming.
*   **Testing**: Use `AppTestCase`/`AppTransactionTestCase` base classes; VCR for HTTP recording; Docker-based test execution only.

**Error handling patterns**:
- Use typed, hierarchical exceptions defined in `exceptions.py`
- Catch specific exceptions, not general `Exception`
- Use context managers for resources (database connections, file handles)
- For async code, use `try/finally` to ensure cleanup

Example:
```python
from agents_api.common.exceptions import ValidationError

async def process_data(data: dict) -> Result:
    try:
        # Process data
        return result
    except KeyError as e:
        raise ValidationError(f"Missing required field: {e}") from e
```

---

## 4. Project layout & Core Components

The backend is a Django monolith with microservice patterns, handling cross-chain blockchain data, social features, and real-time analytics.

| Directory                         | Description                                       |
| --------------------------------- | ------------------------------------------------- |
| **CORE MODULES** | |
| `backend/chaindata/`              | **MOST IMPORTANT** - Universal blockchain data processing, multi-chain analytics, and cross-chain abstraction layer |
| `backend/chaindata/models.py`     | **KEY FILE** (85KB, 2420 lines) - Core blockchain models: Transaction, Address, ContractDetails, ProtocolData |
| `backend/chaindata/views.py`      | **CRITICAL FILE** (137KB, 4207 lines) - Main API endpoints for blockchain data, portfolio, feeds |
| `backend/chaindata/api.py`        | **MAJOR FILE** (89KB, 2466 lines) - Business logic layer for blockchain operations and data enrichment |
| `backend/chaindata/utils.py`      | **CORE FILE** (88KB, 2583 lines) - Universal utilities, chain abstraction, price handling, metadata |
| `backend/chaindata/constants.py`  | **CONFIG FILE** (71KB, 2162 lines) - Chain definitions (IntChainId), protocol mappings, configuration |
| `backend/chaindata/feed/`         | **CRITICAL** - Activity feed generation, ranking algorithms, social graph processing |
| `backend/chaindata/registry.py`   | Chain registration system, strategy pattern for multi-chain support |
| | |
| `backend/activities/`             | **ACTIVITY TRACKING & SOCIAL FEEDS** - User activity tracking, feed generation, engagement scoring |
| `backend/activities/helpers.py`   | **MASSIVE FILE** (234KB, 6535 lines) - Activity parsing, feed scoring, engagement logic |
| `backend/activities/models.py`    | FeedItemBlob, ViewerSpecificFeedItem, engagement models |
| `backend/activities/delayed_jobs.py` | **MAJOR FILE** (96KB, 2712 lines) - Background activity processing, blob creation, feed updates |
| `backend/activities/tasks.py`     | **KEY FILE** (44KB, 1177 lines) - Celery tasks for activity generation and notifications |
| `backend/activities/twitter_mcp/` | Twitter bot integration with MCP (Model Context Protocol) |
| | |
| `backend/_0xppl/`                 | **CORE APPLICATION LOGIC** - User identity management, social features, profile system |
| `backend/_0xppl/api.py`          | **PLATFORM APIS** (53KB, 1573 lines) - Onboarding, identity management, social graph |
| `backend/_0xppl/views.py`        | **HTTP ENDPOINTS** (21KB, 716 lines) - Request handling, response formatting |
| `backend/_0xppl/profiles/`       | **User identity system** - Cross-chain identity resolution, address bundling |
| `backend/_0xppl/profiles/identity/` | Identity models, bundling, crowdsourced profiles, verification systems |
| `backend/_0xppl/social/`         | **Social media features** - Posts, likes, reposts, threads, cross-posting |
| `backend/_0xppl/onboarding/`     | User onboarding flows, invite systems, growth features |
| | |
| `gobase/`                        | **HIGH-PERFORMANCE GO MICROSERVICES** - High-throughput APIs, real-time data processing |
| `gobase/main.go`                 | **Service orchestrator** (117 lines) - HTTP routing, middleware, service initialization |
| `gobase/solana/`                 | **HIGH-PRIORITY** (60 files) - Solana transaction processing, token analysis, program parsing |
| `gobase/evm/`                    | EVM chain processing, contract interactions, multi-chain support |
| `gobase/bitcoin/`                | Bitcoin network integration, UTXO tracking, address analysis |
| `gobase/feed/`                   | High-performance feed APIs, activity aggregation, real-time processing |
| `gobase/profile/`                | Profile management, identity resolution at scale |
| `gobase/core/`                   | Common utilities, HTTP handlers, Sentry integration, profiling |
| | |
| **MULTI-CHAIN SUPPORT** | |
| `backend/chaindata/evm/`         | **Ethereum-compatible chains** - Polygon, BSC, Arbitrum, Base, Optimism, etc. |
| `backend/chaindata/solana/`      | **Solana blockchain** - Native program parsing, transaction processing |
| `backend/chaindata/bitcoin/`     | **Bitcoin network** - UTXO model, address tracking, Runes portfolio tracking |
| | |
| **TRANSACTION PROCESSING** | |
| `backend/chaindata/transaction_jobs.py` | **MAJOR FILE** (101KB) - Background transaction processing, enrichment pipelines |
| `backend/chaindata/internal_trace_tasks.py` | **KEY FILE** (44KB) - EVM internal transaction tracing, contract interactions |
| `backend/chaindata/tasks.py`     | **CELERY TASKS** (651 lines) - Blockchain data processing, background jobs |


### **Key Integration Points**

1. **chaindata** ↔ **activities**: Blockchain events → Activity feed items
2. **activities** ↔ **_0xppl**: Activity feeds → Social engagement → User profiles  
3. **gobase** ↔ **backend**: High-performance APIs ↔ Business logic
4. **chaindata/feed** ↔ **activities**: Feed algorithms ↔ Activity scoring

**Golden Rule**: Most blockchain-related development happens in `backend/chaindata/`. Social and identity features in `backend/_0xppl/`. High-performance operations in `gobase/`.

**Key domain models**:
- **Identity**: Cross-chain user identities and wallet mappings
- **Address**: Blockchain addresses with chain-specific data
- **Transaction**: Multi-chain transaction processing and enrichment
- **Feed**: Social activity feeds with ranking algorithms
- **Portfolio**: Holdings, PnL, and portfolio analytics
- **Activity**: User interactions, follows, and social graph

---

## 5. Anchor comments (**IMPORTANT**)

Add specially formatted comments throughout the codebase, where appropriate, for yourself as inline knowledge that can be easily `grep`ped for. 

### Guidelines:

- Use `AIDEV-NOTE:`, `AIDEV-TODO:`, or `AIDEV-QUESTION:` (all-caps prefix) for comments aimed at AI and developers.
- Keep them concise (≤ 120 chars).
- **Important:** Before scanning files, always first try to **locate existing anchors** `AIDEV-*` in relevant subdirectories.
- **Update relevant anchors** when modifying associated code.
- **Do not remove `AIDEV-NOTE`s** without explicit human instruction.
- Make sure to add relevant anchor comments, whenever a file or piece of code is:
  * too long, or
  * too complex, or
  * very important, or
  * confusing, or
  * could have a bug unrelated to the task you are currently working on.

Example:
```python
# AIDEV-NOTE: perf-hot-path; avoid extra allocations (see ADR-24)
async def render_feed(...):
    ...
```

---

## 6. Commit & PR Discipline

### Automated PR Creation
After task completion and user approval:
```bash
# Standard PR creation flow
git add -A
git commit -m "feat|fix|refactor: concise description [AI]"
git push origin $(git branch --show-current)
gh pr create \
  --title "feat|fix|refactor: Clear title" \
  --body "## Changes\n- Change 1\n- Change 2\n\n## Testing\n- [ ] Manual testing completed\n- [ ] Unit tests pass"
```

### Commit Message Format
- `feat:` New features
- `fix:` Bug fixes  
- `refactor:` Code improvements
- `docs:` Documentation updates
- Always suffix with `[AI]` tag

---

## 7. Django & Web3 patterns

*   **Models**: Use Django models with proper foreign keys, indexing for performance. Multi-chain support via `ChainId` enums.
*   **Views**: RESTful API patterns with Django REST Framework. Always validate blockchain addresses and chain IDs.
*   **Async Operations**: Use Celery for blockchain data fetching, heavy computations, and background tasks.
*   **Caching**: Redis for feed caching, user sessions. Cache blockchain data aggressively to reduce RPC calls.
*   **Database**: PostgreSQL with multiple databases (`default`, `bigtables`, `crawler`). Use database routing for large datasets.

**Web3 pattern examples**:
```python
# Address validation
from chaindata.address_utils import is_valid_address
from chaindata.constants import IntChainId

def process_address(address: str, chain_id: int):
    if not is_valid_address(address, IntChainId(chain_id)):
        raise ValidationError("Invalid address for chain")

# Async blockchain calls
from chaindata.utils import get_web3_client
async def fetch_balance(address: str, chain_id: int):
    web3 = get_web3_client(chain_id)
    balance = await web3.eth.get_balance(address)
    return balance
```

---

## 8. Testing patterns

### Testing Philosophy
- **Tests are verification, not development**
- AI creates tests only when explicitly requested
- Prefer running existing tests over creating new ones

### When User Requests Testing
1. First suggest running existing related tests
2. If new test needed, follow existing patterns exactly
3. Always run in Docker with proper flags
4. Report results clearly

### Test Execution Commands
```bash
# Always use this format:
docker exec eth-insights-backend python /app/manage.py test \
  <app>.<test_module>.<TestClass>.<test_method> \
  --gevent --parallel 1 --exclude-tag=flaky --noinput

# Never use pytest or other test runners
```

### Legacy Testing Patterns
*   **Base Classes**: Inherit from `AppTestCase` or `AppTransactionTestCase` from `tools.tests`.
*   **VCR Recording**: Use `@with_recorded_http` decorator for external API calls.
*   **Docker Only**: Never run tests outside Docker containers. Use `docker exec eth-insights-backend ...`.
*   **Flaky Tests**: Always exclude with `--exclude-tag=flaky` flag.
*   **Database**: Tests use separate test databases with snapshots for faster execution.

**Test example**:
```python
from tools.tests import AppTestCase, with_recorded_http

class TestChainDataAPI(AppTestCase):
    @with_recorded_http
    def test_fetch_transaction(self):
        # Test implementation with VCR recording
        pass
```

---

## 9. Dependencies and configuration

*   **Python Dependencies**: `backend/requirements.txt` (main), `backend/requirements.dev.txt`, `backend/requirements.test.txt`.
*   **Go Dependencies**: `gobase/go.mod`, `gobase/go.sum`. Always run `go mod tidy` after changes.
*   **Code Quality**: Pre-commit hooks in `.pre-commit-config.yaml` run Black, Flake8, and `pyflyby` (import organization).
*   **Docker**: All services defined in `docker-compose*.yml`. Use appropriate compose file for environment.

**Configuration files**:
- `conf/pyproject.toml` - Black formatting configuration
- `conf/.flake8` - Flake8 linting rules
- `conf/*.env` - Environment-specific settings

---

## 12. Key File & Pattern References

*   **Core Models**: `backend/chaindata/models.py` - Transaction, Address, Identity, Portfolio models with multi-chain support
*   **API Endpoints**: `backend/chaindata/views.py` - Django REST views, blockchain data endpoints, feed APIs
*   **Background Jobs**: `backend/tools/delayed_job/` - Priority task queues, async blockchain processing
*   **Multi-chain Utils**: `backend/chaindata/utils.py` - Chain abstraction, address validation, web3 clients

---

## 14. Domain-Specific Terminology

*   **IntChainId**: Enum for supported blockchain networks (Ethereum, Polygon, BSC, Arbitrum, Solana, Bitcoin, etc.). Core identifier used throughout the system for multi-chain support. Located in `backend/chaindata/constants.py`.

*   **Identity**: Top-level interactable entity representing individuals, VCs, orgs, or protocols. Aggregates multiple blockchain addresses into unified profiles with crowdsourced and user-customized data. Core model in `backend/_0xppl/profiles/identity/models.py`.

*   **Transaction**: Multi-chain transaction processing and enrichment. Stores decoded transaction data with enriched context across all supported blockchains. Core model in `backend/chaindata/models.py`.

*   **DelayedJob**: Background task processing system with priority queues. Handles heavy blockchain processing, feed generation, and data enrichment asynchronously. Framework in `backend/tools/delayed_job/`.

*   **AddressEnum**: Classification system for blockchain address types (External, Contract, FungibleToken, NFT, MultiSig, LPToken, etc.). Used for address categorization. Defined in `backend/chaindata/constants.py`.

*   **AIDEV-NOTE/TODO/QUESTION**: Specially formatted anchor comments (`AIDEV-NOTE:`, `AIDEV-TODO:`, `AIDEV-QUESTION:`) used throughout the codebase to provide inline context for AI assistants and developers.

---

## 14. AI Development Workflow

### Standard Task Flow
Every task follows this pattern:

1. **Receive & Analyze Task**
   - Understand requirements
   - Search codebase (10+ targeted searches)
   - Review existing patterns
   - Ask clarifying questions if needed

2. **Execute Task**
   - **Coding**: Implement in appropriate directories
   - **Debugging**: Reproduce → investigate → document findings
   - **Integration**: Add new services/libraries following patterns

3. **Present Completion & Options**
   Always end with:
   ```
   ✅ Task completed. Changes made:
   - [List of files modified]
   - [Brief summary of changes]
   
   Would you like me to:
   1. 📤 Create a PR for these changes
   2. 🧪 Test these changes
   3. 🔄 Make additional modifications
   ```

4. **Execute User Choice**

### Option 1: Creating PR (Recommended Path)
```bash
# When user chooses PR:
git add -A
git commit -m "feat: [description] [AI]"
git push origin [current-branch]
gh pr create --title "[Title]" --body "[Description of changes]"
```

### Option 2: Testing (Use Cautiously)
```bash
# Only when explicitly requested:
# For existing tests:
docker exec eth-insights-backend python /app/manage.py test [specific.test.path] --gevent --parallel 1 --exclude-tag=flaky --noinput

# For new tests (discouraged but possible):
# 1. Create test file following existing patterns
# 2. Run specific test only
# 3. Report results
```

### Workflow Decision Tree
```
Task Given
    ├─> Type: Bug?
    │   └─> Debug First → Code Fix → Prompt User
    ├─> Type: Feature?
    │   └─> Code Implementation → Prompt User
    └─> Type: Integration?
        └─> Research → Implementation → Prompt User
```

---

## 15. AI Assistant Workflow: Step-by-Step Methodology

When responding to user instructions, the AI assistant (Claude, Cursor, GPT, etc.) should follow this process to ensure clarity, correctness, and maintainability:

1. **Consult Relevant Guidance**: When the user gives an instruction, consult the relevant instructions from `AGENTS.md` files (both root and directory-specific) for the request.
2. **Clarify Ambiguities**: Based on what you could gather, see if there's any need for clarifications. If so, ask the user targeted questions before proceeding.
3. **Break Down & Plan**: Break down the task at hand and chalk out a rough plan for carrying it out, referencing project conventions and best practices.
4. **Trivial Tasks**: If the plan/request is trivial, go ahead and get started immediately.
5. **Non-Trivial Tasks**: Otherwise, present the plan to the user for review and iterate based on their feedback.
6. **Track Progress**: Use a to-do list (internally, or optionally in a `TODOS.md` file) to keep track of your progress on multi-step or complex tasks.
7. **If Stuck, Re-plan**: If you get stuck or blocked, return to step 3 to re-evaluate and adjust your plan.
8. **Update Documentation**: Once the user's request is fulfilled, update relevant anchor comments (`AIDEV-NOTE`, etc.) and `AGENTS.md` files in the files and directories you touched.
9. **User Review**: After completing the task, ask the user to review what you've done, and repeat the process as needed.
10. **Session Boundaries**: If the user's request isn't directly related to the current context and can be safely started in a fresh session, suggest starting from scratch to avoid context confusion.
