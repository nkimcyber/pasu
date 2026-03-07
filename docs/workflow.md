# IAM Analyzer — Development Workflow & Future Enhancements

## Step 10: Development Workflow

This workflow is designed so the developer's only manual tasks are **reviewing diffs and pushing commits**. Everything else — code generation, testing, and debugging — is automated.

---

### Actors

| Actor | Responsibility |
|---|---|
| **Developer** | Writes the prompt describing a feature; reviews diffs; pushes commits |
| **Claude Dev Agent** | Generates Python source files from the prompt |
| **Debug Agent** | Sends failing traces to Claude; applies the returned fix |
| **GitHub Actions CI** | Runs tests; triggers Debug Agent on failure; gates merges |

---

### Full Workflow — Step by Step

```
Developer
   │
   ├─ 1. Describe feature in plain English ──► Claude Dev Agent
   │                                              (prompts/dev_agent_prompt.md)
   │                                              │
   │                                              ▼
   │                                        Generates source files
   │                                        (app/*.py, tests/*.py)
   │
   ├─ 2. Review generated code locally
   │
   ├─ 3. git add . && git push ──────────────► GitHub Actions CI
   │                                              │
   │                                    ┌─────── job: test ───────┐
   │                                    │                          │
   │                                 PASS ✅                    FAIL ❌
   │                                    │                          │
   │                            prepare-review              job: debug
   │                            (archive source)     (Debug Agent runs)
   │                                    │                          │
   │                                    │               Claude returns fix
   │                                    │               Patch applied to
   │                                    │               app/analyzer.py
   │                                    │               Artifact uploaded
   │                                    │                          │
   └─ 4. Developer reviews artifact ◄───┴──────────────────────────┘
         downloads patched file (if debug ran)
         reviews diff, approves, and pushes again
```

---

### Local Development Cycle (Windows + venv)

```powershell
# 1. Activate virtual environment
.\venv\Scripts\Activate.ps1

# 2. Run tests locally before pushing
pytest tests/ --tb=short -q

# 3. If tests fail, run Debug Agent interactively
python scripts\debug_agent.py `
  --trace pytest_output.txt `
  --file app\analyzer.py `
  --interactive

# 4. Review suggestion, approve, then push
git add .
git commit -m "fix: apply debug agent patch"
git push
```

---

### CI Trigger Rules

| Event | Jobs triggered |
|---|---|
| Any `git push` | `test` |
| Tests pass | `test` → `prepare-review` |
| Tests fail | `test` → `debug` (Debug Agent runs) |
| PR to `main` | `test` (merge gate) |

---

### Secrets Required in GitHub Repository

| Secret Name | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Used by Debug Agent to call Claude API in CI |

---

## Step 11: Future Enhancements

The following improvements are candidates for future iterations. They extend the current automated workflow without changing its core design.

### Testing
- Expand test coverage to include `aws_client.list_policies` pagination (multiple pages of results).
- Add integration tests that run against a real AWS account using a dedicated test IAM role with read-only permissions; gate these tests behind a separate CI job triggered only on `main`.
- Add parameterized tests for edge-case policy documents (empty statements, deny-only policies, multi-statement policies).
- Introduce test coverage reporting via `pytest-cov` and enforce a minimum threshold (e.g., 80%) as a CI gate.

### Debug Agent
- Extend the Debug Agent to accept a `--file` glob pattern so it can attempt fixes across multiple source files in a single invocation.
- Add a retry limit: if Claude's fix does not pass tests after N attempts (configurable), the agent exits and flags the failure for manual review rather than looping indefinitely.
- Log all fix attempts and their outcomes to a structured JSON file for audit purposes.

### CI/CD
- Add environment-specific deployment jobs: `deploy-staging` (triggers on `main`) and `deploy-production` (manual approval gate) using GitHub Environments.
- Add a lint job (`flake8` or `ruff`) that runs in parallel with the test job and blocks the prepare-review job if lint fails.
- Cache the venv between CI runs using `actions/cache` keyed on the hash of `requirements.txt` to reduce build times.

### Application
- Add a `/api/v1/batch-analyze` endpoint that accepts a list of policy ARNs and returns analysis results for all of them, using `asyncio.gather` for concurrent AWS calls.
- Add structured logging (JSON format) using Python's `logging.config.dictConfig` so logs can be ingested by CloudWatch or Datadog.
- Add request-level tracing with a unique `request_id` propagated from the FastAPI middleware through to the Claude API call and AWS calls.

### Security
- Add AWS STS `assume_role` support in `aws_client.py` so the application can analyze policies across multiple AWS accounts without storing long-lived credentials.
- Validate that all policy ARNs passed to `/analyze` match the expected ARN format (`arn:aws:iam::...`) before making any AWS calls, using a Pydantic `validator`.