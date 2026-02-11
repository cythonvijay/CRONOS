# 🔄 CRONOS GitHub Actions Integration

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         DEVELOPER                                │
│                                                                  │
│  1. Makes code changes to Python files                          │
│  2. Commits and pushes to GitHub                                │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                      GITHUB REPOSITORY                           │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  .github/workflows/cronos-analysis.yml                   │  │
│  │  ↓                                                        │  │
│  │  Triggered on: push, pull_request                        │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                     GITHUB ACTIONS                               │
│                                                                  │
│  Step 1: Checkout code                                          │
│  Step 2: Detect changed Python files                            │
│  Step 3: Get old vs new versions                                │
│  Step 4: Call CRONOS API ───────────────────┐                   │
│  Step 5: Generate reports                   │                   │
│  Step 6: Comment on PR                      │                   │
│  Step 7: Pass/Fail based on risk            │                   │
└─────────────────────────────────────────────┼───────────────────┘
                                              │
                                              ▼
                         ┌────────────────────────────────┐
                         │     CRONOS API (Render)         │
                         │                                │
                         │  POST /analyze_ci              │
                         │  {                             │
                         │    old_code: "...",            │
                         │    new_code: "...",            │
                         │    mode: "STRICT"              │
                         │  }                             │
                         └────────────────┬───────────────┘
                                          │
                                          ▼
                         ┌────────────────────────────────┐
                         │    AST ANALYSIS ENGINE         │
                         │                                │
                         │  • Parse old & new code        │
                         │  • Extract AST nodes           │
                         │  • Detect changes              │
                         │  • Calculate risk (0-100)      │
                         │  • Determine PASS/WARN/FAIL    │
                         └────────────────┬───────────────┘
                                          │
                                          ▼
                         ┌────────────────────────────────┐
                         │        API RESPONSE            │
                         │                                │
                         │  {                             │
                         │    risk: 60,                   │
                         │    status: "FAIL",             │
                         │    summary: [                  │
                         │      "Function call changed",  │
                         │      "Execution modified"      │
                         │    ]                           │
                         │  }                             │
                         └────────────────┬───────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    GITHUB ACTIONS (Results)                      │
│                                                                  │
│  • Generate Markdown report                                     │
│  • Upload artifacts                                             │
│  • Comment on PR with results                                   │
│  • Set status check (✅ PASS / ❌ FAIL)                          │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    DEVELOPER FEEDBACK                            │
│                                                                  │
│  IF FAIL:                                                       │
│    ❌ Merge blocked                                              │
│    📊 Review analysis report                                     │
│    🔧 Fix high-risk changes                                      │
│    🔄 Push new commit                                            │
│                                                                  │
│  IF WARN:                                                       │
│    ⚠️  Review recommended                                        │
│    ✅ Can merge after review                                     │
│                                                                  │
│  IF PASS:                                                       │
│    ✅ Safe to merge                                              │
│    🚀 Deploy with confidence                                     │
└─────────────────────────────────────────────────────────────────┘
```

## 🎯 Risk Scoring Examples

### Example 1: Boundary Change → PASS
```python
# Old
if x > 10:
    do_something()

# New  
if x >= 10:
    do_something()

# Analysis
Risk: 10/100
Status: ✅ PASS
Reason: "Boundary adjustment — affects edge cases only"
```

### Example 2: Function Call Change → FAIL
```python
# Old
result = is_authenticated(user)

# New
result = is_fully_authenticated(user)

# Analysis
Risk: 60/100
Status: ❌ FAIL
Reason: "Function call patterns changed — execution semantics modified"
```

### Example 3: Logic Inversion → FAIL
```python
# Old
if x > 10 and y < 5:
    execute()

# New
if x > 10 or y < 5:
    execute()

# Analysis
Risk: 95/100
Status: ❌ FAIL
Reason: "Critical logical operator change: AND → OR"
```

## 📂 File Structure

```
your-repo/
├── .github/
│   └── workflows/
│       └── cronos-analysis.yml      # GitHub Actions workflow
├── src/
│   ├── auth.py                      # Your Python code
│   ├── utils.py
│   └── validators.py
├── requirements.txt                  # For your project
└── README.md

cronos-api-repo/
├── app.py                           # CRONOS API
├── requirements.txt                 # API dependencies
├── .env                             # API keys (local only)
└── README.md
```

## 🚀 Quick Start

### 1. Deploy CRONOS API
```bash
# On Render.com
1. New Web Service
2. Connect repo with app.py
3. Set build command: pip install -r requirements.txt
4. Set start command: uvicorn app:app --host 0.0.0.0 --port $PORT
5. Deploy!
```

### 2. Configure GitHub
```bash
# Add secret
Repository Settings → Secrets → New secret
Name: CRONOS_API_URL
Value: https://your-cronos-api.onrender.com
```

### 3. Add Workflow
```bash
# Create workflow file
mkdir -p .github/workflows
cp cronos-analysis.yml .github/workflows/
git add .github/workflows/cronos-analysis.yml
git commit -m "Add CRONOS analysis workflow"
git push
```

### 4. Test It
```bash
# Make a test change
echo "def test(): pass" > test.py
git add test.py
git commit -m "Test CRONOS integration"
git push

# Check Actions tab on GitHub to see the workflow run!
```

## 📊 Analysis Modes

| Mode | Risk Threshold | Use Case |
|------|---------------|----------|
| **STRICT** | Blocks ANY semantic change (≥60) | Production, critical paths |
| **BOUNDARY** | Allows boundary changes (<20) | Development, feature branches |
| **CONTRACT** | Allows minor changes (<50) | Testing, experimental code |

## 🎓 Understanding Results

### Status Badges
- ✅ **PASS (0-20)**: Safe to merge, minimal/no risk
- ⚠️ **WARN (21-50)**: Review recommended, doesn't block
- ❌ **FAIL (51-100)**: High risk, merge blocked

### Common Findings

| Finding | Risk | Example |
|---------|------|---------|
| Variable rename | 5 | `x` → `result` |
| Boundary change | 10 | `>` → `>=` |
| New function added | 30 | Added `validate()` |
| Import removed | 55 | Removed `import os` |
| Function call changed | 60 | `auth()` → `check_auth()` |
| Signature changed | 65 | `foo(x)` → `foo(x, y)` |
| Equality inverted | 80 | `==` → `!=` |
| Logic inverted | 95 | `AND` → `OR` |

## 🔍 Troubleshooting

### Workflow not running?
- ✅ Check workflow file is in `.github/workflows/`
- ✅ Verify YAML syntax is valid
- ✅ Ensure pushing to configured branch

### API connection failed?
- ✅ Verify `CRONOS_API_URL` secret is set
- ✅ Test API: `curl https://your-url.onrender.com/`
- ✅ Check Render logs for errors

### All files failing?
- ✅ Try `BOUNDARY` mode instead of `STRICT`
- ✅ Review specific findings in artifacts
- ✅ Check if changes are actually high-risk

## 📚 Resources

- **Setup Guide**: `GITHUB_SETUP_GUIDE.md`
- **Workflow File**: `cronos-analysis.yml`
- **Test Script**: `test_integration.sh`
- **API Documentation**: See `app.py` health endpoint

## 🎉 You're Ready!

Your repository is now protected by automated CRONOS code analysis! 🛡️

Every Python change will be analyzed for risk before merging.
