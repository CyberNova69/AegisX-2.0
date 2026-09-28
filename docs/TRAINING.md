# AegisX — College GPU Fine-Tuning Runbook (Monday)

> **Disclaimer**: This produces a research-ready synthetic SOC triage model,
> NOT a production-grade security tool.

## Prerequisites

- [ ] College PC with NVIDIA CUDA GPU (8+ GB VRAM)
- [ ] Python 3.10+
- [ ] Git
- [ ] Internet access (for model download from HuggingFace)

---

## Step-by-Step Runbook

### Step 1: Transfer Repository

Transfer the AegisX project to the college PC:

```bash
# Option A: Git clone (if pushed to remote)
git clone <your-repo-url>
cd AegisX

# Option B: USB drive / file transfer
# Copy the entire AegisX/ folder
cd AegisX
```

### Step 2: Create Virtual Environment

```bash
python -m venv .venv

# Windows:
.venv\Scripts\activate

# Linux:
source .venv/bin/activate
```

### Step 3: Install Base Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Install Fine-Tuning Dependencies

```bash
pip install -r requirements-finetuning.txt
```

This installs: `torch`, `transformers`, `datasets`, `peft`, `trl`, `accelerate`, `bitsandbytes`.

### Step 5: Run GPU Preflight

```bash
python -m finetuning.gpu_preflight
```

**Expected output**: A report showing:
- PyTorch version and CUDA availability
- GPU name and VRAM
- Library versions
- Suitability verdict (SUITABLE or EXCELLENT)

**If verdict is NO_GPU**: Stop. Check NVIDIA drivers and CUDA installation.

### Step 6: Select Model Based on VRAM

Edit `finetuning/config.yaml` and set `model.name` based on the preflight verdict:

| VRAM | Model |
|------|-------|
| 8 GB | `unsloth/Qwen2.5-3B-Instruct-bnb-4bit` |
| 12 GB | `unsloth/Qwen2.5-7B-Instruct-bnb-4bit` |
| 16 GB | `unsloth/Meta-Llama-3.1-8B-Instruct-bnb-4bit` |
| 24 GB | `unsloth/Qwen2.5-14B-Instruct-bnb-4bit` |

**If BF16 is NOT supported** (older GPUs): Also set `training.bf16: false` and `training.fp16: true`.

### Step 7: Prepare SFT Dataset

```bash
python -m finetuning.prepare_sft_dataset
```

**Expected output**: 2,400 train + 300 validation SFT examples.
Files created in `datasets/finetuning/v0.4/sft/`.

### Step 8: Dry Run

```bash
python -m finetuning.train_lora --dry-run
```

Validates configuration, dataset paths, and GPU status without downloading a model.

**If errors**: Fix the reported issues before proceeding.

### Step 9: Run Full Test Suite

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

All tests should pass. This confirms the pipeline is correctly installed.

### Step 10: Start Training

```bash
python -m finetuning.train_lora
```

**What happens**:
1. Downloads the base model from HuggingFace (~3-8 GB, one time)
2. Applies 4-bit quantization
3. Attaches LoRA adapters
4. Trains for 3 epochs on 2,400 examples
5. Evaluates on validation set after each epoch
6. Saves the best adapter checkpoint

**Estimated time**:
- 3B model on 8 GB GPU: ~30-60 min
- 7B model on 12 GB GPU: ~60-90 min
- 8B model on 16 GB GPU: ~90-120 min

**Monitor**:
- Watch for OOM errors in the first few steps
- If OOM, reduce `training.batch_size` to 2 in `config.yaml`
- Loss should decrease over epochs

### Step 11: Verify Training Output

Check the output directory:

```bash
# Windows:
dir models\aegisx-triage\adapter

# Linux:
ls -la models/aegisx-triage/adapter
```

**Expected files**:
- `adapter_config.json` — LoRA configuration
- `adapter_model.safetensors` — LoRA weights (~50-100 MB)
- `tokenizer_config.json` — Tokenizer settings
- `training_metadata.json` — Training provenance

### Step 12: Evaluate — Baseline

```bash
python -m finetuning.evaluate_model --baseline
```

Runs the base model (without fine-tuning) on the held-out test set.
Saves results to `reports/finetuning/baseline_results.json`.

### Step 13: Evaluate — Fine-Tuned

```bash
python -m finetuning.evaluate_model --adapter-path models/aegisx-triage/adapter
```

Runs the fine-tuned model on the same held-out test set.
Saves results to `reports/finetuning/finetuned_results.json`.

### Step 14: Review Comparison Report

```bash
# Read the markdown comparison:
cat reports/finetuning/comparison.md
```

Look for improvements in:
- Classification accuracy
- Structured output validity rate
- Evidence reference validity rate

### Step 15: Test Inference

```bash
# Use any record from the test set:
python -m finetuning.inference --alert datasets/finetuning/v0.4/test.jsonl
```

Or create a custom alert JSON file with `alert`, `context`, `evidence` keys.

### Step 16: Transfer Results Back

Copy these directories back to the dev laptop:

```
models/aegisx-triage/adapter/       # LoRA adapter (~50-100 MB)
reports/finetuning/                  # Evaluation reports
```

### Step 17: Verify on Dev Laptop

```bash
# On the dev laptop:
python -m unittest discover -s tests -p "test_*.py" -v
```

Confirm all tests still pass with the adapter files present.

---

## Troubleshooting

### OOM (Out of Memory) During Training

```bash
# Reduce batch size:
python -m finetuning.train_lora --model "unsloth/Qwen2.5-3B-Instruct-bnb-4bit"

# Or edit config.yaml:
# training.batch_size: 2
# training.gradient_accumulation_steps: 8  # Keep effective batch at 16
```

### CUDA Not Available

```bash
# Check NVIDIA driver:
nvidia-smi

# Check PyTorch CUDA:
python -c "import torch; print(torch.cuda.is_available())"

# Reinstall PyTorch with CUDA:
pip install torch --index-url https://download.pytorch.org/whl/cu121
```

### Model Download Fails

```bash
# Check internet connection
# Try a smaller model first:
python -m finetuning.train_lora --model "unsloth/Qwen2.5-3B-Instruct-bnb-4bit"
```

### BitsAndBytes Errors on Windows

```bash
# Install Windows-compatible version:
pip install bitsandbytes-windows
# Or use WSL2 for training
```

---

## File Inventory

| File | Purpose | Size |
|------|---------|------|
| `finetuning/config.yaml` | Training configuration | ~1 KB |
| `finetuning/prepare_sft_dataset.py` | Dataset conversion | ~8 KB |
| `finetuning/train_lora.py` | QLoRA training | ~12 KB |
| `finetuning/evaluate_model.py` | Evaluation pipeline | ~10 KB |
| `finetuning/inference.py` | Single-alert inference | ~6 KB |
| `finetuning/gpu_preflight.py` | Hardware diagnostic | ~5 KB |
| `requirements-finetuning.txt` | GPU dependencies | ~200 B |
| `tests/test_finetuning.py` | CPU-safe unit tests | ~12 KB |
| `datasets/finetuning/v0.4/sft/` | SFT-formatted dataset | Generated |
| `models/aegisx-triage/adapter/` | Fine-tuned adapter | Generated |
| `reports/finetuning/` | Evaluation reports | Generated |
