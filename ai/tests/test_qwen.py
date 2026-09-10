import torch
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    BitsAndBytesConfig,
)

MODEL_PATH = r"F:\NM\AegisX-2.0\models\Qwen2.5-7B-Instruct"

print("=" * 60)
print("AegisX - Qwen2.5-7B-Instruct 4-bit Test")
print("=" * 60)

print("\nGPU:", torch.cuda.get_device_name(0))
print(
    "Total VRAM:",
    round(torch.cuda.get_device_properties(0).total_memory / 1024**3, 2),
    "GB",
)

# 4-bit configuration
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,
    bnb_4bit_use_double_quant=True,
)

print("\nLoading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)

print("Loading Qwen in 4-bit...")
model = AutoModelForCausalLM.from_pretrained(
    MODEL_PATH,
    quantization_config=bnb_config,
    device_map="auto",
)

print("\n" + "=" * 60)
print("MODEL LOADED SUCCESSFULLY")
print("=" * 60)

print("Model device:", model.device)
print(
    "GPU memory allocated:",
    round(torch.cuda.memory_allocated(0) / 1024**3, 2),
    "GB",
)

messages = [
    {
        "role": "system",
        "content": (
            "You are AegisX, an AI SOC investigation assistant. "
            "Analyze security evidence carefully and avoid unsupported conclusions."
        ),
    },
    {
        "role": "user",
        "content": (
            "A Windows endpoint executed powershell.exe as a child of "
            "WINWORD.EXE. The PowerShell command used an encoded command "
            "and the process subsequently connected to an external IP. "
            "Assess this alert and explain the key evidence."
        ),
    },
]

prompt = tokenizer.apply_chat_template(
    messages,
    tokenize=False,
    add_generation_prompt=True,
)

inputs = tokenizer(
    prompt,
    return_tensors="pt",
).to("cuda")

print("\nGenerating response...\n")

with torch.no_grad():
    outputs = model.generate(
        **inputs,
        max_new_tokens=200,
        do_sample=False,
    )

response = tokenizer.decode(
    outputs[0][inputs["input_ids"].shape[1]:],
    skip_special_tokens=True,
)

print("=" * 60)
print("QWEN RESPONSE")
print("=" * 60)
print(response)

print("\n" + "=" * 60)
print("GPU MEMORY")
print("=" * 60)

print(
    "Allocated:",
    round(torch.cuda.memory_allocated(0) / 1024**3, 2),
    "GB",
)

print(
    "Reserved:",
    round(torch.cuda.memory_reserved(0) / 1024**3, 2),
    "GB",
)

print(
    "Peak:",
    round(torch.cuda.max_memory_allocated(0) / 1024**3, 2),
    "GB",
)