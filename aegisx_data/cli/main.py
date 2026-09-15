"""Unified CLI entry point for the AegisX Data Platform.

Usage:
    python -m aegisx_data ingest --source cicids --output datasets/external/raw/
    python -m aegisx_data process --input datasets/external/raw/ --output datasets/external/processed/
    python -m aegisx_data quality --input datasets/external/processed/
    python -m aegisx_data version --input datasets/external/processed/ --tag v1.0
    python -m aegisx_data sft --version v1.0 --output datasets/external/sft/
    python -m aegisx_data gpu-check
    python -m aegisx_data train --dataset-version v1.0 --dry-run
    python -m aegisx_data evaluate --run-id <run_id>
    python -m aegisx_data registry list
    python -m aegisx_data registry promote --model-id <model_id>
    python -m aegisx_data pipeline --source cicids --limit 1000
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.config import PROJECT_ROOT, load_config


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="aegisx_data",
        description="AegisX External Cybersecurity Dataset & Fine-Tuning Platform",
    )
    parser.add_argument("--config", type=Path, help="Path to config file")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- ingest ---
    ingest_parser = subparsers.add_parser("ingest", help="Ingest an external dataset")
    ingest_parser.add_argument("--source", required=True,
                               choices=["cicids", "ctu13", "unsw_nb15", "ember",
                                        "mitre", "custom", "huggingface"],
                               help="Dataset source")
    ingest_parser.add_argument("--input", type=Path, help="Input file/directory")
    ingest_parser.add_argument("--output", type=Path, help="Output directory")
    ingest_parser.add_argument("--limit", type=int, help="Max records to ingest")
    ingest_parser.add_argument("--version", default="2017", help="Dataset version (CICIDS)")

    # --- process ---
    process_parser = subparsers.add_parser("process", help="Process raw records")
    process_parser.add_argument("--input", type=Path, required=True, help="Input JSONL file")
    process_parser.add_argument("--output", type=Path, help="Output JSONL file")

    # --- quality ---
    quality_parser = subparsers.add_parser("quality", help="Analyze dataset quality")
    quality_parser.add_argument("--input", type=Path, required=True, help="Input JSONL file")
    quality_parser.add_argument("--output", type=Path, help="Report output path")
    quality_parser.add_argument("--format", choices=["json", "markdown", "both"],
                                default="both", help="Report format")

    # --- version ---
    version_parser = subparsers.add_parser("version", help="Manage dataset versions")
    version_parser.add_argument("action", nargs="?", default="list",
                                choices=["list", "create", "verify", "diff"])
    version_parser.add_argument("--input", type=Path, help="Input JSONL for create")
    version_parser.add_argument("--tag", help="Version tag (e.g., 1.0)")
    version_parser.add_argument("--compare", nargs=2, help="Two versions to diff")

    # --- sft ---
    sft_parser = subparsers.add_parser("sft", help="Generate SFT training dataset")
    sft_parser.add_argument("--version", required=True, help="Dataset version to use")
    sft_parser.add_argument("--output", type=Path, help="Output directory")
    sft_parser.add_argument("--balance", default="none",
                            choices=["none", "oversample_minority", "undersample_majority"])
    sft_parser.add_argument("--max-examples", type=int)

    # --- gpu-check ---
    subparsers.add_parser("gpu-check", help="Run GPU preflight diagnostics")

    # --- train ---
    train_parser = subparsers.add_parser("train", help="Launch a training run")
    train_parser.add_argument("--dataset-version", required=True, help="Dataset version")
    train_parser.add_argument("--sft-dir", type=Path, help="SFT dataset directory")
    train_parser.add_argument("--model", help="Model name override")
    train_parser.add_argument("--dry-run", action="store_true", help="Validate only")

    # --- evaluate ---
    eval_parser = subparsers.add_parser("evaluate", help="Evaluate a trained model")
    eval_parser.add_argument("--run-id", required=True, help="Training run ID")

    # --- registry ---
    reg_parser = subparsers.add_parser("registry", help="Manage model registry")
    reg_parser.add_argument("action", choices=["list", "promote", "deprecate", "info"])
    reg_parser.add_argument("--model-id", help="Model ID")
    reg_parser.add_argument("--run-id", help="Run ID for registration")

    # --- pipeline ---
    pipeline_parser = subparsers.add_parser("pipeline", help="Full pipeline (ingest→process→quality→version→sft)")
    pipeline_parser.add_argument("--source", required=True, help="Dataset source")
    pipeline_parser.add_argument("--input", type=Path, help="Input file/directory")
    pipeline_parser.add_argument("--limit", type=int, help="Max records")
    pipeline_parser.add_argument("--version-tag", default="1.0", help="Version tag")
    pipeline_parser.add_argument("--train", action="store_true", help="Also launch training")
    pipeline_parser.add_argument("--dry-run", action="store_true")

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    config = load_config(args.config)

    try:
        if args.command == "ingest":
            return cmd_ingest(args, config)
        elif args.command == "process":
            return cmd_process(args, config)
        elif args.command == "quality":
            return cmd_quality(args, config)
        elif args.command == "version":
            return cmd_version(args, config)
        elif args.command == "sft":
            return cmd_sft(args, config)
        elif args.command == "gpu-check":
            return cmd_gpu_check(args, config)
        elif args.command == "train":
            return cmd_train(args, config)
        elif args.command == "evaluate":
            return cmd_evaluate(args, config)
        elif args.command == "registry":
            return cmd_registry(args, config)
        elif args.command == "pipeline":
            return cmd_pipeline(args, config)
        else:
            parser.print_help()
            return 1
    except Exception as e:
        print(f"\n[ERROR] {e}", file=sys.stderr)
        return 1


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------

def cmd_ingest(args, config) -> int:
    """Ingest an external dataset."""
    from ..sources import (
        CICIDSSource, CTU13Source, UNSWNB15Source, EMBERSource,
        MITREAttackSource, CustomCSVSource,
    )

    source_map = {
        "cicids": lambda: CICIDSSource(version=args.version,
                                        cache_dir=config.resolve_path("datasets/external/cache/cicids")),
        "ctu13": lambda: CTU13Source(cache_dir=config.resolve_path("datasets/external/cache/ctu13")),
        "unsw_nb15": lambda: UNSWNB15Source(cache_dir=config.resolve_path("datasets/external/cache/unsw_nb15")),
        "ember": lambda: EMBERSource(cache_dir=config.resolve_path("datasets/external/cache/ember")),
        "mitre": lambda: MITREAttackSource(cache_dir=config.resolve_path("datasets/external/cache/mitre")),
        "custom": lambda: CustomCSVSource(cache_dir=config.resolve_path("datasets/external/cache/custom")),
    }

    if args.source not in source_map:
        print(f"Unknown source: {args.source}")
        return 1

    source = source_map[args.source]()
    input_path = args.input or source.cache_dir

    if not input_path.exists():
        print(f"Input path does not exist: {input_path}")
        print(f"Download dataset files to: {input_path}")
        return 1

    output = args.output or config.get_base_dir() / "raw"
    output.mkdir(parents=True, exist_ok=True)

    print(f"[INGEST] Source: {args.source}")
    print(f"[INGEST] Input: {input_path}")
    print(f"[INGEST] Output: {output}")

    count = 0
    output_file = output / f"{args.source}_raw.jsonl"
    with open(output_file, "w", encoding="utf-8") as f:
        for record in source.parse(input_path, limit=args.limit):
            f.write(json.dumps(record.to_dict(), ensure_ascii=False) + "\n")
            count += 1
            if count % 10000 == 0:
                print(f"  Ingested {count:,} records...")

    print(f"[INGEST] Complete: {count:,} records → {output_file}")
    return 0


def cmd_process(args, config) -> int:
    """Process raw records through the pipeline."""
    from ..processing.pipeline import build_pipeline
    from ..core.types import DatasetRecord

    input_path = Path(args.input)
    output_path = args.output or input_path.parent / "processed" / input_path.name

    print(f"[PROCESS] Input: {input_path}")
    print(f"[PROCESS] Output: {output_path}")

    # Load raw records
    records = []
    with open(input_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(DatasetRecord.from_dict(json.loads(line)))

    print(f"[PROCESS] Loaded {len(records):,} records")

    label_maps_dir = config.resolve_path(config.label_maps_dir)
    pipeline = build_pipeline(
        dedup_strategy=config.processing.dedup_strategy,
        validation_strict=config.processing.validation_strict,
        mitre_enabled=config.processing.mitre_mapping,
        label_maps_dir=label_maps_dir if label_maps_dir.exists() else None,
    )

    processed, report = pipeline.process_all(iter(records))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for record in processed:
            f.write(json.dumps(record.to_dict(), ensure_ascii=False) + "\n")

    print(f"[PROCESS] Complete: {report.output_records:,} records")
    print(f"  Rejected: {report.rejected:,}, Duplicates: {report.duplicates:,}")
    print(f"  Duration: {report.duration_seconds:.1f}s")
    print(f"  Class distribution: {report.class_distribution}")
    return 0


def cmd_quality(args, config) -> int:
    """Analyze dataset quality."""
    from ..core.types import DatasetRecord
    from ..quality.analyzer import DatasetQualityAnalyzer
    from ..quality.reporter import QualityReporter

    input_path = Path(args.input)
    records = []
    with open(input_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(DatasetRecord.from_dict(json.loads(line)))

    analyzer = DatasetQualityAnalyzer()
    report = analyzer.analyze(records, version=input_path.stem)

    reporter = QualityReporter()

    output_dir = args.output or config.get_reports_dir()
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.format in ("json", "both"):
        reporter.to_json(report, output_dir / "quality_report.json")
    if args.format in ("markdown", "both"):
        md = reporter.to_markdown(report, output_dir / "quality_report.md")
        print(md)

    print(f"\n[QUALITY] Score: {report.overall_quality_score:.2f}")
    return 0


def cmd_version(args, config) -> int:
    """Manage dataset versions."""
    from ..versioning.manager import VersionManager

    base_dir = config.get_base_dir()
    vm = VersionManager(base_dir)

    if args.action == "list":
        versions = vm.list_versions()
        if not versions:
            print("No versions found.")
        for v in versions:
            print(f"  v{v.version} | {v.record_count:,} records | "
                  f"quality={v.quality_score or 'N/A'} | {v.created_at}")

    elif args.action == "create":
        if not args.input or not args.tag:
            print("--input and --tag required for create")
            return 1
        from ..core.types import DatasetRecord
        records = []
        with open(args.input, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    records.append(DatasetRecord.from_dict(json.loads(line)))
        manifest = vm.create_version(args.tag, records)
        print(f"[VERSION] Created v{args.tag}: {manifest.record_count:,} records")

    elif args.action == "verify":
        if not args.tag:
            print("--tag required for verify")
            return 1
        results = vm.verify_integrity(args.tag)
        for fname, ok in results.items():
            status = "✓" if ok else "✗ CORRUPTED"
            print(f"  {fname}: {status}")

    elif args.action == "diff":
        if not args.compare or len(args.compare) != 2:
            print("--compare <v1> <v2> required for diff")
            return 1
        diff = vm.diff_versions(args.compare[0], args.compare[1])
        print(json.dumps(diff, indent=2))

    return 0


def cmd_sft(args, config) -> int:
    """Generate SFT training dataset."""
    from ..core.types import DatasetRecord
    from ..sft.generator import SFTGenerator
    from ..versioning.manager import VersionManager

    vm = VersionManager(config.get_base_dir())
    records, manifest = vm.load_version(args.version)

    output_dir = args.output or config.get_base_dir() / "sft" / f"v{args.version}"

    # Resolve protected test path for test firewall
    protected_test_path = None
    if config.sft.protected_test_path:
        protected_test_path = config.resolve_path(config.sft.protected_test_path)

    generator = SFTGenerator(
        train_ratio=config.sft.train_ratio,
        val_ratio=config.sft.val_ratio,
        test_ratio=config.sft.test_ratio,
        balance_strategy=args.balance,
        max_examples=args.max_examples or config.sft.max_examples,
        seed=config.sft.seed,
        protected_test_path=protected_test_path,
    )

    metadata = generator.generate(records, output_dir)

    print(f"[SFT] Generated dataset from v{args.version}")
    for split, info in metadata["splits"].items():
        print(f"  {split}: {info['converted']} examples → {info['file']}")

    return 0


def cmd_gpu_check(args, config) -> int:
    """Run GPU preflight diagnostics."""
    from ..training.gpu_check import run_gpu_check

    report = run_gpu_check()
    print("[GPU CHECK]")
    print(f"  CUDA available: {report.get('cuda_available', False)}")
    print(f"  Verdict: {report.get('verdict', 'UNKNOWN')}")

    for gpu in report.get("gpus", []):
        print(f"  GPU {gpu['index']}: {gpu['name']} ({gpu['vram_gb']} GB)")

    print("\n  VRAM Requirements:")
    for name, est in report.get("vram_estimates", {}).items():
        print(f"    {est['model']}: {est['min_vram_gb']}-{est['recommended_vram_gb']} GB "
              f"({est['method']})")

    return 0


def cmd_train(args, config) -> int:
    """Launch a training run."""
    from ..training.launcher import TrainingLauncher
    from ..training.run_manager import RunManager

    run_manager = RunManager(config.get_runs_dir())
    launcher = TrainingLauncher(run_manager)

    sft_dir = args.sft_dir or config.get_base_dir() / "sft" / f"v{args.dataset_version}"

    run_id = launcher.launch(
        dataset_version=args.dataset_version,
        sft_dir=Path(sft_dir),
        model_name=args.model,
        dry_run=args.dry_run,
    )

    print(f"\n[TRAIN] Run ID: {run_id}")
    return 0


def cmd_evaluate(args, config) -> int:
    """Evaluate a trained model."""
    from ..training.run_manager import RunManager

    run_manager = RunManager(config.get_runs_dir())
    run = run_manager.get_run(args.run_id)
    print(f"[EVAL] Run: {run.run_id}")
    print(f"  Status: {run.status.value}")
    print(f"  Model: {run.base_model}")
    print(f"  Metrics: {json.dumps(run.metrics, indent=2)}")
    return 0


def cmd_registry(args, config) -> int:
    """Manage model registry."""
    from ..registry.model_registry import ModelRegistry

    registry_path = config.resolve_path(config.output.registry_file)
    registry = ModelRegistry(registry_path)

    if args.action == "list":
        models = registry.list_models()
        if not models:
            print("No models registered.")
        for m in models:
            status = "★" if m.lifecycle.value == "promoted" else " "
            print(f"  [{status}] {m.model_id} | {m.base_model} | "
                  f"{m.lifecycle.value} | run={m.run_id}")

    elif args.action == "promote":
        if not args.model_id:
            print("--model-id required")
            return 1
        registry.promote(args.model_id)
        print(f"[REGISTRY] Promoted: {args.model_id}")

    elif args.action == "deprecate":
        if not args.model_id:
            print("--model-id required")
            return 1
        registry.deprecate(args.model_id)
        print(f"[REGISTRY] Deprecated: {args.model_id}")

    elif args.action == "info":
        if not args.model_id:
            print("--model-id required")
            return 1
        model = registry.get(args.model_id)
        if model:
            print(json.dumps(model.to_dict(), indent=2))
        else:
            print(f"Model not found: {args.model_id}")
            return 1

    return 0


def cmd_pipeline(args, config) -> int:
    """Run the full pipeline."""
    print("=" * 60)
    print("  AegisX Data Platform — Full Pipeline")
    print("=" * 60)

    # Step 1: Ingest
    print("\n[1/5] INGEST")
    ingest_args = argparse.Namespace(
        source=args.source,
        input=args.input,
        output=config.get_base_dir() / "raw",
        limit=args.limit,
        version="2017",
    )
    result = cmd_ingest(ingest_args, config)
    if result != 0:
        return result

    # Step 2: Process
    print("\n[2/5] PROCESS")
    raw_file = config.get_base_dir() / "raw" / f"{args.source}_raw.jsonl"
    processed_file = config.get_base_dir() / "processed" / f"{args.source}_processed.jsonl"
    process_args = argparse.Namespace(
        input=raw_file,
        output=processed_file,
    )
    result = cmd_process(process_args, config)
    if result != 0:
        return result

    # Step 3: Quality
    print("\n[3/5] QUALITY ANALYSIS")
    quality_args = argparse.Namespace(
        input=processed_file,
        output=config.get_reports_dir(),
        format="both",
    )
    cmd_quality(quality_args, config)

    # Step 4: Version
    print(f"\n[4/5] VERSION (v{args.version_tag})")
    version_args = argparse.Namespace(
        action="create",
        input=processed_file,
        tag=args.version_tag,
        compare=None,
    )
    cmd_version(version_args, config)

    # Step 5: SFT
    print("\n[5/5] SFT GENERATION")
    sft_args = argparse.Namespace(
        version=args.version_tag,
        output=config.get_base_dir() / "sft" / f"v{args.version_tag}",
        balance="oversample_minority",
        max_examples=None,
    )
    cmd_sft(sft_args, config)

    # Optional training
    if getattr(args, "train", False):
        print("\n[BONUS] TRAINING")
        train_args = argparse.Namespace(
            dataset_version=args.version_tag,
            sft_dir=config.get_base_dir() / "sft" / f"v{args.version_tag}",
            model=None,
            dry_run=getattr(args, "dry_run", True),
        )
        cmd_train(train_args, config)

    print("\n" + "=" * 60)
    print("  Pipeline Complete!")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
