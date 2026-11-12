from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import platform
from shutil import copyfile
from tempfile import TemporaryDirectory
from time import perf_counter_ns

import numpy as np
import onnx
import onnxruntime as ort
from onnxruntime.quantization import QuantType, quantize_dynamic
from onnxruntime.quantization.shape_inference import quant_pre_process
import torch

from .codebert_data import Case, DatasetError, read_split, write_json
from .codebert_eval_data import load_candidates
from .codebert_evaluate import Evaluation, Scores, classification, frozen_policy, load_classifier, load_training
from .codebert_input import MAX_TOKENS, sha256_file, token_ids
from .codebert_onnx import INPUT_NAMES, OUTPUT_NAME, THREADS, infer_logits, make_feed, open_session, review_probability, runtime_tokenizer
from .review_priority import RankingPolicy

WARMUPS = 12
REPEATS = 7


class Classifier(torch.nn.Module):
    def __init__(self, model: torch.nn.Module):
        super().__init__()
        self.model = model

    def forward(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        return self.model(input_ids=input_ids, attention_mask=attention_mask).logits


@dataclass(frozen=True, slots=True)
class Feed:
    case: Case
    inputs: dict[str, np.ndarray]


def _input_cases(cases: list[Case], hf_tokenizer, tokenizer) -> tuple[list[Feed], dict[str, str]]:
    feeds, statuses = [], {}
    for case in cases:
        statuses[case.case_id] = case.status
        if case.status != "eligible":
            continue
        feed = make_feed(tokenizer, case.command)
        ids = token_ids(hf_tokenizer, case.command)
        if feed is None:
            if ids is not None:
                raise DatasetError("tokenizers disagree on token limit")
            statuses[case.case_id] = "too_long"
            continue
        if feed["input_ids"].tolist() != [ids]:
            raise DatasetError("export tokenizer differs from training")
        statuses[case.case_id] = "ok"
        feeds.append(Feed(case, feed))
    if {feed.case.label for feed in feeds if feed.case.label != "unknown"} != {"benign", "review"}:
        raise DatasetError("export comparison requires both known classes within the token limit")
    return feeds, statuses


def _export(model: Classifier, inputs: dict[str, np.ndarray], out: Path) -> tuple[Path, Path, int]:
    fp32, int8 = out / "codebert-fp32.onnx", out / "codebert-int8.onnx"
    with TemporaryDirectory(dir=out) as temp:
        raw = Path(temp) / "export.onnx"
        with torch.inference_mode():
            torch.onnx.export(
                model, tuple(torch.from_numpy(inputs[name]) for name in INPUT_NAMES), str(raw),
                input_names=list(INPUT_NAMES), output_names=[OUTPUT_NAME],
                dynamic_axes={name: {1: "sequence"} for name in INPUT_NAMES},
                opset_version=17, dynamo=False, external_data=False,
            )
        quant_pre_process(raw, fp32, skip_optimization=True, skip_symbolic_shape=True)
    quantize_dynamic(fp32, int8, op_types_to_quantize=["MatMul", "Gather"], per_channel=True,
                     weight_type=QuantType.QInt8)
    graph = onnx.load(int8, load_external_data=False)
    return fp32, int8, sum(node.op_type == "MatMulInteger" for node in graph.graph.node)


def _percentiles(samples: list[int]) -> dict[str, float]:
    return {"p50_ms": float(np.percentile(samples, 50) / 1e6),
            "p95_ms": float(np.percentile(samples, 95) / 1e6)}


def _measure(graph: Path, feeds: list[Feed], tokenizer) -> tuple[dict[str, np.ndarray], dict]:
    runtime = open_session(graph)
    for index in range(WARMUPS):
        infer_logits(runtime, feeds[index % len(feeds)].inputs)
    logits = {feed.case.case_id: infer_logits(runtime, feed.inputs) for feed in feeds}
    inference_ns, total_ns = [], []
    for _ in range(REPEATS):
        for feed in feeds:
            start = perf_counter_ns()
            infer_logits(runtime, feed.inputs)
            inference_ns.append(perf_counter_ns() - start)
            start = perf_counter_ns()
            inputs = make_feed(tokenizer, feed.case.command)
            if inputs is None:
                raise DatasetError("inconsistent tokenizer output")
            infer_logits(runtime, inputs)
            total_ns.append(perf_counter_ns() - start)
    return logits, {"bytes": graph.stat().st_size, "sha256": sha256_file(graph),
                    "inference": _percentiles(inference_ns), "with_tokenizer": _percentiles(total_ns)}


def run(args: argparse.Namespace) -> None:
    cases, fixture = read_split(args.test, "test")
    training = load_training(args.model)
    policy_doc = frozen_policy(args.policy, args.model, args.test)
    policy = RankingPolicy.model_validate(policy_doc["policies"]["codebert"])
    test_hash, candidates_hash = sha256_file(args.test), sha256_file(args.candidates)
    evaluation = json.loads(args.evaluation.read_text(encoding="utf-8"))
    if (training["fixture"] != fixture or policy_doc["fixture"] != fixture or evaluation["fixture"] != fixture
            or evaluation["test_sha256"] != test_hash or evaluation["candidates_sha256"] != candidates_hash
            or evaluation["policy_sha256"] != sha256_file(args.policy)):
        raise DatasetError("independent evaluation and export inputs differ")
    eval_set = Evaluation(cases, load_candidates(args.candidates, args.test, cases))
    torch.set_num_threads(THREADS)
    hf_tokenizer, model = load_classifier(args.model)
    tokenizer = runtime_tokenizer(args.model / "tokenizer.json")
    feeds, statuses = _input_cases(cases, hf_tokenizer, tokenizer)
    classifier = Classifier(model).eval()
    args.out.mkdir(parents=True, exist_ok=False)
    fp32, int8, integer_ops = _export(classifier, feeds[0].inputs, args.out)
    fp_logits, fp_report = _measure(fp32, feeds, tokenizer)
    int_logits, int_report = _measure(int8, feeds, tokenizer)
    max_error = 0.0
    with torch.inference_mode():
        for feed in feeds:
            reference = classifier(*(torch.from_numpy(feed.inputs[name]) for name in INPUT_NAMES)).numpy()
            actual = fp_logits[feed.case.case_id]
            np.testing.assert_allclose(actual, reference, atol=1e-4, rtol=1e-4)
            max_error = max(max_error, float(np.max(np.abs(actual - reference))))
    for logits, report in ((fp_logits, fp_report), (int_logits, int_report)):
        scores = Scores({key: review_probability(values) for key, values in logits.items()}, statuses)
        report["top10"] = eval_set.ranked(scores, policy)
        report["classification"] = classification(cases, scores, policy.threshold)
    fp_hits, int_hits = (set(report["top10"]["investigations"]) for report in (fp_report, int_report))
    new_misses = sorted(set(int_report["classification"]["missed"]) - set(fp_report["classification"]["missed"]))
    expected_top = evaluation["arms"]["codebert"]
    fp_pass = (
        fp_report["top10"]["protected_order"] == expected_top["protected_order"]
        and fp_hits == set(expected_top["investigations"])
        and fp_report["classification"]["missed"] == expected_top["classification"]["missed"]
        and fp_report["classification"]["false_positives"] == expected_top["classification"]["false_positives"]
    )
    int_pass = (fp_pass and integer_ops > 0 and int_report["bytes"] < fp_report["bytes"]
                and not new_misses and len(int_hits) >= len(fp_hits)
                and int_report["top10"]["protected_order"] == fp_report["top10"]["protected_order"])
    selected = int8 if int_pass else fp32 if fp_pass else None
    write_json(args.out / "quantization.json", {
        "fixture": fixture, "test_sha256": test_hash, "policy_sha256": sha256_file(args.policy),
        "evaluation_sha256": sha256_file(args.evaluation), "platform": platform.platform(),
        "runtime_version": ort.__version__, "threads": THREADS, "batch_size": 1,
        "warmups": WARMUPS, "repeats_per_case": REPEATS, "fp32_max_abs_logit_error": max_error,
        "fp32": fp_report, "int8": int_report, "int8_integer_matmuls": integer_ops,
        "int8_new_misses": new_misses, "int8_top10_gains": sorted(int_hits - fp_hits),
        "int8_top10_losses": sorted(fp_hits - int_hits), "int8_pass": int_pass, "fp32_pass": fp_pass,
        "selected": selected.name if selected else None,
        "promotion_eligible": not fixture and bool(selected) and evaluation["promotion_eligible"],
    })
    if selected is not None:
        copyfile(args.model / "tokenizer.json", args.out / "tokenizer.json")
        write_json(args.out / "policy.json", policy.model_dump())
        write_json(args.out / "manifest.json", {
            "schema": 1, "fixture": fixture, "graph": selected.name, "max_tokens": MAX_TOKENS,
            "labels": ["benign", "review"], "files": {name: sha256_file(args.out / name)
                                                     for name in (selected.name, "tokenizer.json", "policy.json")},
        })


def main() -> None:
    parser = argparse.ArgumentParser()
    for name in ("model", "test", "candidates", "policy", "evaluation", "out"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    run(parser.parse_args())


if __name__ == "__main__":
    main()
