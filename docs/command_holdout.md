# Command BERT synthetic holdout protocol

This is a manually authored, synthetic command-triage experiment, not an operational test or proof of an attack. The 40 cases cover 32 manually assigned groups: 12 positive, 14 negative, 14 unknown. Positive means the stated fictional scenario warrants analyst review; negative means that scenario is authorized, not that the command is inherently safe. Some labels depend on information unavailable to the classifier. Eight unknown commands are ambiguous and six additional cases test missing/null/empty/too-long inputs. No commands or addresses are executed. Linux examples probe out-of-scope generalization, not Windows performance.

## Preregistered before model inference

- Dataset SHA-256: `569cb879e46a049ad8fe25f2728aab06342a82aca01c4d71b48fca3b631a162b`. The CLI refuses changes to the file. Dataset, labels, group assignments and this protocol are fixed before inspecting predictions.
- Fine-tuned model weights SHA-256: `c33ad158789d3b57d60947ac89346ade3eec16c0045b381356fed423c025bf28`; use the separately trusted original metadata manifest to verify all six artifacts. The Drive upload was confirmed, but its downloaded copy was not verified when this protocol was written. The Colab-exported original is available locally. No training, thresholds or rules are changed for the holdout.
- Product binary classifier uses the existing uncalibrated 0.5 threshold. The label is decided before its score is rounded to six decimals, so a reported score of 0.5 can belong to either label. No ATT&CK labels are predicted by the model.
- Unit: a case's command string. Baseline runs existing `RuleDetector` and `SemanticRiskAdapter` using the command's first token as synthetic process and an empty parent, as in the previous experiment; the BERT model sees only the command. Comparison is of these implementations with limited context, not matched real process telemetry.
- Headline scores compare the same cases: known positive or negative labels with usable input and successful model output. Unknown truth, missing/invalid input, model length rejection and inference errors are excluded and counted separately. Baseline is also scored on all eligible labeled inputs. Status mismatches for six boundary cases are explicitly reported. An error is not a negative prediction. Undefined precision, recall or F1 is null with its reason.
- A technique annotation denotes a plausible fictional behavior, not successful execution or malicious intent. For annotated positives only, report the fraction flagged for review by the baseline and by the binary model. This is not technique classification or technique-specific precision; one case may have multiple candidates.
- Recall and precision are synthetic and intentionally prevalence-biased; the 32 hand-assigned groups are not guaranteed independent. The same command families appear in prior project data and may occur in pretraining. This is a project-held-out supplement, not an independent production benchmark.

## Existing data comparison

Run `PYTHONPATH=src python -m aegis_on.command_overlap`. It compares all text against `command_synthetic_v2.json` (all four splits) and `synthetic_v1.json` (all splits), after case/whitespace normalization, path/URL/numeric template replacement and executable-name comparison. Before inference: 35 nonblank strings within the character limit inspected; zero exact duplicates, four template similarity candidates at 0.70 or above, 12 shared executable names. Candidates include dissimilar tools being grouped by coarse path replacement; examine case IDs and source code manually. The output excludes missing/empty/null and oversized strings. These heuristics cannot prove semantic disjointness, discover all variant templates, or establish source independence. For example, approved PowerShell script execution shares an interpreter family with older examples, and normal downloads share the curl family. No claim of zero semantic overlap is made.

## Run

Install `requirements.txt` and `requirements-attack.txt`. Extract the privately stored original outside Git. Independently compare the archive and manifest hashes against trusted originals, then:

```bash
export AEGIS_ATTACK_MODEL_DIR=/path/to/unpacked/model
export AEGIS_ATTACK_MODEL_MANIFEST=/path/to/unpacked/metadata.json
PYTHONPATH=src python -m aegis_on.command_holdout --dataset evaluation/command_holdout_v1.json --output /tmp/command-holdout-report.json
PYTHONPATH=src python -m aegis_on.command_overlap
PYTHONPATH=src python -m unittest discover -s tests -v
```

The model is separate from PII NER; local inference sends no commands to an external API. Do not feed real logs to this synthetic evaluator. A metadata file stored beside the model can itself be modified; separately protect the expected hashes. Seeded re-training does not guarantee identical weights. The base BERT-Tiny model card states Apache-2.0; base corpus permissions and model distribution rights are separate questions. New cases are project-authored and contain no real secrets, but their labels require human review and have not been validated against actual incidents.

## Frozen experiment: observed result

The protocol/data/evaluator were committed at `df098b3593f6130d5fb519895a16a53869c4ee1d` **before** actual model evaluation. macOS arm64, Python 3.12.2, PyTorch 2.7.0 and Transformers 4.41.2 loaded the original Colab-exported model using its six-file manifest. Two runs produced identical report SHA-256 `274891a7b0aa6206e1e3134caf163414b57ffe265c438f1ac0edeb3f6a2ce80d`. The Drive ZIP was not downloaded and hash-checked; the model came from the original Colab export, not a verified Drive round trip. The stored [report](../evaluation/command_holdout_report_v1.json) contains only synthetic case IDs, groups and predictions, not real logs.

26 labeled cases from 21 manually assigned groups were scored in common (12 positive, 14 negative). The rest: 8 unknown truth, 3 missing or blank, 1 invalid type and 2 length limits. All six boundary input statuses matched expectations. The comparison concerns the product's unmodified existing baseline and the actual model, not a combined prediction. The overall eligible baseline happens to have the same 26 cases as the common set.

Boundary statuses are checked by direct `AttackModel.predict` calls; a missing key is passed as the empty string. This does not test JSON/Sysmon HTTP validation, which can reject or normalize input differently. The eight valid unknown cases have their input status recorded, but this report intentionally does not retain their model labels or scores; it cannot measure abstention or ambiguity handling.

| Method | TP | FP | TN | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Existing rules and keyword baseline | 2 | 4 | 10 | 10 | 0.333 | 0.167 | 0.222 |
| Original actual BERT model | 12 | 13 | 1 | 0 | 0.480 | 1.000 | 0.649 |

The model flagged 25/26 inputs and 13/14 synthetic negative cases. The review-candidate labels depend on hypothetical context unavailable to either input. This very high false-positive count makes the model unsuitable to present as an independently validated operational detector. As context only, flagging every one of these 26 cases would yield F1 0.632; neither that reference nor the model score represents real deployment performance. Baseline FPs: `holdout-003`, `holdout-005`, `holdout-039`, `holdout-040`. Baseline FNs: `holdout-013`, `014`, `016`, and `018`–`024`. Model FPs: `001`–`006`, `008`–`012`, `039`, `040`; no labeled FNs. Full IDs and numeric scores are in the report. No rules, model weights or threshold were tuned after seeing these results.

| Annotated candidate | Cases | Baseline flagged for any reason | Binary model flagged |
| --- | ---: | ---: | ---: |
| T1685.005 (clear Windows event logs) | 1 | 0/1 | 1/1 |
| T1685.001 (modify Windows event logging) | 1 | 0/1 | 1/1 |
| T1218.005 (mshta proxy execution) | 1 | 1/1 | 1/1 |

Each candidate has only one example. These are binary review flags, not ATT&CK identification; in particular the baseline may flag another feature, such as a URL. The source mapping is MITRE ATT&CK's current technique descriptions, which do not prove attack intent in these hypothetical cases.

Full macOS suite: 153 tests run, 150 passed and three opt-in real-model tests skipped. The actual attack model integration test was run separately and passed. The prior PII ONNX Colab test is documented in the merged PR; it was not rerun here. Real Windows Sysmon, browser flow, production infrastructure and GitHub-hosted Actions are unverified. The existing PII workflow last failed before starting because GitHub reported payment or spending limits.
