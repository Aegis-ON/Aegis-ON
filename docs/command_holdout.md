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
