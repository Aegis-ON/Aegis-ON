# Experimental command-model refinement

This is a reproducibility experiment with synthetic strings, not a production attack classifier or PII detection. Never execute the example commands. Positive means a fictional review policy flags a security-relevant change; it does not establish intent or success. Some download/script labels depend on hypothetical authorization absent from the command, so outputs cannot establish that authorization. Unknown cases are unscored. All examples are project-authored synthetic text, no real logs or secrets; external datasets were not used. The project has not stated a standalone data license, so no additional external license is asserted.

## Preregistered plan

- Development file `evaluation/command_refine_dev_v1.json` SHA-256 `1b9e9c7e1899227d97a403d952a6717150884391943d8caa24482bb2251bb97a`: train 40 cases / 10 manual groups, validation 16 / 4 groups; each is balanced by label. Test file `evaluation/command_refine_test_v1.json` SHA-256 `822c1c0b963c80536fc196bf8a59e66fb161a78763aa62c0c6946cb60debcacf`: 24 labeled cases / 6 manual groups plus 3 unknown. Each group contains two similar variants per class; they are not independent samples.
- Prior model SHA-256 `c33ad158789d3b57d60947ac89346ade3eec16c0045b381356fed423c025bf28`, loaded locally after six-file manifest verification. Fine-tune a separate copy, seed 101, CPU, AdamW 3e-5, batch 4, 8 epochs; select by lowest validation loss. Max 128 tokens, no truncation; oversized inputs rejected. Do not use PR7 or test data for training or checkpoint selection.
- Keep original threshold 0.5 for both models, no post-test threshold or rule adjustment. Before test inference, commit the selected model hash, test hash, threshold and evaluation method. Binary alert indicators only, no inferred ATT&CK classifier. Compare identical eligible cases; unknown and failed inputs excluded with reasons, report common support, confusion matrices, precision/recall/F1, false alert rate and group-specific counts.
- Normalized exact duplicate check across development, test, prior v2, PR4 and PR7 yielded zero. Groups are manually disjoint across new splits. Exact comparison and hand-assigned groups cannot establish semantic independence. The new train uses some tool/action families seen in old development or evaluation (e.g. PowerShell, scheduled tasks and registry); the old v2/PR4/PR7 test material is no longer independent after refinement. Avoid using PR7 data in training or validation; PR7 results are reference only. Existing previous-model pretraining is unchanged and unknown training-corpus overlap cannot be excluded.
- Development and test were authored by a reviewer who had read prior project data; this is not blind third-party evaluation. Data are small, artificially balanced, and weakly labeled fictional triage policies; two variants in a group may share superficial cues. Results cannot be generalized to production or used to claim actual attacks.

## Commands

Install `requirements.txt` and `requirements-attack.txt`; use the independently protected original model and its original manifest. Outputs must be a new directory outside Git; the trainer refuses to overwrite an existing output directory.

```bash
PYTHONPATH=src python -m aegis_on.command_refine --development evaluation/command_refine_dev_v1.json --original-dir /path/original/model --original-manifest /path/original/metadata.json --output /path/new/model
```

## Actual run and selected model

On macOS arm64, Python 3.12.2, PyTorch 2.7.0 and Transformers 4.41.2, the original model was loaded through the product loader and separately fine-tuned. The minimum validation loss was at epoch 8 (0.6170874). No final-test examples were used to train or choose the checkpoint, and 0.5 was not tuned. The selected weights SHA-256 is `bff7da13980f8c939c63d102c33a7143e90e3113182b9ebdc9116889255d0432`. The accompanying manifest records hashes of all six artifacts and local environment. Saved files were reloaded with the actual product loader and passed its real-model test. The original model was not modified. The evaluator and selected model/test hashes were frozen in commit `9fee9dad4d351b0bb7b2723b6445d03d67658539` before final test inference.

The local ZIP backup SHA-256 is `b5808996909ee9ac422e92f4432a7387b989f8bfa154e2a6d12ccae22d6e05fe`. Its upload to an owner-only private Drive folder was observed; the Drive copy has not been independently downloaded or hash-checked. Compare independently trusted hashes after copying; a manifest next to mutable model files is not a signature. The original Drive ZIP round-trip has not been verified either. The prior model itself originates from BERT-Tiny revision `30b0a37ccaaa32f332884b96992754e246e48c5f`, fine-tuned previously on synthetic data; the refined model starts from that checkpoint, not a freshly trained model.

To repeat the frozen comparison using the separately retained models:

```bash
PYTHONPATH=src python -m aegis_on.command_refine_evaluate \
  --test evaluation/command_refine_test_v1.json \
  --protocol evaluation/command_refine_protocol_v1.json \
  --original-dir /path/original/model --original-manifest /path/original/metadata.json \
  --refined-dir /path/new/model --refined-manifest /path/new/model/manifest.json \
  --output /tmp/refinement-new-report.json
```

## Final synthetic test

Two local runs produced byte-identical reports, SHA-256 `7e57fbabfb5fdc00c8ada626054127831c9ab9ee12bf0b10c5a6702cfe751b57`. The 27-case file has 24 labeled cases across six manually grouped families, plus three unknown cases excluded before inference. Both models successfully scored all 24 labeled commands. The same 24 events were used by each method. Baseline uses the existing rules and keyword adapter with the first command token as a synthetic process and an empty parent. Model inputs are command strings only. Case/group details are in [the report](../evaluation/command_refine_report_v1.json).

| Method | TP | FP | TN | FN | Precision | Recall | F1 | Negative false-alert rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rules + keyword | 7 | 4 | 8 | 5 | 0.636 | 0.583 | 0.609 | 4/12 (0.333) |
| Original BERT | 12 | 12 | 0 | 0 | 0.500 | 1.000 | 0.667 | 12/12 (1.000) |
| Refined BERT | 7 | 2 | 10 | 5 | 0.778 | 0.583 | 0.667 | 2/12 (0.167) |

The refined model reduced this dataset's negative alerts by ten but missed five positives instead of zero. It missed both proxy-setting examples, both event-tracing examples and one remote PowerShell configuration example. Its two FPs are one BitLocker inventory and one proxy inventory example. Baseline missed both proxy-setting examples, both Wi-Fi profile export examples and one tracing example. The original flagged every scored command. Equal F1 does not mean equivalent behavior: the false-alarm/miss trade-off changes. Do not enable this model by default or claim an operational improvement without real-world evidence.

Each of the six families has two negative and two positive related variants. On the refined model: binary-proxy TP2/FP0/TN2/FN0; bitlocker-config 2/1/1/0; event-tracing 0/0/2/2; proxy-configuration 0/1/1/2; remote-powershell 1/0/2/1; wifi-profile 2/0/2/0. These groups are hand-assigned, not six statistically independent samples. The two T1218.007 annotations are two variations from one binary-proxy group; all three methods flagged 2/2 for review for any reason. The binary models do not predict ATT&CK technique IDs. Source: https://attack.mitre.org/techniques/T1218/007/

The weak labels, tool reuse across earlier datasets, small grouped variants, and missing context sharply limit inference. An approved download can look like an unapproved one in a command string; an unspecified script's true content is unknowable. Three unknown examples do not validate model abstention. The original PR7 evaluation was examined earlier and is reference-only; old PR4/v2 evaluation families overlap some new training families and are not independent post-refinement. No performance should be generalized to a real population or attributed to a proven causal training bias. Production work requires a separately sourced, consented, independently annotated, privacy-reviewed dataset with truly held-out source/template families and explicit analyst cost for false negatives.

## Verification

Mac full regression: 159 tests, 156 passed, three opt-in real-model tests skipped; separately the actual refined attack model integration test passed. In-process authenticated JSON and synthetic Sysmon requests with the refined model also passed, including event ID links, missing command and regex IP masking. The existing model integrates optionally into the same JSON/Sysmon pipeline, but these numbers do not represent browser, Windows Sysmon, production deployment, or a new real PII ONNX test. The last relevant GitHub-hosted PII job failed before execution due to billing/spending limits; local tests are not GitHub CI. The model is not committed to Git. No sharing settings, GitHub billing, protections or automatic merge were changed.
