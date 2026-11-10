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
