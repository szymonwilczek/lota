---
name: Bug
about: Defect in LOTA behavior - agent, verifier, attest-CA, BPF LSM, SDK, or tooling
title: ''
labels: bug
---

<!--
Non-security defects only.
Suspected vulnerability in the attestation chain, TPM enrollment, verifier policy,
BPF LSM, release integrity, or SDK token validation goes through
PRIVATE SECURITY REPORTING, NEVER HERE.
-->

## Description

What breaks, stated plainly.

## Reproduction

Exact steps. The commands, config, and inputs that trigger it.

## Expected vs actual

What should happen, and what happens instead. Quote errors verbatim.

## Environment

- Version / commit:
- Component (agent / verifier / attest-CA / SDK / fleet CLI / something else):
- Kernel and distro:
- TPM (hardware / swtpm / vTPM), firmware (UEFI+SB / BIOS legacy):

## Logs

Relevant journal or verifier output, trimmed to the failure. Redact secrets.
