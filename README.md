# PaaS-Managed-Services-Permissions-Control-Plane
PaaS & Managed Services Permissions Control Plane
AWS Security Scripts
A practical, auditable framework to manage AWS managed service permissions using a strict scan → plan → remediate execution model.
This repository treats PaaS & Managed Services Permissions as a Control Plane, producing:
Versioned outputs
Deterministic plans
Guarded remediations
It is designed for real-world managed service governance, not academic checks.

## Antes de tudo: clone (ou atualize) a série no AWS CloudShell

O AWS CloudShell é um terminal no navegador que já vem autenticado, com a AWS CLI e o Git instalados. É o jeito mais rápido de testar a série inteira.

**Clone (ou atualize) os módulos da série no `$HOME`**

```bash
cd ~
for repo in $(gh repo list wagnermazevedo -L 100 --json name -q '.[].name' | grep -E '^AWS-.*Control-Plane'); do
    if [ -d "$repo/.git" ]; then
        git -C "$repo" pull --ff-only          # já clonado: só atualiza
    else
        gh repo clone "wagnermazevedo/$repo"   # primeira vez: clona
    fi
done
```

O mesmo comando serve para a primeira vez e para atualizar depois. O `--ff-only` nunca mistura mudanças: se você alterou algum arquivo localmente, o Git avisa e não mexe naquele repositório.

(Se a GitHub CLI não estiver autenticada, rode `gh auth login` antes. Ou clone só o módulo que quiser com `git clone`.)

## Before anything: clone (or update) the series in AWS CloudShell

AWS CloudShell is a browser-based terminal that comes already authenticated, with the AWS CLI and Git installed. It is the fastest way to try the whole series.

**Clone (or update) the series modules in `$HOME`**

```bash
cd ~
for repo in $(gh repo list wagnermazevedo -L 100 --json name -q '.[].name' | grep -E '^AWS-.*Control-Plane'); do
    if [ -d "$repo/.git" ]; then
        git -C "$repo" pull --ff-only          # already cloned: just update
    else
        gh repo clone "wagnermazevedo/$repo"   # first time: clone
    fi
done
```

The same command works the first time and for later updates. `--ff-only` never mixes changes: if you changed a file locally, Git warns you and leaves that repository alone.

(If the GitHub CLI is not authenticated, run `gh auth login` first. Or clone only the module you want with `git clone`.)

---

🎯 What This Project Covers
Day-to-day managed service permission security operations, including:

AWS Service Control Policies (SCPs)
IAM Permission Boundaries
Cross-account role permissions
Managed policy attachment
Service control policies
Resource-based policies
Identity and Access Management for managed services
CloudFormation stack policies
Lambda function permissions
S3 bucket policies
RDS access controls
EC2 instance profile permissions
API Gateway resource policies
EKS cluster access controls
DynamoDB table permissions
SQS queue policies
SNS topic permissions
KMS key policies
CloudTrail trail configurations
⚠️ Important note
Effective permissions in AWS managed services depend on SCPs, permission boundaries, conditions, session policies, and resource policies.
This framework uses strong indicators + policy simulation to provide an operationally accurate posture.

🧱 Repository Structure
AWS-Security-Scripts-PaaS-Permissions-Control-Plane/
├─ 00_managed_service_scan.py
├─ 01_managed_service_plan.py

├─ 02_managed_service_remediate.py
├─ lab_insecure_managed_services.py
├─ requirements.txt
├─ README.md
├─ MANUAL.md
├─ lib/
│   ├─ aws.py
│   ├─ cli.py
│   ├─ managed_services.py
│   ├─ io.py
│   └─ policy_eval.py
└─ outputs/
└─ .gitkeep

🔧 Prerequisites
Python 3.9+
AWS credentials configured (CLI / profiles)
Recommended IAM Permissions
Scan: organizations:List*, iam:List*, sts:GetCallerIdentity, s3:List*, dynamodb:List*
Remediation: organizations:PutPolicy, iam:PutUserPermissionsBoundary, iam:AttachUserPolicy
📦 Install

Copy
bash
pip install -r requirements.txt
export PYTHONPATH=$(pwd)
🔁 Execution Contract
1️⃣ Scan
Collects managed service inventory and produces findings.


Copy
bash
python 00_managed_service_scan.py \
  --profile default \
  --region us-east-1 \
  --include-scps \
  --include-permission-boundaries \
  --out outputs
Output:


Copy
outputs/managed_service_scan_<timestamp>.json
2️⃣ Plan
Transforms findings into proposed actions.


Copy
bash
python 01_managed_service_plan.py \
  --scan-file outputs/managed_service_scan_<timestamp>.json \
  --out outputs
Output:


Copy
outputs/managed_service_plan_<timestamp>.json
3️⃣ Remediate
Applies safe actions only, with guardrails.


Copy
bash
# Dry-Run (no changes applied)
python 02_managed_service_remediate.py \
  --plan-file outputs/managed_service_plan_<timestamp>.json \
  --dry-run \
  --out outputs

# Apply safe actions
python 02_managed_service_remediate.py \
  --plan-file outputs/managed_service_plan_<timestamp>.json \
  --out outputs
🔐 Optional controls
Enable SCP enforcement → --enable-scp-enforcement
Apply permission boundaries → --apply-boundaries
Update managed policies → --update-managed-policies
🧪 Lab Mode (Validation Only)
Creates intentionally insecure managed service configurations to validate detections.


Copy
bash
python lab_insecure_managed_services.py \
  --profile default \
  --create-permissive-scp \
  --create-unbound-user \
  --out outputs
⚠️ LAB ONLY
Always delete created resources after testing.

🛡️ Safety Guarantees
Dry-run supported
Max actions per run capped
No destructive remediations by default
High-impact changes require explicit opt-in
📋 Example Output Format

Copy
json
{
  "timestamp": "2023-12-01T10:30:00Z",
  "findings": [
    {
      "type": "scp_overly_permissive",
      "resource_id": "root-account",
      "severity": "CRITICAL",
      "description": "SCP allows excessive permissions for root account"
    }
  ],
  "total_findings": 1
}
🚀 Quick Start Guide

Copy
bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Scan your managed services
python 00_managed_service_scan.py --profile default --out outputs

# 3. Plan remediations
python 01_managed_service_plan.py --scan-file outputs/managed_service_scan_*.json --out outputs

# 4. Test with dry-run
python 02_managed_service_remediate.py --plan-file outputs/managed_service_plan_*.json --dry-run --out outputs

# 5. Apply safe remediations
python 02_managed_service_remediate.py --plan-file outputs/managed_service_plan_*.json --out outputs
📚 Related Resources
AWS Well-Architected Framework - Security Pillar
AWS Organizations Best Practices
IAM Permission Boundaries Documentation
Service Control Policies Reference
🤝 Contributing
Fork the repository
Create your feature branch (git checkout -b feature/AmazingFeature)
Commit your changes (git commit -m 'Add some AmazingFeature')
Push to the branch (git push origin feature/AmazingFeature)
Open a Pull Request
📄 License
MIT License - see LICENSE file for details


