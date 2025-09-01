# Sec Lab Playbook

Un dépôt "clean" orienté sécu (YARA/IoC/artefacts) – **sans aucune automatisation**.  
Le but: héberger des artefacts R&D sécu.

## Dossiers
```
sec-lab-repo/
├── README.md
├── LICENSE
├── SECURITY.md
├── .gitignore
├── pyproject.toml
├── pre-commit-config.yaml
├── detect-secrets.baseline
├── tools/
│   └── ioc_maker.py  
├── rules/
│   └── yara/
│       └── README.md
├── artifacts/
│   ├── .gitkeep
│   └── README.md
└── scripts/
    └── lint.sh
```
