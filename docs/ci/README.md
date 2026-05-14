# CI templates

GitHub Actions workflow lives here as a template because the OAuth
credential currently used for automated commits lacks the `workflow`
scope. To activate Actions:

```bash
mkdir -p .github/workflows
cp docs/ci/github-actions.yml.template .github/workflows/ci.yml
git add .github/workflows/ci.yml
git commit -m "ci: enable GitHub Actions"
git push  # requires a credential with the `workflow` scope
```

The template is functional as-is; only the path is non-standard.
