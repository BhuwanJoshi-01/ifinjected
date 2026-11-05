# Publishing (maintainers)

## One-time setup

1. **PyPI trusted publisher.** Log in at <https://pypi.org>, open *Your projects → Publishing*, and add a *pending
   publisher* for project `ifinjected`: owner `BhuwanJoshi-01`, repository `ifinjected`, workflow
   `release.yml`, environment `pypi`. The first release then creates the project; no API token is ever stored.
2. **GitHub environment.** In the repository settings create an environment named `pypi`. Restricting it to
   protected tags or requiring a reviewer is a good extra safeguard.

## A release

1. Make sure `main` is green, and update `CHANGELOG.md`: move the *Unreleased* entries under a new
   `## X.Y.Z (YYYY-MM-DD)` heading.
2. Set the version and merge it through a pull request:

   ```bash
   uv version X.Y.Z          # updates pyproject.toml and uv.lock
   ```

3. Tag and create the release from `main` (the release is yours; the workflow only builds and uploads):

   ```bash
   git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z
   awk -v v=X.Y.Z '$0 ~ "^## "v" " {p=1; next} /^## / {p=0} p' CHANGELOG.md > /tmp/notes.md
   gh release create vX.Y.Z --title vX.Y.Z --notes-file /tmp/notes.md
   ```

4. Publishing the release runs `release.yml`: it checks the tag matches the version, builds the sdist and wheel,
   attaches them to the release and uploads them to PyPI.
5. The `PyPI` workflow then installs the release from PyPI on Linux, macOS and Windows and runs it (it also runs
   weekly). To check by hand, in a fresh environment:

   ```bash
   uv tool install ifinjected==X.Y.Z && ifinjected --version
   ```

## Versioning

`0.1.0` is the first validated release. Minor versions add features; until `1.0.0` the CLI may still change, but the
JSON output follows `its schema_version`, finding IDs keep their meaning and are never reused (see
[json-output.md](json-output.md) and [rules.md](rules.md)), and the GitHub Action keeps its inputs.

## The GitHub Action

The Action (`action.yml` at the repository root) is versioned by the same tags: `uses:
BhuwanJoshi-01/ifinjected@vX.Y.Z` runs the code of that tag, installed from the action's own checkout. To list
it on the GitHub Marketplace, tick *Publish this Action to the GitHub Marketplace* when creating the release in the
browser (the first time, GitHub asks the maintainer to accept the Marketplace agreement). The `Action` workflow
runs the action on a widening and a quiet change for every pull request, so a release never ships a broken one.
