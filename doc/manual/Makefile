# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line.
SPHINXOPTS    =
SPHINXBUILD   = uv run sphinx-build
SPHINXPROJ    = CascadeUserManual
SOURCEDIR     = source
BUILDDIR      = build
BUILD_DATE    = "Jan 01, 2026"

SPHINXAUTOBUILD     = uv run sphinx-autobuild
SPHINXAUTOBUILDOPTS =
AUTOBUILDDIR        = build/live

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: help deps update-deps live Makefile

deps:
	uv sync --group livehtml

update-deps:
	uv lock
	uv export --format requirements.txt > requirements.txt

live: deps
	@$(SPHINXAUTOBUILD) $(SPHINXAUTOBUILDOPTS) "$(SOURCEDIR)" "$(AUTOBUILDDIR)" $(SPHINXOPTS) $(O)

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O) -D today=$(BUILD_DATE)
