# Build signed Web Bundles (.swbn) for the IWA tools in this repo.
#
# Each tool lives in its own subdirectory with a package.json exposing
# `build`, `keygen` and `test` scripts. Add new tools to UTILS below.
#
#   make              # build every tool's .swbn
#   make adidns       # build just one tool
#   make test         # run every tool's unit tests
#   make keygen-adidns# regenerate a tool's signing key (CHANGES its app origin)
#   make clean        # remove build output
#   make distclean    # also remove installed node_modules

UTILS := adidns soaphound sharphound evil-winrm ldap-shell portscan certify iwa-tools

NPM := npm

# NOTE: do not mark the pattern-rule targets (test-%, keygen-%) .PHONY —
# GNU make skips implicit/pattern rules for phony targets. They never create a
# file, so they re-run every invocation regardless.
.PHONY: all test clean distclean help $(UTILS)

all: $(UTILS)

help:
	@echo "Tools: $(UTILS)"
	@echo "Targets: all, <tool>, test, test-<tool>, keygen-<tool>, clean, distclean"

# Build a tool's signed bundle. Ensures deps and a signing key exist first.
$(UTILS): %: %/node_modules %/signing.key
	$(NPM) --prefix $@ run build
	@echo ">> built $@:" $@/dist/*.swbn

# Install dependencies when package.json is newer than node_modules.
%/node_modules: %/package.json
	$(NPM) --prefix $* install
	@touch $@

# Generate a signing key only if one does not already exist.
%/signing.key:
	$(NPM) --prefix $* run keygen

# Force-regenerate a signing key (new app origin).
keygen-%:
	$(NPM) --prefix $* run keygen -- --force

# Per-tool and aggregate test targets.
test-%: %/node_modules
	$(NPM) --prefix $* test

test: $(addprefix test-,$(UTILS))

clean:
	rm -rf $(addsuffix /dist,$(UTILS))

distclean: clean
	rm -rf $(addsuffix /node_modules,$(UTILS))
