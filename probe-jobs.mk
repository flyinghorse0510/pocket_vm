include Makefile
.DEFAULT_GOAL := probe-jobs-show
.PHONY: probe-jobs-show
probe-jobs-show:
	@printf 'MAKEFLAGS=[%s]\n' '$(MAKEFLAGS)'
	@printf 'filter=[%s]\n' '$(filter -j%,$(MAKEFLAGS))'
	@printf 'POCKET_BUILD_JOBS=[%s]\n' '$(POCKET_BUILD_JOBS)'
	@printf 'recipe-env POCKET_BUILD_JOBS=[%s]\n' "$${POCKET_BUILD_JOBS-UNSET}"
	@printf 'recipe-env MAKEFLAGS=[%s]\n' "$${MAKEFLAGS-UNSET}"
	@printf 'recipe-env MFLAGS=[%s]\n' "$${MFLAGS-UNSET}"
