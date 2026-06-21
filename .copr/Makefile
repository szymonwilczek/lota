# COPR entry point.
# COPR invokes `make -f .copr/Makefile srpm outdir=<dir>`
# and rebuilds the resulting source RPM in a clean chroot.
# Delegate to the top-level srpm target so the build logic lives in one place.
srpm:
	$(MAKE) srpm OUTDIR=$(outdir)
