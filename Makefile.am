SUBDIRS = src

AM_MAKEFLAGS = -rR --no-print-directory

EXTRA_DIST = Documentation CHANGES FAQ LICENSE RELEASE-NOTES version

RPM_DIRS = --define "_sourcedir `pwd`" \
	   --define "_rpmdir `pwd`" \
	   --define "_specdir `pwd`" \
	   --define "_builddir `pwd`" \
	   --define "_srcrpmdir `pwd`"

rpm:
	./gen-version
	autoconf --force
	$(MAKE) dist
	rpmbuild $(RPM_DIRS) -ba iptraf-ng.spec

srpm:
	./gen-version
	autoconf --force
	$(MAKE) dist
	rpmbuild $(RPM_DIRS) -bs iptraf-ng.spec

# value for overriding from command line
# e.g: make scratch-build DIST=f15
DIST=rawhide
scratch-build: srpm
	koji build --scratch dist-$(DIST) `make srpm | grep Wrote | cut -d' ' -f2`
