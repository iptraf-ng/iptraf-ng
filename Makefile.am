SUBDIRS = src

AM_MAKEFLAGS = -rR --no-print-directory

EXTRA_DIST = Documentation CHANGES FAQ LICENSE RELEASE-NOTES

RPM_DIRS = --define "_sourcedir `pwd`" \
	   --define "_rpmdir `pwd`" \
	   --define "_specdir `pwd`" \
	   --define "_builddir `pwd`" \
	   --define "_srcrpmdir `pwd`"

rpm: dist
	./gen-version
	rpmbuild $(RPM_DIRS) -ba iptraf-ng.spec

srpm: dist
	./gen-version
	rpmbuild $(RPM_DIRS) -bs iptraf-ng.spec
