CLEAN_SUBDIRS = src doc tests
STUDENT_DIR = ~/pintos-student

all::
	@echo "This makefile has only 'clean' and 'check' targets."

clean::
	for d in $(CLEAN_SUBDIRS); do $(MAKE) -C $$d $@; done

distclean:: clean
	find . -name '*~' -exec rm '{}' \;

check::
	$(MAKE) -C tests $@

studentdist:
	-rm -rf $(STUDENT_DIR)
	mkdir $(STUDENT_DIR)
	cp -r AUTHORS LICENSE Makefile doc specs src tests $(STUDENT_DIR)
