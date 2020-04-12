all: debug release

clean: clean_debug clean_release

debug:
	cd Native && make debug

clean_debug:
	cd Native && make clean_debug

release:
	cd Native && make release

clean_release:
	cd Native && make clean_release
