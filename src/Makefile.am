bin_PROGRAMS = le_disasm
bindir = $(prefix)/usr/$(PACKAGE)

le_disasm_SOURCES = \
	analyser.hpp \
	analyser.cpp \
	disassembler.hpp \
	disassembler.cpp \
	error.hpp \
	instruction.hpp \
	instruction.cpp \
	image.hpp \
	image.cpp \
	known_file.hpp \
	known_file.cpp \
	label.hpp \
	label.cpp \
	le.hpp \
	le.cpp \
	le_image.hpp \
	le_image.cpp \
	MAPReader.cpp \
	MAPReader.hpp \
	regions.hpp \
	regions.cpp \
	symbol.cpp \
	symbol.hpp \
	symbol_ld_map.cpp \
	symbol_map.cpp \
	symbol_map.hpp \
	le_disasm.cpp \
	le_disasm_ver.h \
	util.hpp \
	util.cpp

le_disasm_CPPFLAGS = 

le_disasm_RCFLAGS = \
  -I"$(top_srcdir)/src" -I"$(builddir)" \
  $(RCFLAGS)

if HAS_WINDRES
le_disasm_RESRCS = le_disasm_stdres.res
else
le_disasm_RESRCS =
endif

le_disasm_LDADD = \
  $(le_disasm_RESRCS)

if HAS_WINDRES
%.res: $(top_srcdir)/res/%.rc
	$(WINDRES) $(le_disasm_RCFLAGS) -i $< -J rc -o $@ -O coff
endif

# Include dynamic libraries in the package
if TARGET_WINDOWS
install-exec-hook:
	mkdir -p "$(DESTDIR)${prefix}/usr/$(PACKAGE)"
	## Find main executable dependencies
	$(eval lib_SHARED_INSTALL := $(shell objdump -p le_disasm$(EXEEXT) | \
		sed -n 's/\s*\(DLL Name:\|NEEDED\)\s*\(.*\)$$/\2/p' | \
		xargs -I {} find $(shell dirname $(shell which ${CXX})) -name '{}'))
	## Find sub-dependencies for the previous dependencies
	$(eval lib_SHARED_INSTALL += $(shell echo -n '$(lib_SHARED_INSTALL)' | \
        xargs -d ' ' -I {} objdump -p '{}' | \
		sed -n 's/\s*\(DLL Name:\|NEEDED\)\s*\(.*\)$$/\2/p' | \
		xargs -I {} find $(shell dirname $(shell which ${CXX})) -name '{}'))
	## Remove duplicates
	$(eval lib_SHARED_INSTALL := $(sort $(lib_SHARED_INSTALL)))
	cp $(lib_SHARED_INSTALL) $(DESTDIR)${prefix}/usr/$(PACKAGE)
endif


DISTCLEANFILES = *~
