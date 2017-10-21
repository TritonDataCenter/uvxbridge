TOP_DIR:=${.CURDIR}

.include "Makefile.inc"
SUBDIR=kipfw
SUBDIR+=ipfw
SUBDIR+=src

.include <bsd.subdir.mk>


