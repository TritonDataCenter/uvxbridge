TOP_DIR:=${.CURDIR}

.include "Makefile.inc"
SUBDIR=ipfw
SUBDIR+=src

.include <bsd.subdir.mk>


