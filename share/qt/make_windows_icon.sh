#!/bin/bash
# create multiresolution windows icon
ICON_DST=../../src/qt/res/icons/disse.ico

convert ../../src/qt/res/icons/disse-16.png ../../src/qt/res/icons/disse-32.png ../../src/qt/res/icons/disse-48.png ${ICON_DST}
