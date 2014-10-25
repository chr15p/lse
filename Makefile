# fctool - manage fc devices 
#
# Copyright (C) 2010 Chris Procter
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v.2.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

CC=gcc
CFLAGS=-Wall -g
EXE=lse 
OBJ=lse.o

COMPILEFLAGS=$(shell pkg-config --cflags --libs libselinux)

LINKERFLAGS=$(shell pkg-config --cflags --libs libselinux)


all: $(OBJ) 
	$(CC) $(OBJ) -o $(EXE) $(LINKERFLAGS) $(CFLAGS)


.c.o:
	$(CC) $(CFLAGS) -c $< $(COMPILEFLAGS)
