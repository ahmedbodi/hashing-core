CC=gcc

CXXFLAGS = -O2 -I.. -march=native -fPIC
CFLAGS= $(CXXFLAGS) -std=gnu99
LDFLAGS=-O2 -lgmp
OBJDIR=obj
LIBDIR=../libs

SOURCES=lyra2re.c lyra2v2.c Lyra2.c lyra2z.c Lyra2-z.c Sponge.c allium.c \
	c11.c x11.c x12.c x13.c hsr14.c sm3.c x14.c x15.c x17.c \
	blake.c blakecoin.c blake2s.c jha.c keccak.c lbry.c tribus.c \
	deep.c fresh.c groestl.c neoscrypt.c nist5.c quark.c qubit.c skein.c skein2.c \
	bitcore.c timetravel.c x11evo.c x16r.c x16s.c xevan.c bastion.c hmq17.c sonoa.c \
	bmw.c luffa.c pentablake.c vitalium.c whirlpool.c whirlpoolx.c zr5.c \
	scrypt.c scryptn.c sha256.c sha256t.c \
	yescrypt.c yescrypt-opt.c sha256_Y.c \
	a5a.c a5amath.c m7m.c magimath.cpp velvet.c \
	argon2a.c ar2/blake2b.c ar2/argon2.c ar2/ref.c ar2/cores.c ar2/ar2-scrypt-jane.c \
	hive.c pomelo.c \
	phi.c phi2.c polytimos.c skunk.c sib.c veltor.c gost.c aergo.c \
	sha3/aes_helper.c    sha3/sph_echo.c     sha3/sph_haval.c   sha3/sph_luffa.c    sha3/sph_shabal.c   sha3/sph_tiger.c \
	sha3/blake2s.c       sha3/sph_blake.c     sha3/sph_fugue.c    sha3/sph_hefty1.c  sha3/sph_ripemd.c   sha3/sph_shavite.c  sha3/sph_whirlpool.c \
	sha3/hamsi_helper.c  sha3/sph_bmw.c       sha3/sph_groestl.c  sha3/sph_jh.c      sha3/sph_sha2big.c  sha3/sph_simd.c \
	sha3/sph_cubehash.c  sha3/sph_hamsi.c    sha3/sph_keccak.c  sha3/sph_sha2.c     sha3/sph_skein.c

OBJECTS=$(SOURCES:%.c=obj/%.o) $(SOURCES:%.cpp=obj/%.o)
OUTPUT=libalgos.a

all: $(SOURCES) $(OUTPUT)

$(OUTPUT): $(OBJECTS)
	@mkdir -p $(LIBDIR)
	ar rc $(LIBDIR)/$@ $(OBJECTS)

$(OBJDIR)/%.o: %.cpp
	@mkdir -p $(OBJDIR)
	@mkdir -p $(OBJDIR)/ar2
	@mkdir -p $(OBJDIR)/sha3
	$(CC) $(CXXFLAGS) -c -o $@ $<

$(OBJDIR)/%.o: %.c
	@mkdir -p $(OBJDIR)
	@mkdir -p $(OBJDIR)/ar2
	@mkdir -p $(OBJDIR)/sha3
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJDIR)/*.o
	rm -f $(OBJDIR)/ar2/*.o
	rm -f $(OBJDIR)/sha3/*.o
	rm $(LIBDIR)/libalgos.a

