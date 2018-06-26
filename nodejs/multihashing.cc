#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>

extern "C" {
    #include "../algos/blake.h"
    #include "../algos/lyra2v2.h"
    #include "../algos/phi.h"
    #include "../algos/sib.h"
    #include "../algos/tribus.h"
    #include "../algos/x13.h"
    #include "../algos/a5amath.h"
    #include "../algos/bmw.h"
    #include "../algos/hmq17.h"
    #include "../algos/lyra2z.h"
    #include "../algos/polytimos.h"
    #include "../algos/veltor.h"
    #include "../algos/x14.h"
    #include "../algos/aergo.h"
    #include "../algos/c11.h"
    #include "../algos/hsr14.h"
    #include "../algos/Lyra2-z.h"
    #include "../algos/pomelo.h"
    #include "../algos/skein.h"
    #include "../algos/x15.h"
    #include "../algos/allium.h"
    #include "../algos/jha.h"
    #include "../algos/quark.h"
    #include "../algos/skunk.h"
    #include "../algos/vitalium.h"
    #include "../algos/x16r.h"
    #include "../algos/argon2a.h"
    #include "../algos/deep.h"
    #include "../algos/keccak.h"
    #include "../algos/magimath.h"
    #include "../algos/qubit.h"
    #include "../algos/sm3.h"
    #include "../algos/whirlpool.h"
    #include "../algos/x16s.h"
    #include "../algos/bastion.h"
    #include "../algos/drop.h"
    #include "../algos/neoscrypt.h"
    #include "../algos/scryptn.h"
    #include "../algos/scrypt.h"
    #include "../algos/sonoa.h"
    #include "../algos/whirlpoolx.h"
    #include "../algos/x17.h"
    #include "../algos/bitcore.h"
    #include "../algos/fresh.h"
    #include "../algos/luffa.h"
    #include "../algos/nist5.h"
    #include "../algos/x11evo.h"
    #include "../algos/xevan.h"
    #include "../algos/blake2s.h"
    #include "../algos/gost.h"
    #include "../algos/Lyra2.h"
    #include "../algos/pentablake.h"
    #include "../algos/sha256t.h"
    #include "../algos/x11.h"
    #include "../algos/blakecoin.h"
    #include "../algos/groestl.h"
    #include "../algos/lyra2re.h"
    #include "../algos/phi2.h"
    #include "../algos/sha256_Y.h"
    #include "../algos/timetravel.h"
    #include "../algos/x12.h"
    #include "../algos/zr5.h"
    #include "../algos/sha3/blake2s.h"
    #include "../algos/sha3/sph_echo.h"
    #include "../algos/sha3/sph_haval.h"
    #include "../algos/sha3/sph_luffa.h"
    #include "../algos/sha3/sph_shavite.h"
    #include "../algos/sha3/sph_types.h"
    #include "../algos/sha3/sph_blake.h"
    #include "../algos/sha3/sph_fugue.h"
    #include "../algos/sha3/sph_hefty1.h"
    #include "../algos/sha3/sph_ripemd.h"
    #include "../algos/sha3/sph_simd.h"
    #include "../algos/sha3/sph_whirlpool.h"
    #include "../algos/sha3/sph_bmw.h"
    #include "../algos/sha3/sph_groestl.h"
    #include "../algos/sha3/sph_jh.h"
    #include "../algos/sha3/sph_sha2.h"
    #include "../algos/sha3/sph_skein.h"
    #include "../algos/sha3/sph_cubehash.h"
    #include "../algos/sha3/sph_hamsi.h"
    #include "../algos/sha3/sph_keccak.h"
    #include "../algos/sha3/sph_shabal.h"
    #include "../algos/sha3/sph_tiger.h"
}

using namespace node;
using namespace v8;

#if NODE_MAJOR_VERSION >= 4

#define DECLARE_INIT(x) \
    void x(Local<Object> exports)

#define DECLARE_FUNC(x) \
    void x(const FunctionCallbackInfo<Value>& args)

#define DECLARE_SCOPE \
    v8::Isolate* isolate = args.GetIsolate();

#define SET_BUFFER_RETURN(x, len) \
    args.GetReturnValue().Set(Buffer::Copy(isolate, x, len).ToLocalChecked());

#define SET_BOOLEAN_RETURN(x) \
    args.GetReturnValue().Set(Boolean::New(isolate, x));

#define RETURN_EXCEPT(msg) \
    do { \
        isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, msg))); \
        return; \
    } while (0)

#else

#define DECLARE_INIT(x) \
    void x(Handle<Object> exports)

#define DECLARE_FUNC(x) \
    Handle<Value> x(const Arguments& args)

#define DECLARE_SCOPE \
    HandleScope scope

#define SET_BUFFER_RETURN(x, len) \
    do { \
        Buffer* buff = Buffer::New(x, len); \
        return scope.Close(buff->handle_); \
    } while (0)

#define SET_BOOLEAN_RETURN(x) \
    return scope.Close(Boolean::New(x));

#define RETURN_EXCEPT(msg) \
    return ThrowException(Exception::Error(String::New(msg)))

#endif // NODE_MAJOR_VERSION

#define DECLARE_CALLBACK(name, hash, output_len) \
    DECLARE_FUNC(name) { \
    DECLARE_SCOPE; \
 \
    if (args.Length() < 1) \
        RETURN_EXCEPT("You must provide one argument."); \
 \
    Local<Object> target = args[0]->ToObject(); \
 \
    if(!Buffer::HasInstance(target)) \
        RETURN_EXCEPT("Argument should be a buffer object."); \
 \
    char * input = Buffer::Data(target); \
    char output[32]; \
 \
    uint32_t input_len = Buffer::Length(target); \
 \
    hash(input, output, input_len); \
 \
    SET_BUFFER_RETURN(output, output_len); \
}

 // Hashing-Core Callbacks
 DECLARE_CALLBACK(c11, c11_hash, 32);
 DECLARE_CALLBACK(x11, x11_hash, 32);
 DECLARE_CALLBACK(x12, x12_hash, 32);
 DECLARE_CALLBACK(x13, x13_hash, 32);
 DECLARE_CALLBACK(x14, x14_hash, 32);
 DECLARE_CALLBACK(x15, x15_hash, 32);
 DECLARE_CALLBACK(x17, x17_hash, 32);
 DECLARE_CALLBACK(x11evo, x11evo_hash, 32);
 DECLARE_CALLBACK(xevan, xevan_hash, 32);
 DECLARE_CALLBACK(x16r, x16r_hash, 32);
 DECLARE_CALLBACK(x16s, x16s_hash, 32);
 DECLARE_CALLBACK(timetravel, timetravel_hash, 32);
 DECLARE_CALLBACK(bitcore, timetravel10_hash, 32);
 DECLARE_CALLBACK(hsr, hsr_hash, 32);
 DECLARE_CALLBACK(hmq1725, hmq17_hash, 32);
 DECLARE_CALLBACK(jha, jha_hash, 32);
 DECLARE_CALLBACK(allium, allium_hash, 32);
 DECLARE_CALLBACK(lyra2, lyra2re_hash, 32);
 DECLARE_CALLBACK(lyra2v2, lyra2v2_hash, 32);
 DECLARE_CALLBACK(lyra2z, lyra2z_hash, 32);
 DECLARE_CALLBACK(bastion, bastion_hash, 32);
 DECLARE_CALLBACK(blake, blake_hash, 32);
 DECLARE_CALLBACK(blake2s, blake2s_hash, 32);
 DECLARE_CALLBACK(vanilla, blakecoin_hash, 32);
 DECLARE_CALLBACK(decred, decred_hash, 32);
 DECLARE_CALLBACK(deep, deep_hash, 32);
 DECLARE_CALLBACK(fresh, fresh_hash, 32);
 DECLARE_CALLBACK(quark, quark_hash, 32);
 DECLARE_CALLBACK(nist5, nist5_hash, 32);
 DECLARE_CALLBACK(qubit, qubit_hash, 32);
 DECLARE_CALLBACK(groestl, groestl_hash, 32);
 DECLARE_CALLBACK(skein, skein_hash, 32);
 DECLARE_CALLBACK(sonoa, sonoa_hash, 32);
 DECLARE_CALLBACK(tribus, tribus_hash, 32);
 DECLARE_CALLBACK(keccak, keccak256_hash, 32);
 DECLARE_CALLBACK(keccakc, keccak256_hash, 32);
 DECLARE_CALLBACK(phi, phi_hash, 32);
 DECLARE_CALLBACK(phi2, phi2_hash, 32);
 DECLARE_CALLBACK(polytimos, polytimos_hash, 32);
 DECLARE_CALLBACK(skunk, skunk_hash, 32);
 DECLARE_CALLBACK(bmw, bmw_hash, 32);
 DECLARE_CALLBACK(luffa, luffa_hash, 32);
 DECLARE_CALLBACK(penta, penta_hash, 32);
 DECLARE_CALLBACK(zr5, zr5_hash, 32);
 DECLARE_CALLBACK(veltor, veltor_hash, 32);
 DECLARE_CALLBACK(vitalium, vitalium_hash, 32);
 DECLARE_CALLBACK(aergo, aergo_hash, 32);
 DECLARE_CALLBACK(sib, sib_hash, 32);
 DECLARE_CALLBACK(whirlpoolx, whirlpoolx_hash, 32);
 DECLARE_CALLBACK(scrypt, scrypt_hash, 32);
 DECLARE_CALLBACK(scryptn, scryptn_hash, 32);
 DECLARE_CALLBACK(neoscrypt, neoscrypt_hash, 32);


DECLARE_INIT(init) {
 NODE_SET_METHOD(exports, "x11", x11);
 NODE_SET_METHOD(exports, "c11", c11);
 NODE_SET_METHOD(exports, "x11", x11);
 NODE_SET_METHOD(exports, "x12", x12);
 NODE_SET_METHOD(exports, "x13", x13);
 NODE_SET_METHOD(exports, "x14", x14);
 NODE_SET_METHOD(exports, "x15", x15);
 NODE_SET_METHOD(exports, "x17", x17);
 NODE_SET_METHOD(exports, "x11evo", x11evo);
 NODE_SET_METHOD(exports, "xevan", xevan);
 NODE_SET_METHOD(exports, "x16r", x16r);
 NODE_SET_METHOD(exports, "x16s", x16s);
 NODE_SET_METHOD(exports, "timetravel", timetravel);
 NODE_SET_METHOD(exports, "bitcore", bitcore);
 NODE_SET_METHOD(exports, "hsr", hsr);
 NODE_SET_METHOD(exports, "hmq1725", hmq1725);
 NODE_SET_METHOD(exports, "jha", jha);
 NODE_SET_METHOD(exports, "allium", allium);
 NODE_SET_METHOD(exports, "lyra2", lyra2);
 NODE_SET_METHOD(exports, "lyra2v2", lyra2v2);
 NODE_SET_METHOD(exports, "lyra2z", lyra2z);
 NODE_SET_METHOD(exports, "bastion", bastion);
 NODE_SET_METHOD(exports, "blake", blake);
 NODE_SET_METHOD(exports, "blake2s", blake2s);
 NODE_SET_METHOD(exports, "vanilla", vanilla);
 NODE_SET_METHOD(exports, "decred", decred);
 NODE_SET_METHOD(exports, "deep", deep);
 NODE_SET_METHOD(exports, "fresh", fresh);
 NODE_SET_METHOD(exports, "quark", quark);
 NODE_SET_METHOD(exports, "nist5", nist5);
 NODE_SET_METHOD(exports, "qubit", qubit);
 NODE_SET_METHOD(exports, "groestl", groestl);
 NODE_SET_METHOD(exports, "skein", skein);
 NODE_SET_METHOD(exports, "sonoa", sonoa);
 NODE_SET_METHOD(exports, "tribus", tribus);
 NODE_SET_METHOD(exports, "keccak", keccak);
 NODE_SET_METHOD(exports, "keccakc", keccakc);
 NODE_SET_METHOD(exports, "phi", phi);
 NODE_SET_METHOD(exports, "phi2", phi2);
 NODE_SET_METHOD(exports, "polytimos", polytimos);
 NODE_SET_METHOD(exports, "skunk", skunk);
 NODE_SET_METHOD(exports, "bmw", bmw);
 NODE_SET_METHOD(exports, "luffa", luffa);
 NODE_SET_METHOD(exports, "penta", penta);
 NODE_SET_METHOD(exports, "zr5", zr5);
 NODE_SET_METHOD(exports, "veltor", veltor);
 NODE_SET_METHOD(exports, "vitalium", vitalium);
 NODE_SET_METHOD(exports, "aergo", aergo);
 NODE_SET_METHOD(exports, "sib", sib);
 NODE_SET_METHOD(exports, "whirlpoolx", whirlpoolx);
 NODE_SET_METHOD(exports, "scrypt", scrypt);
 NODE_SET_METHOD(exports, "scryptn", scryptn);
 NODE_SET_METHOD(exports, "neoscrypt", neoscrypt);
}

NODE_MODULE(multihashing, init)
