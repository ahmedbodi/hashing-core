#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>

extern "C" {
    #include "../algos/a5a.h"
    #include "../algos/blake.h"
    #include "../algos/hive.h"
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
    #include "../algos/skein2.h"
    #include "../algos/veltor.h"
    #include "../algos/x14.h"
    #include "../algos/aergo.h"
    #include "../algos/c11.h"
    #include "../algos/hsr14.h"
    #include "../algos/Lyra2-z.h"
    #include "../algos/pomelo.h"
    #include "../algos/skein.h"
    #include "../algos/velvet.h"
    #include "../algos/x15.h"
    #include "../algos/allium.h"
    #include "../algos/jha.h"
    #include "../algos/m7m.h"
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
    #include "../algos/lbry.h"
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
    #include "../algos/yescrypt.h"
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

 DECLARE_CALLBACK(blake, blake_hash, 32);
 DECLARE_CALLBACK(c11, c11_hash, 32);
 DECLARE_CALLBACK(fresh, fresh_hash, 32);
 DECLARE_CALLBACK(groestl, groestl_hash, 32);
 DECLARE_CALLBACK(groestlmyriad, groestlmyriad_hash, 32);
 DECLARE_CALLBACK(nist5, nist5_hash, 32);
 DECLARE_CALLBACK(quark, quark_hash, 32);
 DECLARE_CALLBACK(qubit, qubit_hash, 32);
 DECLARE_CALLBACK(skein, skein_hash, 32);
 DECLARE_CALLBACK(x11, x11_hash, 32);
 DECLARE_CALLBACK(x13, x13_hash, 32);
 DECLARE_CALLBACK(x15, x15_hash, 32);

DECLARE_INIT(init) {
    NODE_SET_METHOD(exports, "blake", blake);
    NODE_SET_METHOD(exports, "c11", c11);
    NODE_SET_METHOD(exports, "fresh", fresh);
    NODE_SET_METHOD(exports, "groestl", groestl);
    NODE_SET_METHOD(exports, "groestlmyriad", groestlmyriad);
    NODE_SET_METHOD(exports, "nist5", nist5);
    NODE_SET_METHOD(exports, "quark", quark);
    NODE_SET_METHOD(exports, "qubit", qubit);
    NODE_SET_METHOD(exports, "skein", skein);
    NODE_SET_METHOD(exports, "x11", x11);
    NODE_SET_METHOD(exports, "x13", x13);
    NODE_SET_METHOD(exports, "x15", x15);
}

NODE_MODULE(multihashing, init)
