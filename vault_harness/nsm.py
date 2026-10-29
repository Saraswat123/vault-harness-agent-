"""Fetch a Nitro attestation document from inside the enclave via libnsm (aws-nitro-enclaves-nsm-api).
UNVERIFIED: written from the documented C API (nsm_lib_init / nsm_get_attestation_doc / nsm_lib_exit); it can only be exercised inside a real
Nitro enclave. The enclave's public key is bound into the signed document, so a verifier can prove 'this key belongs to this exact image (PCRs)'."""
import ctypes
import os


def attestation_fn(lib_path: str = None):
    lib = ctypes.CDLL(lib_path or os.environ.get("NSM_LIB", "/usr/lib/libnsm.so"))
    lib.nsm_lib_init.restype = ctypes.c_int32
    lib.nsm_get_attestation_doc.argtypes = [ctypes.c_int32, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint32,
                                            ctypes.c_char_p, ctypes.c_uint32, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32)]
    lib.nsm_get_attestation_doc.restype = ctypes.c_int32

    def get(public_key: bytes, nonce: bytes = None) -> str:
        fd = lib.nsm_lib_init()
        if fd < 0:
            raise RuntimeError("cannot open /dev/nsm (not running inside a Nitro enclave?)")
        try:
            nonce = nonce or os.urandom(32)
            buf = ctypes.create_string_buffer(16384)
            n = ctypes.c_uint32(len(buf))
            rc = lib.nsm_get_attestation_doc(fd, None, 0, nonce, len(nonce), public_key, len(public_key), buf, ctypes.byref(n))
            if rc != 0:
                raise RuntimeError(f"nsm_get_attestation_doc failed ({rc})")
            return buf.raw[: n.value].hex()
        finally:
            lib.nsm_lib_exit(fd)
    return get
