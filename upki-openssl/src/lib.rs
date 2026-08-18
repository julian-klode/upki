#![warn(clippy::undocumented_unsafe_blocks)]

use core::ffi::{c_long, c_void};
use core::marker::PhantomData;
use core::ptr;
use std::os::raw::c_int;
use std::slice;
use std::sync::LazyLock;

use openssl_sys::{
    CRYPTO_EX_DATA, CRYPTO_EX_INDEX_SSL_CTX, CRYPTO_get_ex_new_index, OPENSSL_free, OPENSSL_sk_num,
    OPENSSL_sk_value, SSL, SSL_CTX, SSL_CTX_get_ex_data, SSL_CTX_set_ex_data, SSL_get_SSL_CTX,
    SSL_get_ex_data_X509_STORE_CTX_idx, X509, X509_STORE_CTX, X509_STORE_CTX_get_error_depth,
    X509_STORE_CTX_get_ex_data, X509_STORE_CTX_get0_chain, X509_STORE_CTX_set_error,
    X509_V_ERR_APPLICATION_VERIFICATION, X509_V_ERR_CERT_REVOKED, i2d_X509, stack_st_X509,
};
use rustls_pki_types::CertificateDer;
use tracing::{debug, trace, warn};
use x509_parser::prelude::*;
use upki::ffi::{
    upki_certificate_der, upki_check_revocation, upki_config, upki_config_free, upki_config_new,
    upki_result,
};

/// Sets the upki config to use for connections based upon `ctx`.
///
/// `config` becomes owned by `SSL_CTX`.  If `config` is NULL the previous configuration is
/// freed.
///
/// # Thread safety
///
/// This inherits the property of the OpenSSL API, whereby a single `SSL_CTX` cannot be shared
/// between threads.
///
/// # Safety
///
/// This does nothing if `ctx` is NULL.  `config` is required to be a valid `upki_config` pointer,
/// or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn upki_openssl_set_config(ctx: *mut SSL_CTX, config: *const upki_config) {
    log::init();
    debug!(
        target: "upki_openssl::set_config",
        "entering: ctx={:p} config={:p}", ctx, config
    );

    if ctx.is_null() {
        debug!(target: "upki_openssl::set_config", "ctx is NULL, doing nothing");
        return;
    }

    let Some(index) = *UPKI_SSL_CTX_CONFIG_INDEX else {
        warn!(target: "upki_openssl::set_config", "no ex_data index available, cannot store config");
        return;
    };

    debug!(target: "upki_openssl::set_config", "using ex_data index={index}");

    // SAFETY: `upki_config_free` is defined for a previous valid pointer, or NULL.
    // We also rely on `SSL_CTX_get_ex_data` only returning NULL or a previous
    // pointer provided to `SSL_CTX_set_ex_data`.
    unsafe {
        // free any previous value.
        let previous = SSL_CTX_get_ex_data(ctx, index).cast();
        debug!(target: "upki_openssl::set_config", "freeing previous config={previous:p}");
        upki_config_free(previous);
    }

    // SAFETY: `ctx` is required to be non-NULL (as established above).
    unsafe {
        SSL_CTX_set_ex_data(ctx, index, config.cast_mut().cast());
    }
    debug!(target: "upki_openssl::set_config", "stored config={config:p}");
}

/// Checks certificate revocation using upki, matching OpenSSL's `SSL_verify_cb` interface.
///
/// This function returns 0 if called with 0 for the `preverify_ok` parameter.
/// As a result, it never allows a verification to pass if the previous verification
/// step has failed.
///
/// If the certificate chain obtained from `x509_ctx` is not included in the revocation data,
/// this function returns `preverify_ok`.
///
/// # Configuration
///
/// If ``upki_openssl_set_config()` was previously called against the `SSL_CTX` available
/// from `X509_STORE_CTX`, this configuration is used.
///
/// Otherwise, if that function wasn't called, or no `SSL_CTX` can be obtained from `X509_STORE_CTX`,
/// the configuration file and data location is found automatically based on defaults.
///
/// # Errors
///
/// If the certificate chain obtained from `x509_ctx` is revoked, this function returns 0
/// and sets the `X509_V_ERR_CERT_REVOKED` error on `x509_ctx` (using
/// `X509_STORE_CTX_set_error(3SSL)`).
///
/// If the revocation status cannot be determined, this function returns 0 and sets
/// the `X509_V_ERR_APPLICATION_VERIFICATION` error on `x509_ctx` (using
/// `X509_STORE_CTX_set_error(3SSL)`).
///
/// On unexpected/unrecoverable errors, this function returns 0.
///
/// # Safety
///
/// This function requires that `x509_ctx` is a valid pointer, or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn upki_openssl_verify_callback(
    mut preverify_ok: c_int,
    x509_ctx: *mut X509_STORE_CTX,
) -> c_int {
    log::init();
    debug!(
        target: "upki_openssl::verify_callback",
        "entering: preverify_ok={preverify_ok} x509_ctx={x509_ctx:p}"
    );

    // Revocation checking never improves the situation if the verification has failed.
    if preverify_ok == 0 {
        trace!(target: "upki_openssl::verify_callback", "preverify_ok==0, skipping");
        return preverify_ok;
    }

    // SAFETY: We rely on the caller providing a valid or NULL `x509_ctx` pointer.  This
    // is required by the C undefined behavior rules (C17 §6.3.2.3 item 7)
    let Some(mut x509_ctx) = (unsafe { BorrowedX509StoreCtx::from_ptr(x509_ctx) }) else {
        warn!(target: "upki_openssl::verify_callback", "x509_ctx is NULL, failing verification");
        return 0;
    };

    // This callback is called once per certificate, with the final call being for the
    // leaf certificate denoted by error_depth = 0.   We only process the chain as a whole;
    // do this at the leaf certificate level.
    let error_depth = x509_ctx.error_depth();
    debug!(target: "upki_openssl::verify_callback", "error_depth={error_depth}");
    if error_depth != 0 {
        trace!(target: "upki_openssl::verify_callback", "not the leaf (error_depth={error_depth}), skipping");
        return preverify_ok;
    }

    let Some(chain) = x509_ctx.chain() else {
        warn!(target: "upki_openssl::verify_callback", "no certificate chain available, failing verification");
        return 0;
    };

    let Some(certs) = chain.copy_certs() else {
        warn!(target: "upki_openssl::verify_callback", "failed to copy certificate chain, failing verification");
        return 0;
    };

    debug!(
        target: "upki_openssl::verify_callback",
        "processing chain of {} certificate(s)", certs.len()
    );
    for (i, cert) in certs.iter().enumerate() {
        debug!(target: "upki_openssl::verify_callback", "cert[{i}]: {}", describe_cert(cert));
    }

    let cert_descriptors = certs
        .iter()
        .map(BorrowedUpkiCertificateDer::from_cert)
        .collect::<Vec<BorrowedUpkiCertificateDer<'_>>>();

    if cert_descriptors.is_empty() {
        warn!(target: "upki_openssl::verify_callback", "certificate descriptor list is empty, setting X509_V_ERR_APPLICATION_VERIFICATION");
        x509_ctx.set_error(X509_V_ERR_APPLICATION_VERIFICATION);
        return 0;
    }

    let config = match UpkiConfig::new(&x509_ctx) {
        Ok(config) => config,
        Err(err) => {
            warn!(target: "upki_openssl::verify_callback", "failed to obtain upki config: rc={:#x}, failing verification", result_code(&err));
            x509_ctx.set_error(X509_V_ERR_APPLICATION_VERIFICATION);
            return 0;
        }
    };
    debug!(
        target: "upki_openssl::verify_callback",
        "using upki config from {}",
        match &config {
            UpkiConfig::FromContext(_) => "SSL_CTX ex_data",
            UpkiConfig::Owned(_) => "default config",
        }
    );

    // SAFETY: `upki_check_revocation` requires:
    // - a valid config pointer, established above (either transitively via the safety
    //   preconditions on `upki_openssl_set_config`, or by creating one stored in `_our_config`)
    // - valid pointers to a sequence of certificates, which is provided by the `cert_descriptors` vec.
    let rc = unsafe {
        upki_check_revocation(
            config.as_ptr(),
            cert_descriptors.as_ptr().cast(),
            cert_descriptors.len(),
        )
    };
    let code = result_code(&rc);
    debug!(
        target: "upki_openssl::verify_callback",
        "upki_check_revocation returned {code:#x}"
    );

    match rc {
        upki_result::UPKI_REVOCATION_REVOKED => {
            warn!(target: "upki_openssl::verify_callback", "certificate is REVOKED, setting X509_V_ERR_CERT_REVOKED");
            x509_ctx.set_error(X509_V_ERR_CERT_REVOKED);
            preverify_ok = 0;
        }
        upki_result::UPKI_REVOCATION_NOT_COVERED => {
            debug!(target: "upki_openssl::verify_callback", "revocation status NOT_COVERED by revocation data, allowing");
        }
        upki_result::UPKI_REVOCATION_NOT_REVOKED => {
            debug!(target: "upki_openssl::verify_callback", "certificate NOT_REVOKED, allowing");
        }
        _e => {
            warn!(target: "upki_openssl::verify_callback", "revocation status undetermined ({:#x}), setting X509_V_ERR_APPLICATION_VERIFICATION", _e as u32);
            x509_ctx.set_error(X509_V_ERR_APPLICATION_VERIFICATION);
            preverify_ok = 0;
        }
    }

    debug!(
        target: "upki_openssl::verify_callback",
        "returning preverify_ok={preverify_ok}"
    );
    preverify_ok
}

struct BorrowedX509StoreCtx<'a>(&'a mut X509_STORE_CTX);

impl<'a> BorrowedX509StoreCtx<'a> {
    unsafe fn from_ptr(ptr: *mut X509_STORE_CTX) -> Option<Self> {
        // SAFETY: we pass up the requirements of `ptr::as_mut()` to our caller
        unsafe { ptr.as_mut() }.map(Self)
    }

    fn error_depth(&self) -> c_int {
        // SAFETY: the input pointer is valid, because it comes from our reference.
        unsafe { X509_STORE_CTX_get_error_depth(ptr::from_ref(self.0)) }
    }

    fn chain(&self) -> Option<BorrowedX509Stack<'a>> {
        // SAFETY: This type guarantees that the pointer is of the correct type, alignment, etc,
        // and is non-NULL (via coming from a reference.)
        let chain = unsafe { X509_STORE_CTX_get0_chain(ptr::from_ref(self.0)) };

        // SAFETY: we require that openssl correctly returns a valid pointer, or NULL.
        unsafe { chain.as_ref() }.map(BorrowedX509Stack)
    }

    fn set_error(&mut self, err: i32) {
        // SAFETY: the input pointer is valid, because it comes from our reference.
        // OpenSSL does not document any other preconditions.
        unsafe { X509_STORE_CTX_set_error(ptr::from_mut(self.0), err) };
    }

    fn upki_config_from_ssl_ctx(&self) -> *const upki_config {
        let ssl_ctx = self.ssl_ctx();
        debug!(
            target: "upki_openssl::verify_callback",
            "looking up upki config from SSL_CTX={ssl_ctx:p}"
        );

        match (ssl_ctx.is_null(), *UPKI_SSL_CTX_CONFIG_INDEX) {
            // SAFETY: `ssl_ctx` is non-NULL, the index only has a upki_config pointer inserted into it.
            (false, Some(index)) => {
                // SAFETY: `ssl_ctx` is non-NULL and `index` was allocated by us for `upki_config` pointers.
                let cfg = unsafe { SSL_CTX_get_ex_data(ssl_ctx, index).cast() };
                debug!(target: "upki_openssl::verify_callback", "SSL_CTX ex_data config={cfg:p}");
                cfg
            }
            (_, _) => {
                debug!(target: "upki_openssl::verify_callback", "no SSL_CTX config available");
                ptr::null()
            }
        }
    }

    fn ssl_ctx(&self) -> *const SSL_CTX {
        // SAFETY: the input pointer is valid, because it comes from our reference.
        let ssl: *const SSL = unsafe {
            X509_STORE_CTX_get_ex_data(ptr::from_ref(self.0), SSL_get_ex_data_X509_STORE_CTX_idx())
                .cast()
        };

        match ssl.is_null() {
            true => {
                debug!(target: "upki_openssl::verify_callback", "no SSL associated with X509_STORE_CTX");
                ptr::null()
            }
            // SAFETY: `SSL_get_SSL_CTX` requires non-NULL parameter, established here.
            false => {
                // SAFETY: `ssl` is non-NULL in this branch, satisfying `SSL_get_SSL_CTX`'s precondition.
                let ctx = unsafe { SSL_get_SSL_CTX(ssl) };
                debug!(target: "upki_openssl::verify_callback", "SSL={ssl:p} SSL_CTX={ctx:p}");
                ctx
            }
        }
    }
}

struct BorrowedX509Stack<'a>(&'a stack_st_X509);

impl<'a> BorrowedX509Stack<'a> {
    fn copy_certs(&self) -> Option<Vec<CertificateDer<'static>>> {
        // SAFETY: the stack pointer is valid, thanks to it being from a reference.
        let count = unsafe { OPENSSL_sk_num(ptr::from_ref(self.0).cast()) };
        if count < 0 {
            warn!(target: "upki_openssl::verify_callback", "OPENSSL_sk_num returned negative count {count}");
            return None;
        }
        debug!(target: "upki_openssl::verify_callback", "stack contains {count} certificate(s)");

        let mut certs = vec![];
        for i in 0..count {
            // SAFETY: the stack pointer is valid, thanks to it being from a reference.  `OPENSSL_sk_value` returns
            // a valid pointer to the item or NULL.
            let x509: *const X509 =
                unsafe { OPENSSL_sk_value(ptr::from_ref(self.0).cast(), i).cast() };

            // SAFETY: we require OpenSSL only fills the stack with valid pointers to X509 objects (or NULL)
            let x509 = unsafe { x509.as_ref() }?;
            match x509_to_certificate_der(x509) {
                Some(cert) => {
                    trace!(target: "upki_openssl::verify_callback", "copied cert[{i}] ({})", cert.len());
                    certs.push(cert);
                }
                None => {
                    warn!(target: "upki_openssl::verify_callback", "failed to DER-encode cert[{i}]");
                    return None;
                }
            }
        }

        Some(certs)
    }
}

enum UpkiConfig {
    FromContext(*const upki_config),
    Owned(*mut upki_config),
}

impl UpkiConfig {
    fn new(store_ctx: &BorrowedX509StoreCtx<'_>) -> Result<Self, upki_result> {
        match store_ctx.upki_config_from_ssl_ctx() {
            ptr if !ptr.is_null() => {
                debug!(target: "upki_openssl::verify_callback", "reusing config from SSL_CTX ex_data");
                return Ok(Self::FromContext(ptr));
            }
            _ => {}
        };

        debug!(target: "upki_openssl::verify_callback", "no SSL_CTX config; constructing default config");
        let mut ptr = ptr::null_mut();
        // SAFETY: `upki_config_new` requires a pointer output, as established here.
        let rc = unsafe { upki_config_new(ptr::null(), &mut ptr) };
        let code = result_code(&rc);

        match ptr.is_null() {
            true => {
                warn!(target: "upki_openssl::verify_callback", "upki_config_new failed with rc={code:#x}");
                Err(rc)
            }
            false => {
                debug!(target: "upki_openssl::verify_callback", "default config created at {:p}", ptr);
                Ok(Self::Owned(ptr))
            }
        }
    }

    fn as_ptr(&self) -> *const upki_config {
        match self {
            Self::FromContext(ptr) => *ptr,
            Self::Owned(ptr) => *ptr,
        }
    }
}

impl Drop for UpkiConfig {
    fn drop(&mut self) {
        if let Self::Owned(ptr) = self {
            // SAFETY: `upki_config_free` defined for a valid pointer or NULL.
            unsafe { upki_config_free(*ptr) }
        }
    }
}

/// A `upki_certificate_der` with borrow information intact.
#[repr(transparent)]
struct BorrowedUpkiCertificateDer<'a>(upki_certificate_der, PhantomData<&'a ()>);

impl<'a> BorrowedUpkiCertificateDer<'a> {
    fn from_cert(a: &'a CertificateDer<'a>) -> Self {
        Self(
            upki_certificate_der {
                data: a.as_ptr(),
                len: a.len(),
            },
            PhantomData,
        )
    }
}

fn x509_to_certificate_der(x509: &'_ X509) -> Option<CertificateDer<'static>> {
    // SAFETY: the x509 pointer is valid, thanks to it coming from a reference.
    let (ptr, len) = unsafe {
        let mut ptr = ptr::null_mut();
        let len = i2d_X509(ptr::from_ref(x509), &mut ptr);
        (ptr, len)
    };

    if len <= 0 || ptr.is_null() {
        warn!(target: "upki_openssl::verify_callback", "i2d_X509 failed (len={len})");
        return None;
    }
    let len = len as usize;

    let mut v = Vec::with_capacity(len);
    // SAFETY: we rely on i2d_X509 allocating `ptr` correctly and signalling an error via negative `len` if not.
    // `ptr` must be an allocated pointer from OpenSSL's allocator.
    unsafe {
        v.extend_from_slice(slice::from_raw_parts(ptr, len));
        OPENSSL_free(ptr as *mut _);
    }
    Some(v.into())
}

static UPKI_SSL_CTX_CONFIG_INDEX: LazyLock<Option<c_int>> = LazyLock::new(|| {
    // SAFETY: `CRYPTO_get_ex_new_index` has no documented safety conditions.
    unsafe {
        let index = CRYPTO_get_ex_new_index(
            CRYPTO_EX_INDEX_SSL_CTX,
            0,
            ptr::null_mut(),
            None,
            None,
            Some(ssl_ctx_upki_config_free),
        );
        match index {
        -1 => None,
        _ => Some(index),
    }
    }
});

/// Funnel `CRYPTO_EX_free` into calling `upki_config_free`.
unsafe extern "C" fn ssl_ctx_upki_config_free(
    _parent: *mut c_void,
    config: *mut c_void,
    _ad: *mut CRYPTO_EX_DATA,
    _idx: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) {
    // SAFETY: The previous value is either NULL or a valid config pointer.
    // This matches the precondition of `upki_config_free`.
    unsafe { upki_config_free(config.cast()) };
}

/// Sets up a `tracing` subscriber that honors the `RUST_LOG` environment variable.
///
/// Because `upki-openssl` is loaded as a C library into a host OpenSSL application, no
/// logging is configured by default.  Calling [`init`] installs a `fmt` subscriber driven
/// by `RUST_LOG` (e.g. `RUST_LOG=debug`, `RUST_LOG=upki_openssl=debug`, `RUST_LOG=trace`).
/// It is safe to call repeatedly; only the first invocation has any effect.  If `RUST_LOG`
/// is unset the filter defaults to `off`, so nothing is printed until explicitly enabled.
mod log {
    use std::sync::Once;

    use tracing_subscriber::EnvFilter;

    static INIT: Once = Once::new();

    pub(crate) fn init() {
        INIT.call_once(|| {
            let filter =
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off"));
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(true)
                .try_init();
        });
    }
}

/// Produce a human-readable description of a certificate for debug logging.
fn describe_cert(cert: &CertificateDer<'_>) -> String {
    match X509Certificate::from_der(cert) {
        Ok((_, c)) => format!(
            "subject={} issuer={} serial={:x} len={}",
            c.subject(),
            c.issuer(),
            c.serial,
            cert.len()
        ),
        Err(e) => format!("(unparseable: {e:?}) len={}", cert.len()),
    }
}

/// Read the raw integer value of a `upki_result` without consuming it.
///
/// `upki_result` is a `#[repr(C)]` enum whose discriminants fit in a `u32`; this lets us log
/// the numeric code in addition to the symbolic `match` arms without moving the value.
fn result_code(r: &upki_result) -> u32 {
    // SAFETY: `upki_result` has a `#[repr(C)]` integer backing with `size_of <= size_of::<u32>()`.
    unsafe { core::mem::transmute_copy(r) }
}

#[cfg(test)]
mod test;
