//! JNI bridge between the Android app and the dump engine.
//!
//! Exports exactly the four symbols declared in
//! `com.rodroid.il2cppdumper.utils.DumperBridge`:
//!
//! * `Java_com_rodroid_il2cppdumper_utils_DumperBridge_detectFormat`
//! * `Java_com_rodroid_il2cppdumper_utils_DumperBridge_dumpIl2Cpp`
//! * `Java_com_rodroid_il2cppdumper_utils_DumperBridge_getDefaultConfig`
//! * `Java_com_rodroid_il2cppdumper_utils_DumperBridge_initCrashHandler`
//!
//! Callback protocol (`DumperCallback`):
//! * `onLog(String)`                    — receives all log/progress/warn/success lines
//! * `onRequestInput(String) -> String` — returns user input; `null`/empty means skip
//!
//! jni-rs 0.22 API notes:
//! * Native methods receive `EnvUnowned`; `EnvUnowned::with_env` provides a
//!   full `Env` and wraps the closure in `catch_unwind` (so a Rust panic can
//!   never unwind across the FFI boundary).
//! * `EnvOutcome::resolve::<LogContextErrorAndDefault>` converts JNI-level
//!   errors/panics into a `null` return value (Java side falls back to its
//!   own error handling); engine-level errors are encoded into the returned
//!   `"Error: ..."` string, which `DumpViewModel` already detects.

use std::io::Read;
use std::panic;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use jni::errors::LogContextErrorAndDefault;
use jni::jni_sig;
use jni::jni_str;
use jni::objects::{Global, JClass, JObject, JString, JValue};
use jni::sys::{jobject, jstring};
use jni::{Env, EnvUnowned};

use crate::config::Config;
use crate::dump_engine::{self, DumpSink};

/// Name of each native method, used as the error context for `resolve_with`.
fn method_context(name: &'static str) -> String {
    name.to_string()
}

// ---------------------------------------------------------------------------
// detectFormat
// ---------------------------------------------------------------------------

fn describe_file(path: &str) -> String {
    let head = read_file_head(path, 8);
    if head.len() >= 4 {
        let m32 = dump_engine::read_magic_u32(&head);
        if m32 == dump_engine::MAGIC_METADATA {
            return "Metadata".into();
        }
    }
    match dump_engine::detect_format(&head) {
        "elf" => {
            if head.len() >= 5 && head[4] == 2 {
                "ELF64".into()
            } else {
                "ELF32".into()
            }
        }
        "pe" => "PE".into(),
        "macho" => {
            if head.len() >= 4 && dump_engine::read_magic_u32(&head) == dump_engine::MAGIC_MACHO64 {
                "MachO64".into()
            } else {
                "MachO32".into()
            }
        }
        "macho_fat" => "Fat Mach-O".into(),
        "nso" => "NSO".into(),
        "wasm" => "WASM".into(),
        _ => "Unknown".into(),
    }
}

fn read_file_head(path: &str, n: usize) -> Vec<u8> {
    std::fs::File::open(path)
        .map(|mut f| {
            let mut buf = vec![0u8; n];
            let got = f.read(&mut buf).unwrap_or(0);
            buf.truncate(got);
            buf
        })
        .unwrap_or_default()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_rodroid_il2cppdumper_utils_DumperBridge_detectFormat<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
    path: JString<'local>,
) -> jstring {
    let label = unowned_env
        .with_env(|env| -> jni::errors::Result<Option<JString<'local>>> {
            let path = path.mutf8_chars(env)?.to_string();
            Ok(Some(env.new_string(describe_file(&path))?))
        })
        .resolve_with::<LogContextErrorAndDefault, _>(|| method_context("detectFormat"));
    match label {
        Some(js) => js.into_raw(),
        None => std::ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------------
// dumpIl2Cpp
// ---------------------------------------------------------------------------

/// `DumpSink` that forwards every event to the Java `DumperCallback`.
///
/// `callback` is a global reference so it stays alive for the whole dump;
/// the engine runs synchronously on the calling thread, so no cross-thread
/// attachment is needed.
struct JniSink<'env, 'local> {
    env: &'env mut Env<'local>,
    callback: Global<JObject<'static>>,
}

impl JniSink<'_, '_> {
    fn call_log(&mut self, msg: &str) {
        let Ok(jmsg) = self.env.new_string(msg) else { return };
        let jmsg: JObject = jmsg.into();
        let cb = self.callback.as_obj();
        let _ = self.env.call_method(
            cb,
            jni_str!("onLog"),
            jni_sig!("(Ljava/lang/String;)V"),
            &[JValue::Object(&jmsg)],
        );
    }
}

impl DumpSink for JniSink<'_, '_> {
    fn log(&mut self, msg: &str) {
        self.call_log(msg);
    }

    fn progress(&mut self, msg: &str) {
        self.call_log(msg);
    }

    fn warn(&mut self, msg: &str) {
        self.call_log(msg);
    }

    fn success(&mut self, msg: &str) {
        self.call_log(msg);
    }

    fn request_input(&mut self, prompt: &str, default: Option<&str>) -> Option<String> {
        let Ok(jprompt) = self.env.new_string(prompt) else {
            return default.map(String::from);
        };
        let jprompt: JObject = jprompt.into();
        let cb = self.callback.as_obj();
        let out = self
            .env
            .call_method(
                cb,
                jni_str!("onRequestInput"),
                jni_sig!("(Ljava/lang/String;)Ljava/lang/String;"),
                &[JValue::Object(&jprompt)],
            )
            .ok()?;
        let obj = out.l().ok()?;
        if obj.is_null() {
            return default.map(String::from);
        }
        // Re-wrap the raw reference as a JString (transferring ownership of
        // the local reference) for string extraction.
        let jstr = unsafe { JString::from_raw(self.env, obj.into_raw() as jobject) };
        let text = jstr.mutf8_chars(self.env).ok()?.to_string();
        if text.is_empty() {
            default.map(String::from)
        } else {
            Some(text)
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_rodroid_il2cppdumper_utils_DumperBridge_dumpIl2Cpp<'local>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
    binary_path: JString<'local>,
    metadata_path: JString<'local>,
    output_dir: JString<'local>,
    config_json: JString<'local>,
    callback: JObject<'local>,
) -> jstring {
    let out = unowned_env
        .with_env(|env| -> jni::errors::Result<Option<JString<'local>>> {
            let get_str = |env: &mut Env<'local>, s: &JString<'local>| -> String {
                s.mutf8_chars(env).map(|c| c.to_string()).unwrap_or_default()
            };
            let binary_path = get_str(env, &binary_path);
            let metadata_path = get_str(env, &metadata_path);
            let output_dir = get_str(env, &output_dir);
            let config_json = get_str(env, &config_json);

            if binary_path.is_empty() || metadata_path.is_empty() {
                return Ok(Some(env.new_string("Error: binary path and metadata path are required")?));
            }

            // Config derives `#[serde(default)]`, so missing keys fall back to
            // `Config::default()` automatically; a wholly invalid JSON string
            // also falls back to defaults.
            let config = if config_json.is_empty() {
                Config::default()
            } else {
                serde_json::from_str::<Config>(&config_json).unwrap_or_else(|_| Config::default())
            };

            let callback = env.new_global_ref(callback)?;
            let mut sink = JniSink {
                env,
                callback,
            };

            sink.log("Engine: rodroid_il2cppdumper (Rust build)");

            let result = dump_engine::dump_with_sink(
                &binary_path,
                &metadata_path,
                &output_dir,
                &config,
                &mut sink,
            )
            .map(|s| {
                sink.log(&format!(
                    "Dump completed in {:.2}s: {} files",
                    s.elapsed_secs,
                    s.generated_files.len()
                ));
                s.output_dir
            })
            .unwrap_or_else(|e| format!("Error: {}", e.user_message()));

            Ok(Some(env.new_string(&result)?))
        })
        .resolve_with::<LogContextErrorAndDefault, _>(|| method_context("dumpIl2Cpp"));
    match out {
        Some(js) => js.into_raw(),
        None => std::ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------------
// getDefaultConfig
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_rodroid_il2cppdumper_utils_DumperBridge_getDefaultConfig<
    'local,
>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jstring {
    let json = unowned_env
        .with_env(|env| -> jni::errors::Result<Option<JString<'local>>> {
            let json = serde_json::to_string(&Config::default()).unwrap_or_else(|_| "{}".into());
            Ok(Some(env.new_string(&json)?))
        })
        .resolve_with::<LogContextErrorAndDefault, _>(|| method_context("getDefaultConfig"));
    match json {
        Some(js) => js.into_raw(),
        None => std::ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------------
// initCrashHandler
// ---------------------------------------------------------------------------

static PANIC_HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);
static CRASH_LOG_PATH: Mutex<Option<String>> = Mutex::new(None);

fn install_panic_hook(log_path: String) {
    if PANIC_HOOK_INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    // `into_inner()` keeps the hook functional even if the mutex was
    // poisoned by a previous panic while holding the lock.
    *CRASH_LOG_PATH.lock().unwrap_or_else(|e| e.into_inner()) = Some(log_path);
    let prev_hook = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        if let Some(path) = CRASH_LOG_PATH.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            let _ = std::fs::write(path, format!("Native panic: {info}\n"));
        }
        prev_hook(info);
    }));
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_rodroid_il2cppdumper_utils_DumperBridge_initCrashHandler<
    'local,
>(
    mut unowned_env: EnvUnowned<'local>,
    _class: JClass<'local>,
    log_path: JString<'local>,
) {
    let _ = unowned_env
        .with_env(|env| -> jni::errors::Result<()> {
            let path = log_path.mutf8_chars(env)?.to_string();
            if !path.is_empty() {
                install_panic_hook(path);
            }
            Ok(())
        })
        .resolve_with::<LogContextErrorAndDefault, _>(|| method_context("initCrashHandler"));
}
