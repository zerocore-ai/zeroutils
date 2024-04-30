//! Bindings for the WASI I/O module.

//--------------------------------------------------------------------------------------------------
// Modules
//--------------------------------------------------------------------------------------------------

mod generated {
    wasmtime::component::bindgen!({
        path: "../wit/wasi",
        world: "zeroutils:wasi/imports@0.1.0", // The world that serves as entry point for the generated code.
        tracing: true, // Adds tracing calls to the generated code.
        trappable_imports: true, // Allow imports to trap.
        trappable_error_type: {
            "wasi:io/streams/stream-error" => crate::io::StreamError,
        },
        async: {
            // These are the only methods and functions that are async,
            // all other methods are synchronous.
            only_imports: [
                "[method]input-stream.blocking-read",
                "[method]input-stream.blocking-skip",
                "[method]output-stream.forward",
                "[method]output-stream.splice",
                "[method]output-stream.blocking-splice",
                "[method]output-stream.blocking-flush",
                "[method]output-stream.blocking-write",
                "[method]output-stream.blocking-write-and-flush",
                "[method]output-stream.blocking-write-zeroes-and-flush",
                "poll",
                "[method]pollable.block",
                "[method]pollable.ready",
            ]
        },
        with: {
            "wasi:io/streams/input-stream": crate::io::InputStreamHandle,
            "wasi:io/streams/output-stream": crate::io::OutputStreamHandle,
            "wasi:io/poll/pollable": crate::io::PollableHandle,
            "wasi:io/error/error": crate::io::IoError,
        }
    });
}

pub use generated::wasi::io::*;
