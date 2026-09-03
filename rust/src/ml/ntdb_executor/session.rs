// SPDX-License-Identifier: GPL-3.0-only
use super::{ntdb_error, NtdbResult};
use ort::session::Session;
use std::path::Path;

pub(super) fn load_single_thread_session(path: impl AsRef<Path>) -> NtdbResult<Session> {
    let path = path.as_ref();
    let builder = Session::builder()
        .map_err(|err| ntdb_error(format!("failed to create ORT session builder: {err}")))?;
    let builder = builder
        .with_intra_threads(1)
        .map_err(|err| ntdb_error(format!("failed to set ORT intra threads: {err}")))?;
    let builder = builder
        .with_inter_threads(1)
        .map_err(|err| ntdb_error(format!("failed to set ORT inter threads: {err}")))?;
    let mut builder = builder
        .with_intra_op_spinning(false)
        .map_err(|err| ntdb_error(format!("failed to disable ORT spinning: {err}")))?;
    builder.commit_from_file(path).map_err(|err| {
        ntdb_error(format!(
            "failed to load ORT model {}: {err}",
            path.display()
        ))
    })
}
