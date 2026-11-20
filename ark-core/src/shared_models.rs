// SPDX-License-Identifier: MIT OR Apache-2.0
//! Process-wide registry of loaded models: scanners and gateways in one
//! process that load the same model (same key) share one instance instead of
//! loading it again. An entry lives as long as one holder keeps it; the
//! registry itself holds only weak references.
use std::{
    any::{Any, TypeId},
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex, Weak},
};

type Entry = Weak<dyn Any + Send + Sync>;

static MODELS: LazyLock<Mutex<HashMap<(TypeId, String), Entry>>> = LazyLock::new(Default::default);

/// The loaded `T` under `key`, loading it with `load` when no holder keeps
/// one. Loads run under the registry lock, so one model loads once even when
/// two hosts start together; scans never take this lock.
pub fn shared<T, E>(key: &str, load: impl FnOnce() -> Result<T, E>) -> Result<Arc<T>, E>
where
    T: Send + Sync + 'static,
{
    let mut models = MODELS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let slot = (TypeId::of::<T>(), key.to_owned());
    if let Some(model) = models
        .get(&slot)
        .and_then(Weak::upgrade)
        .and_then(|model| model.downcast::<T>().ok())
    {
        return Ok(model);
    }
    models.retain(|_, model| model.strong_count() > 0);
    let model = Arc::new(load()?);
    let entry: Arc<dyn Any + Send + Sync> = model.clone();
    models.insert(slot, Arc::downgrade(&entry));
    Ok(model)
}

#[cfg(test)]
mod tests {
    use super::shared;
    use std::sync::Arc;

    #[test]
    fn equal_keys_share_one_instance_while_it_is_held() {
        let mut loads = 0;
        let mut load = || {
            loads += 1;
            Ok::<_, ()>(String::from("model"))
        };
        let first = shared("shared_models::equal", &mut load).unwrap();
        let second = shared("shared_models::equal", &mut load).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        let other = shared("shared_models::other", &mut load).unwrap();
        assert!(!Arc::ptr_eq(&first, &other));
        drop((first, second));
        let reloaded = shared("shared_models::equal", &mut load).unwrap();
        assert_eq!(*reloaded, "model");
        assert_eq!(loads, 3, "a released model loads again");
    }

    #[test]
    fn a_failed_load_is_returned_and_not_kept() {
        assert_eq!(
            shared::<u8, _>("shared_models::fails", || Err("bad")),
            Err("bad")
        );
        assert_eq!(
            *shared("shared_models::fails", || Ok::<u8, ()>(7)).unwrap(),
            7
        );
    }
}
