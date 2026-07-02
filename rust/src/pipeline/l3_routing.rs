use crate::L3SchedulerPolicy;

pub fn priority_index(policy: &L3SchedulerPolicy, category: &str, model: &str) -> usize {
    policy
        .priority
        .iter()
        .position(|item| item == category || item == model)
        .unwrap_or(policy.priority.len())
}

pub fn ttl_ms(policy: &L3SchedulerPolicy, category: &str, model: &str) -> u64 {
    policy
        .ttl_ms
        .get(model)
        .or_else(|| policy.ttl_ms.get(category))
        .copied()
        .unwrap_or(5_000)
}
