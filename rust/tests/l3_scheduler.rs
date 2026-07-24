use std::time::Duration;

use patronus_ark::{
    QueuedSecurityEvent, SecurityCategory, SecurityGateway, SecurityLevel,
    SecurityRequestCompletion,
};

fn scanner() -> SecurityGateway {
    SecurityGateway::with_max_level(
        vec![SecurityCategory::Injection],
        SecurityLevel::L3,
        None,
        false,
    )
}

fn final_model_order(scanner: &SecurityGateway, job_count: usize) -> Vec<String> {
    let mut fallbacks = 0;
    let mut finals = Vec::new();
    while finals.len() < job_count {
        match scanner
            .consume_next_event(Some(Duration::from_secs(3)))
            .expect("scheduler test timed out")
        {
            QueuedSecurityEvent::Result(queued) if queued.result.level == "L2" => fallbacks += 1,
            QueuedSecurityEvent::Result(queued) if queued.result.level == "L3" => {
                finals.push(queued.result.model)
            }
            QueuedSecurityEvent::Result(_)
            | QueuedSecurityEvent::Progress(_)
            | QueuedSecurityEvent::Provisional(_)
            | QueuedSecurityEvent::Finished { .. } => {}
        }
    }
    assert_eq!(fallbacks, job_count);
    finals
}

#[test]
fn cost_fair_scheduler_gives_short_dynamic_jobs_proportional_turns() {
    let scanner = scanner();
    let jobs = [
        ("injection", 0, 30, "injection-1", 60),
        ("injection", 0, 30, "injection-2", 60),
        ("injection", 0, 30, "injection-3", 60),
        ("dynamic-pii", 1, 10, "dynamic-1", 20),
        ("dynamic-pii", 1, 10, "dynamic-2", 20),
        ("dynamic-pii", 1, 10, "dynamic-3", 20),
        ("dynamic-pii", 1, 10, "dynamic-4", 20),
        ("dynamic-pii", 1, 10, "dynamic-5", 20),
        ("dynamic-pii", 1, 10, "dynamic-6", 20),
    ];
    scanner.enqueue_test_l3_scheduler_requests(&jobs, 20, 5_000);

    let order = final_model_order(&scanner, jobs.len());

    assert_eq!(
        &order[..6],
        [
            "injection-1",
            "dynamic-1",
            "dynamic-2",
            "dynamic-3",
            "injection-2",
            "dynamic-4",
        ]
    );
}

#[test]
fn max_wait_aging_prevents_lower_priority_starvation() {
    let scanner = scanner();
    let jobs = [
        ("dynamic-pii", 10, 5, "aged-dynamic", 20),
        ("injection", 0, 150, "blocking-injection", 60),
        ("injection", 0, 5, "queued-injection", 60),
    ];
    scanner.enqueue_test_l3_scheduler_requests(&jobs, 20, 40);

    let order = final_model_order(&scanner, jobs.len());

    assert_eq!(order[0], "blocking-injection");
    assert_eq!(order[1], "aged-dynamic");
    assert_eq!(order[2], "queued-injection");
}

#[test]
fn request_wide_threat_early_exit_skips_queued_lower_priority_l3_jobs() {
    let scanner = scanner();
    scanner.enqueue_test_request_wide_early_exit_request();

    let mut l3 = Vec::new();
    let mut finished = false;
    while !finished {
        match scanner
            .consume_next_event(Some(Duration::from_secs(3)))
            .expect("request-wide early-exit test timed out")
        {
            QueuedSecurityEvent::Result(queued)
                if queued.result.level == "L3"
                    || queued
                        .result
                        .layers
                        .iter()
                        .any(|layer| layer.layer_type == "l3_skipped") =>
            {
                l3.push(queued.result);
            }
            QueuedSecurityEvent::Finished { completion, .. } => {
                assert!(matches!(completion, SecurityRequestCompletion::Complete));
                finished = true;
            }
            QueuedSecurityEvent::Result(_)
            | QueuedSecurityEvent::Progress(_)
            | QueuedSecurityEvent::Provisional(_) => {}
        }
    }

    assert_eq!(l3.len(), 2);
    assert_eq!(l3[0].category, "threat");
    assert_eq!(l3[0].class_name, "test_l3");
    assert_eq!(l3[1].category, "tool_class");
    assert!(l3[1]
        .layers
        .iter()
        .any(|layer| layer.layer_type == "l3_skipped"
            && layer
                .details
                .get("skip_reason")
                .and_then(serde_json::Value::as_str)
                == Some("request_wide_early_exit")));
}
