// SPDX-License-Identifier: GPL-3.0-only
use std::time::Duration;

use redis::AsyncCommands;
use serde_json::Value;

const OPERATION_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub struct JobStore {
    connection: redis::aio::ConnectionManager,
    prefix: String,
    retention_secs: u64,
    active_ttl_secs: u64,
}

impl JobStore {
    pub async fn connect(
        url: &str,
        prefix: String,
        retention_secs: u64,
        active_ttl_secs: u64,
    ) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(url)?;
        let manager = redis::aio::ConnectionManagerConfig::new()
            .set_connection_timeout(Duration::from_secs(1))
            .set_response_timeout(Duration::from_secs(1))
            .set_number_of_retries(2)
            .set_max_delay(100);
        let connection = deadline(client.get_connection_manager_with_config(manager)).await?;
        let store = Self {
            connection,
            prefix,
            retention_secs,
            active_ttl_secs,
        };
        store.ping().await?;
        Ok(store)
    }

    pub async fn ready(&self) -> bool {
        self.ping().await.is_ok()
    }

    pub async fn save_many(&self, jobs: &[Value]) -> Result<(), redis::RedisError> {
        let mut pipe = redis::pipe();
        pipe.atomic();
        for job in jobs {
            let id = required_string(job, "job_id")?;
            let status = required_string(job, "status")?;
            let ttl = if matches!(status, "completed" | "failed") {
                self.retention_secs
            } else {
                self.active_ttl_secs
            };
            let payload = serde_json::to_string(job).map_err(|error| {
                redis::RedisError::from(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
            })?;
            pipe.cmd("SET")
                .arg(self.key(id))
                .arg(payload)
                .arg("EX")
                .arg(ttl)
                .ignore();
        }
        let mut connection = self.connection.clone();
        deadline(pipe.query_async::<()>(&mut connection)).await
    }

    pub async fn save(&self, job: &Value) -> Result<(), redis::RedisError> {
        self.save_many(std::slice::from_ref(job)).await
    }

    pub async fn load(&self, id: &str) -> Result<Option<Value>, redis::RedisError> {
        let mut connection = self.connection.clone();
        let payload: Option<String> = deadline(connection.get(self.key(id))).await?;
        payload
            .map(|value| {
                serde_json::from_str(&value).map_err(|error| {
                    redis::RedisError::from(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        error,
                    ))
                })
            })
            .transpose()
    }

    async fn ping(&self) -> Result<(), redis::RedisError> {
        let mut connection = self.connection.clone();
        let pong = deadline(redis::cmd("PING").query_async::<String>(&mut connection)).await?;
        if pong == "PONG" {
            Ok(())
        } else {
            Err(redis::RedisError::from((
                redis::ErrorKind::ResponseError,
                "unexpected Redis PING response",
            )))
        }
    }

    fn key(&self, id: &str) -> String {
        format!("{}{}", self.prefix, id)
    }
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, redis::RedisError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| redis::RedisError::from((redis::ErrorKind::TypeError, "invalid job object")))
}

async fn deadline<T>(
    operation: impl std::future::Future<Output = redis::RedisResult<T>>,
) -> redis::RedisResult<T> {
    tokio::time::timeout(OPERATION_TIMEOUT, operation)
        .await
        .map_err(|_| {
            redis::RedisError::from(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Redis operation deadline exceeded",
            ))
        })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    async fn redis_fixture() -> (JobStore, std::sync::Arc<std::sync::Mutex<Vec<Vec<String>>>>) {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let commands = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = commands.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let recorded = recorded.clone();
                tokio::spawn(async move {
                    let mut io = BufReader::new(stream);
                    let mut transaction = None::<Vec<Vec<String>>>;
                    loop {
                        let mut line = String::new();
                        if io.read_line(&mut line).await.unwrap_or(0) == 0 {
                            break;
                        }
                        let count: usize = line.trim().strip_prefix('*').unwrap().parse().unwrap();
                        let mut args = Vec::new();
                        for _ in 0..count {
                            line.clear();
                            io.read_line(&mut line).await.unwrap();
                            let len: usize =
                                line.trim().strip_prefix('$').unwrap().parse().unwrap();
                            let mut value = vec![0; len + 2];
                            io.read_exact(&mut value).await.unwrap();
                            value.truncate(len);
                            args.push(String::from_utf8(value).unwrap());
                        }
                        let response = match args[0].as_str() {
                            "CLIENT" => "+OK\r\n".into(),
                            "PING" => "+PONG\r\n".into(),
                            "MULTI" => {
                                transaction = Some(Vec::new());
                                "+OK\r\n".into()
                            }
                            "EXEC" => {
                                let queued = transaction.take().unwrap();
                                let mut response = format!("*{}\r\n", queued.len());
                                for command in queued {
                                    recorded.lock().unwrap().push(command);
                                    response.push_str("+OK\r\n");
                                }
                                response
                            }
                            "SET" if transaction.is_some() => {
                                transaction.as_mut().unwrap().push(args);
                                "+QUEUED\r\n".into()
                            }
                            command => panic!("unexpected Redis command: {command}"),
                        };
                        if io.get_mut().write_all(response.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        let store = JobStore::connect(&format!("redis://{address}/"), "test:".into(), 900, 1200)
            .await
            .unwrap();
        (store, commands)
    }

    #[test]
    fn job_store_rejects_values_without_identity_or_status() {
        assert!(required_string(&json!({"status":"running"}), "job_id").is_err());
        assert!(required_string(&json!({"job_id":"job_1"}), "status").is_err());
    }

    #[tokio::test]
    async fn parent_jobs_are_saved_atomically_with_state_specific_retention() {
        let (store, commands) = redis_fixture().await;
        store
            .save_many(&[
                json!({"job_id":"job_running","status":"running"}),
                json!({"job_id":"job_done","status":"completed"}),
            ])
            .await
            .unwrap();
        let commands = commands.lock().unwrap();
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0][0], "SET");
        assert_eq!(commands[0][1], "test:job_running");
        assert_eq!(commands[0][3..], ["EX", "1200"]);
        assert_eq!(commands[1][1], "test:job_done");
        assert_eq!(commands[1][3..], ["EX", "900"]);
    }
}
