//! OpsRamp sink
//!
//! This sink provides downstream support for `OpsRamp`
//!
//! This sink does not use `PartitionBatching` but elects to do
//! stream multiplexing by organizing the streams in the `build_request`
//! phase. There must be at least one valid set of labels.

use crate::{
    config::{
        log_schema, DataType, GenerateConfig, ProxyConfig, SinkConfig, SinkContext, SinkDescription,
    },
    event::{self, Event, Value},
    http::{Auth, HttpClient, MaybeAuth},
    sinks::util::{
        buffer::opsramp::{
            GlobalTimestamps, OpsRampBuffer, OpsRampEvent, OpsRampRecord, PartitionKey,
        },
        encoding::{EncodingConfig, EncodingConfiguration},
        http::{HttpSink, PartitionHttpSink},
        service::ConcurrencyOption,
        BatchConfig, BatchSettings, PartitionBuffer, PartitionInnerBuffer, TowerRequestConfig,
        UriSerde,
    },
    template::Template,
    tls::{TlsOptions, TlsSettings},
};
use futures::{FutureExt, SinkExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, RwLock};
use std::thread;
use base64;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OpsRampAuthResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    scope: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpsRampConfig {
    endpoint: UriSerde,
    encoding: EncodingConfig<Encoding>,

    tenant_id: Option<Template>,
    client_key: Option<Template>,
    client_secret: Option<Template>,
    labels: HashMap<String, Template>,

    #[serde(default = "crate::serde::default_false")]
    remove_label_fields: bool,
    #[serde(default = "crate::serde::default_true")]
    remove_timestamp: bool,
    #[serde(default)]
    out_of_order_action: OutOfOrderAction,

    auth: Option<Auth>,

    #[serde(default)]
    request: TowerRequestConfig,

    #[serde(default)]
    batch: BatchConfig,

    tls: Option<TlsOptions>,
    proxy: Option<ProxyConfig>,
}

#[derive(Clone, Debug, Derivative, Deserialize, Serialize)]
#[derivative(Default)]
#[serde(rename_all = "snake_case")]
pub enum OutOfOrderAction {
    #[derivative(Default)]
    Drop,
    RewriteTimestamp,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Encoding {
    Json,
    Text,
}

inventory::submit! {
    SinkDescription::new::<OpsRampConfig>("opsramp")
}

impl GenerateConfig for OpsRampConfig {
    fn generate_config() -> toml::Value {
        toml::from_str(
            r#"endpoint = "http://localhost:3100"
            encoding = "json"
            labels = {}"#,
        )
            .unwrap()
    }
}

#[async_trait::async_trait]
#[typetag::serde(name = "opsramp")]
impl SinkConfig for OpsRampConfig {
    async fn build(
        &self,
        cx: SinkContext,
    ) -> crate::Result<(super::VectorSink, super::Healthcheck)> {
        if self.labels.is_empty() {
            return Err("`labels` must include at least one label.".into());
        }

        if self.request.concurrency.is_some() {
            warn!("Option `request.concurrency` is not supported.");
        }
        let mut request_settings = self.request.unwrap_with(&TowerRequestConfig::default());
        request_settings.concurrency = Some(1);

        let batch_settings = BatchSettings::default()
            .bytes(102_400)
            .events(100_000)
            .timeout(1)
            .parse_config(self.batch)?;
        let tls = TlsSettings::from_options(&self.tls)?;
        let client = HttpClient::new(tls, cx.proxy())?;

        let config = OpsRampConfig {
            auth: self.auth.choose_one(&self.endpoint.auth)?,
            proxy: Option::from(cx.proxy().clone()),
            ..self.clone()
        };

        let sink = OpsRampSink::new(config.clone());

        let sink = PartitionHttpSink::new(
            sink,
            PartitionBuffer::new(OpsRampBuffer::new(
                batch_settings.size,
                GlobalTimestamps::default(),
                config.out_of_order_action.clone(),
            )),
            request_settings,
            batch_settings.timeout,
            client.clone(),
            cx.acker(),
        )
            .sink_map_err(|error| error!(message = "Fatal opsramp sink error.", %error));

        let healthcheck = healthcheck(config, client).boxed();

        Ok((super::VectorSink::Sink(Box::new(sink)), healthcheck))
    }

    fn input_type(&self) -> DataType {
        DataType::Log
    }

    fn sink_type(&self) -> &'static str {
        "opsramp"
    }
}

#[derive(Clone, Debug)]
struct OpsRampSink {
    endpoint: UriSerde,
    encoding: EncodingConfig<Encoding>,

    tenant_id: Option<Template>,
    client_key: Option<Template>,
    client_secret: Option<Template>,
    labels: HashMap<String, Template>,

    remove_label_fields: bool,
    remove_timestamp: bool,
    pub gaccess_token: Arc<RwLock<String>>,
    pub renewal_timer_set: Arc<RwLock<bool>>,

    pub gclient_key: Arc<RwLock<String>>,
    pub gclient_secret: Arc<RwLock<String>>,
    tls: Option<TlsOptions>,
    proxy: Option<ProxyConfig>,
}

impl OpsRampSink {
    fn new(config: OpsRampConfig) -> Self {
        Self {
            endpoint: config.endpoint,
            encoding: config.encoding,
            tenant_id: config.tenant_id,
            client_key: config.client_key,
            client_secret: config.client_secret,
            labels: config.labels,
            remove_label_fields: config.remove_label_fields,
            remove_timestamp: config.remove_timestamp,
            gaccess_token: Arc::new(RwLock::new("".to_string())),
            gclient_key: Arc::new(RwLock::new("".to_string())),
            gclient_secret: Arc::new(RwLock::new("".to_string())),
            renewal_timer_set: Arc::new(RwLock::new(false)),
            //tls: config.tls(verify_certificate:false),
            tls: config.tls,
            proxy: config.proxy,
        }
    }

    pub fn spawn_renewal_token(&self, ex_secs: u64) {
        println!("spawn_renewal_token Triggered");
        let this = self.clone();
        let period = ex_secs;
        thread::spawn(move || {
            let this = this.clone();
            println!("Token renewal after secs-- {}", period);
            thread::sleep(std::time::Duration::from_secs(period));
            println!("==========Renewing authentication token===========");
            *this.gaccess_token.write().unwrap() = "".to_string();
        });
    }
}

pub fn keysecret_replacement(
    key: String,
    secret: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let yaml_content = fs::read_to_string("/opt/opsramp/agent/conf/log/log-config.yaml");
    if yaml_content.is_ok() {
        let replaced_yaml_content = yaml_content
            .unwrap()
            .replace(&key, "<ENCRYPTED_KEY>")
            .replace(&secret, "<ENCRYPTED_SECRET>");
        fs::write(
            "/opt/opsramp/agent/conf/log/log-config.yaml",
            replaced_yaml_content,
        );
    }

    let logd_yaml_content = fs::read_to_string("/opt/opsramp/agent/conf/log.d/log-config.yaml");
    if logd_yaml_content.is_ok() {
        let logd_replaced_yaml_content = logd_yaml_content
            .unwrap()
            .replace(&key, "<ENCRYPTED_KEY>")
            .replace(&secret, "<ENCRYPTED_SECRET>");
        fs::write(
            "/opt/opsramp/agent/conf/log.d/log-config.yaml",
            logd_replaced_yaml_content,
        );
    }

    Ok(())
}

#[async_trait::async_trait]
impl HttpSink for OpsRampSink {
    type Input = PartitionInnerBuffer<OpsRampRecord, PartitionKey>;
    type Output = PartitionInnerBuffer<serde_json::Value, PartitionKey>;

    fn encode_event(&self, mut event: Event) -> Option<Self::Input> {
        let tenant_id = self.tenant_id.as_ref().and_then(|t| {
            t.render_string(&event)
                .map_err(|missing| {
                    error!(
                        message = "Error rendering `tenant_id` template.",
                        ?missing,
                        internal_log_rate_secs = 30
                    );
                })
                .ok()
        });
        let client_key = self.client_key.as_ref().and_then(|t| {
            t.render_string(&event)
                .map_err(|missing| {
                    error!(
                        message = "Error rendering `client_key` template.",
                        ?missing,
                        internal_log_rate_secs = 30
                    );
                })
                .ok()
        });
        let client_secret = self.client_secret.as_ref().and_then(|t| {
            t.render_string(&event)
                .map_err(|missing| {
                    error!(
                        message = "Error rendering `client_secret` template.",
                        ?missing,
                        internal_log_rate_secs = 30
                    );
                })
                .ok()
        });

        let ckey = client_key.clone().unwrap();
        let csecret = client_secret.clone().unwrap();

        let key = PartitionKey {
            tenant_id,
            client_key,
            client_secret,
        };

        if self.gclient_key.read().unwrap().to_string().is_empty() {
            *self.gclient_key.write().unwrap() = ckey.clone();
            *self.gclient_secret.write().unwrap() = csecret.clone();
            println!("Calling key replacement");
            keysecret_replacement(ckey, csecret);
        }

        let mut labels = Vec::new();

        for (key, template) in &self.labels {
            if let Ok(value) = template.render_string(&event) {
                labels.push((key.clone(), value));
            }
        }

        if self.remove_label_fields {
            for template in self.labels.values() {
                if let Some(fields) = template.get_fields() {
                    for field in fields {
                        event.as_mut_log().remove(&field);
                    }
                }
            }
        }

        let timestamp = match event.as_log().get(log_schema().timestamp_key()) {
            Some(event::Value::Timestamp(ts)) => ts.timestamp_nanos(),
            _ => chrono::Utc::now().timestamp_nanos(),
        };

        if self.remove_timestamp {
            event.as_mut_log().remove(log_schema().timestamp_key());
        }

        self.encoding.apply_rules(&mut event);
        let log = event.into_log();
        let event = match &self.encoding.codec() {
            Encoding::Json => {
                serde_json::to_string(&log.all_fields()).expect("json encoding should never fail")
            }

            Encoding::Text => log
                .get(log_schema().message_key())
                .map(Value::to_string_lossy)
                .unwrap_or_default(),
        };

        // If no labels are provided we set our own default
        // `{agent="vector"}` label. This can happen if the only
        // label is a templatable one but the event doesn't match.
        if labels.is_empty() {
            labels = vec![("agent".to_string(), "vector".to_string())]
        }

        let event = OpsRampEvent { timestamp, event };
        Some(PartitionInnerBuffer::new(
            OpsRampRecord {
                labels,
                event,
                partition: key.clone(),
            },
            key,
        ))
    }

    async fn build_request(&self, output: Self::Output) -> crate::Result<http::Request<Vec<u8>>> {
        let (json, key) = output.into_parts();
        let tenant_id = key.tenant_id;

        let body = serde_json::to_vec(&json).unwrap();
        let mut access_token: String;
        access_token = self.gaccess_token.read().unwrap().to_string();

        let proxy = self.proxy.clone().unwrap_or_default();

        let proxy_username = proxy.username.clone().unwrap_or_default();
        let proxy_password = proxy.password.clone().unwrap_or_default();

        if access_token.is_empty() {
            println!("Fetching access token as it is empty.. ");
            let client_key = self.gclient_key.read().unwrap().to_string();
            let client_secret = self.gclient_secret.read().unwrap().to_string();
            let opsramp_auth_uri = format!("{}auth/oauth/token", self.endpoint.uri);

            let opsramp_auth_body = format!(
                "client_id={}&client_secret={}&grant_type=client_credentials",
                client_key, client_secret
            );

            let mut builder = http::Request::post(opsramp_auth_uri)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json");
            if proxy_username != "" && proxy_password != "" {
                let proxy_auth_base64 = base64::encode(format!("{}:{}", proxy_username.clone(), proxy_password.clone()));
                builder = builder.header("Proxy-Authorization", format!("Basic {}", proxy_auth_base64));
            }
            let opsramp_auth_req = builder.body(hyper::Body::from(opsramp_auth_body)).unwrap();

            let tls = TlsSettings::from_options(&self.tls)?;

            println!("Using Proxy {:?}", self.proxy);

            let client: HttpClient = HttpClient::new(tls, &proxy)?;

            let opsramp_auth_res = client.send(opsramp_auth_req).await?;
            if opsramp_auth_res.status() != http::StatusCode::OK {
                return Err(format!(
                    "A non-successful status returned: {}",
                    opsramp_auth_res.status()
                )
                    .into());
            } else {
                let body = opsramp_auth_res.into_parts();
                let body_bytes = hyper::body::to_bytes(body.1).await?;
                let bodystring = String::from_utf8(body_bytes.to_vec()).unwrap();
                println!("{}", bodystring);
                let p: OpsRampAuthResponse = serde_json::from_str(&bodystring)?;
                *self.gaccess_token.write().unwrap() = p.access_token.to_string();
                access_token = self.gaccess_token.read().unwrap().to_string();
                let exp_secs = p.expires_in;

                // Start timer to renew access token here
                let timer_set: bool;
                timer_set = *self.renewal_timer_set.read().unwrap();

                if !timer_set {
                    *self.renewal_timer_set.write().unwrap() = true;
                    println!("Setting Renewal timer {}", exp_secs);
                    self.spawn_renewal_token(exp_secs);
                }

                //TO-DO Hide below log once tested
                println!("access_token saved:{}", access_token);
            }
        } else {
            //println!("Using saved Acess token : {} ",access_token);
            println!("Using saved Access token");
        }

        let uri = format!(
            "{}logswql/api/v7/tenants/{}/logs",
            self.endpoint.uri,
            tenant_id.clone().unwrap()
        );
        println!("{}", uri);

        let mut req = http::Request::post(uri).header("Content-Type", "application/json");

        if let Some(tenant_id) = tenant_id {
            req = req.header("X-Scope-OrgID", tenant_id);
        }
        if proxy_username != "" && proxy_password != "" {
            let proxy_auth_base64 = base64::encode(format!("{}:{}", proxy_username.clone(), proxy_password.clone()));
            req = req.header("Proxy-Authorization", format!("Basic {}", proxy_auth_base64));
        }

        let mut req = req.body(body).unwrap();

        let auth = Auth::Bearer {
            token: access_token.to_string(),
        };
        auth.apply(&mut req);

        Ok(req)
    }
}

async fn healthcheck(config: OpsRampConfig, client: HttpClient) -> crate::Result<()> {
    let uri = format!("{}", config.endpoint.uri);

    let mut req = http::Request::get(uri).body(hyper::Body::empty()).unwrap();

    if let Some(auth) = &config.auth {
        auth.apply(&mut req);
    }

    let res = client.send(req).await?;

    if res.status() != http::StatusCode::OK {
        return Err(format!("A non-successful status returned: {}", res.status()).into());
    }
    // let request = sink.build_request(vec![]).await?.map(Body::from);

    // let response = client.send(request).await?;
    // healthcheck_response(sink.creds.clone(), HealthcheckError::NotFound.into())(response);

    Ok(())
}

// Use this to map a healthcheck response, as it handles setting up the renewal task.
// pub fn healthcheck_response(
//     creds: Option<Auth>,
//     not_found_error: crate::Error,
// ) -> impl FnOnce(http::Response<hyper::Body>) -> crate::Result<()> {
//     move |response| match response.status() {
//         StatusCode::OK => {
//             // If there are credentials configured, the
//             // generated OAuth token needs to be periodically
//             // regenerated. Since the health check runs at
//             // startup, after a successful health check is a
//             // good place to create the regeneration task.
//             if let Some(creds) = creds {
//                 creds.spawn_regenerate_token();
//             }
//             Ok(())
//         }
//         StatusCode::FORBIDDEN => Err(GcpError::InvalidCredentials0.into()),
//         StatusCode::NOT_FOUND => Err(not_found_error),
//         status => Err(HealthcheckError::UnexpectedStatus { status }.into()),
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use crate::sinks::util::http::HttpSink;
    use crate::sinks::util::test::{build_test_server, load_sink};
    use crate::test_util;
    use futures::StreamExt;

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<OpsRampConfig>();
    }

    #[test]
    fn interpolate_labels() {
        let (config, _cx) = load_sink::<OpsRampConfig>(
            r#"
            endpoint = "http://localhost:3100"
            labels = {label1 = "{{ foo }}", label2 = "some-static-label", label3 = "{{ foo }}"}
            encoding = "json"
            remove_label_fields = true
        "#,
        )
            .unwrap();
        let sink = OpsRampSink::new(config);

        let mut e1 = Event::from("hello world");

        e1.as_mut_log().insert("foo", "bar");

        let mut record = sink.encode_event(e1).unwrap().item.into_parts().0;

        // HashMap -> Vec doesn't like keeping ordering
        record.labels.sort();

        // The final event should have timestamps and labels removed
        let expected_line = serde_json::to_string(&serde_json::json!({
            "message": "hello world",
        }))
            .unwrap();

        assert_eq!(record.event.event, expected_line);

        assert_eq!(record.labels[0], ("label1".to_string(), "bar".to_string()));
        assert_eq!(
            record.labels[1],
            ("label2".to_string(), "some-static-label".to_string())
        );
        // make sure we can reuse fields across labels.
        assert_eq!(record.labels[2], ("label3".to_string(), "bar".to_string()));
    }

    #[test]
    fn use_label_from_dropped_fields() {
        let (config, _cx) = load_sink::<OpsRampConfig>(
            r#"
            endpoint = "http://localhost:3100"
            labels.bar = "{{ foo }}"
            encoding.codec = "json"
            encoding.except_fields = ["foo"]
        "#,
        )
            .unwrap();
        let sink = OpsRampSink::new(config);

        let mut e1 = Event::from("hello world");

        e1.as_mut_log().insert("foo", "bar");

        let record = sink.encode_event(e1).unwrap().item.into_parts().0;

        let expected_line = serde_json::to_string(&serde_json::json!({
            "message": "hello world",
        }))
            .unwrap();

        assert_eq!(record.event.event, expected_line);

        assert_eq!(record.labels[0], ("bar".to_string(), "bar".to_string()));
    }

    #[tokio::test]
    async fn healthcheck_includes_auth() {
        let (mut config, _cx) = load_sink::<OpsRampConfig>(
            r#"
            endpoint = "http://localhost:3100"
            labels = {test_name = "placeholder"}
            encoding = "json"
			auth.strategy = "basic"
			auth.user = "username"
			auth.password = "some_password"
        "#,
        )
            .unwrap();

        let addr = test_util::next_addr();
        let endpoint = format!("http://{}", addr);
        config.endpoint = endpoint
            .clone()
            .parse::<http::Uri>()
            .expect("could not create URI")
            .into();

        let (rx, _trigger, server) = build_test_server(addr);
        tokio::spawn(server);

        let tls = TlsSettings::from_options(&config.tls).expect("could not create TLS settings");
        let client = HttpClient::new(tls, _cx.proxy()).expect("could not cerate HTTP client");

        healthcheck(config.clone(), client)
            .await
            .expect("healthcheck failed");

        let output = rx.take(1).collect::<Vec<_>>().await;
        assert_eq!(
            Some(&http::header::HeaderValue::from_static(
                "Basic dXNlcm5hbWU6c29tZV9wYXNzd29yZA=="
            )),
            output[0].0.headers.get("authorization")
        );
    }
}

#[cfg(feature = "opsramp-integration-tests")]
#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::{
        config::SinkConfig, sinks::util::test::load_sink, sinks::VectorSink, template::Template,
        test_util::random_lines,
    };
    use bytes::Bytes;
    use chrono::{DateTime, Duration, Utc};
    use futures::{stream, StreamExt};
    use std::convert::TryFrom;
    use vector_core::event::{BatchNotifier, BatchStatus, Event, LogEvent};

    async fn build_sink(encoding: &str) -> (uuid::Uuid, VectorSink) {
        let stream = uuid::Uuid::new_v4();

        let config = format!(
            r#"
            endpoint = "http://localhost:3100"
            labels = {{test_name = "placeholder"}}
            encoding = "{}"
            remove_timestamp = false
            tenant_id = "default"
        "#,
            encoding
        );

        let (mut config, cx) = load_sink::<OpsRampConfig>(&config).unwrap();

        let test_name = config.labels.get_mut("test_name").unwrap();
        assert_eq!(test_name.get_ref(), &Bytes::from("placeholder"));

        *test_name = Template::try_from(stream.to_string()).unwrap();

        let (sink, _) = config.build(cx).await.unwrap();

        (stream, sink)
    }

    #[tokio::test]
    async fn text() {
        let (stream, sink) = build_sink("text").await;

        let lines = random_lines(100).take(10).collect::<Vec<_>>();

        let (batch, mut receiver) = BatchNotifier::new_with_receiver();
        let events = lines
            .clone()
            .into_iter()
            .map(move |line| Event::from(LogEvent::from(line).with_batch_notifier(&batch)));
        let _ = sink
            .into_sink()
            .send_all(&mut stream::iter(events).map(Ok))
            .await
            .unwrap();
        assert_eq!(receiver.try_recv(), Ok(BatchStatus::Delivered));

        let (_, outputs) = fetch_stream(stream.to_string(), "default").await;
        assert_eq!(lines.len(), outputs.len());
        for (i, output) in outputs.iter().enumerate() {
            assert_eq!(output, &lines[i]);
        }
    }

    #[tokio::test]
    async fn json() {
        let (stream, sink) = build_sink("json").await;

        let events = random_lines(100)
            .take(10)
            .map(Event::from)
            .collect::<Vec<_>>();
        let (batch, mut receiver) = BatchNotifier::new_with_receiver();
        let _ = sink
            .into_sink()
            .send_all(&mut stream::iter(events.clone().into_iter().map(
                move |event| Ok(event.into_log().with_batch_notifier(&batch).into()),
            )))
            .await
            .unwrap();
        assert_eq!(receiver.try_recv(), Ok(BatchStatus::Delivered));

        let (_, outputs) = fetch_stream(stream.to_string(), "default").await;
        assert_eq!(events.len(), outputs.len());
        for (i, output) in outputs.iter().enumerate() {
            let expected_json = serde_json::to_string(&events[i].as_log().all_fields()).unwrap();
            assert_eq!(output, &expected_json);
        }
    }

    #[tokio::test]
    async fn many_streams() {
        let stream1 = uuid::Uuid::new_v4();
        let stream2 = uuid::Uuid::new_v4();

        let (config, cx) = load_sink::<OpsRampConfig>(
            r#"
            endpoint = "http://localhost:3100"
            labels = {test_name = "{{ stream_id }}"}
            encoding = "text"
            tenant_id = "default"
        "#,
        )
            .unwrap();

        let (sink, _) = config.build(cx).await.unwrap();

        let lines = random_lines(100).take(10).collect::<Vec<_>>();

        let mut events = lines
            .clone()
            .into_iter()
            .map(Event::from)
            .collect::<Vec<_>>();

        for i in 0..10 {
            let event = events.get_mut(i).unwrap();

            if i % 2 == 0 {
                event.as_mut_log().insert("stream_id", stream1.to_string());
            } else {
                event.as_mut_log().insert("stream_id", stream2.to_string());
            }
        }

        let _ = sink
            .into_sink()
            .send_all(&mut stream::iter(events).map(Ok))
            .await
            .unwrap();

        let (_, outputs1) = fetch_stream(stream1.to_string(), "default").await;
        let (_, outputs2) = fetch_stream(stream2.to_string(), "default").await;

        assert_eq!(outputs1.len() + outputs2.len(), lines.len());

        for (i, output) in outputs1.iter().enumerate() {
            let index = (i % 5) * 2;
            assert_eq!(output, &lines[index]);
        }

        for (i, output) in outputs2.iter().enumerate() {
            let index = ((i % 5) * 2) + 1;
            assert_eq!(output, &lines[index]);
        }
    }

    #[tokio::test]
    async fn many_tenants() {
        let stream = uuid::Uuid::new_v4();

        let (mut config, cx) = load_sink::<OpsRampConfig>(
            r#"
            endpoint = "http://localhost:3100"
            labels = {test_name = "placeholder"}
            encoding = "text"
            tenant_id = "{{ tenant_id }}"
        "#,
        )
            .unwrap();

        let test_name = config.labels.get_mut("test_name").unwrap();
        assert_eq!(test_name.get_ref(), &Bytes::from("placeholder"));

        *test_name = Template::try_from(stream.to_string()).unwrap();

        let (sink, _) = config.build(cx).await.unwrap();

        let lines = random_lines(100).take(10).collect::<Vec<_>>();

        let mut events = lines
            .clone()
            .into_iter()
            .map(Event::from)
            .collect::<Vec<_>>();

        for i in 0..10 {
            let event = events.get_mut(i).unwrap();

            if i % 2 == 0 {
                event.as_mut_log().insert("tenant_id", "tenant1");
            } else {
                event.as_mut_log().insert("tenant_id", "tenant2");
            }
        }

        let _ = sink
            .into_sink()
            .send_all(&mut stream::iter(events).map(Ok))
            .await
            .unwrap();

        let (_, outputs1) = fetch_stream(stream.to_string(), "tenant1").await;
        let (_, outputs2) = fetch_stream(stream.to_string(), "tenant2").await;

        assert_eq!(outputs1.len() + outputs2.len(), lines.len());

        for (i, output) in outputs1.iter().enumerate() {
            let index = (i % 5) * 2;
            assert_eq!(output, &lines[index]);
        }

        for (i, output) in outputs2.iter().enumerate() {
            let index = ((i % 5) * 2) + 1;
            assert_eq!(output, &lines[index]);
        }
    }

    #[tokio::test]
    async fn out_of_order_drop() {
        let batch_size = 5;
        let lines = random_lines(100).take(10).collect::<Vec<_>>();
        let mut events = lines
            .clone()
            .into_iter()
            .map(Event::from)
            .collect::<Vec<_>>();

        let base = chrono::Utc::now() - Duration::seconds(20);
        for (i, event) in events.iter_mut().enumerate() {
            let log = event.as_mut_log();
            log.insert(
                log_schema().timestamp_key(),
                base + Duration::seconds(i as i64),
            );
        }
        // first event of the second batch is out-of-order.
        events[batch_size]
            .as_mut_log()
            .insert(log_schema().timestamp_key(), base);

        let mut expected = events.clone();
        expected.remove(batch_size);

        test_out_of_order_events(OutOfOrderAction::Drop, batch_size, events, expected).await;
    }

    #[tokio::test]
    async fn out_of_order_rewrite() {
        let batch_size = 5;
        let lines = random_lines(100).take(10).collect::<Vec<_>>();
        let mut events = lines
            .clone()
            .into_iter()
            .map(Event::from)
            .collect::<Vec<_>>();

        let base = chrono::Utc::now() - Duration::seconds(20);
        for (i, event) in events.iter_mut().enumerate() {
            let log = event.as_mut_log();
            log.insert(
                log_schema().timestamp_key(),
                base + Duration::seconds(i as i64),
            );
        }
        // first event of the second batch is out-of-order.
        events[batch_size]
            .as_mut_log()
            .insert(log_schema().timestamp_key(), base);

        let mut expected = events.clone();
        let time = get_timestamp(&expected[batch_size - 1]);
        // timestamp is rewriten with latest timestamp of the first batch
        expected[batch_size]
            .as_mut_log()
            .insert(log_schema().timestamp_key(), time);

        test_out_of_order_events(
            OutOfOrderAction::RewriteTimestamp,
            batch_size,
            events,
            expected,
        )
            .await;
    }

    async fn test_out_of_order_events(
        action: OutOfOrderAction,
        batch_size: usize,
        events: Vec<Event>,
        expected: Vec<Event>,
    ) {
        crate::test_util::trace_init();
        let stream = uuid::Uuid::new_v4();

        let (mut config, cx) = load_sink::<OpsRampConfig>(
            r#"
            endpoint = "http://localhost:3100"
            labels = {test_name = "placeholder"}
            encoding = "text"
            tenant_id = "default"
        "#,
        )
            .unwrap();
        config.out_of_order_action = action;
        config.labels.insert(
            "test_name".to_owned(),
            Template::try_from(stream.to_string()).unwrap(),
        );
        config.batch.max_events = Some(batch_size);

        let (sink, _) = config.build(cx).await.unwrap();
        sink.into_sink()
            .send_all(&mut stream::iter(events.clone()).map(Ok))
            .await
            .unwrap();

        let (timestamps, outputs) = fetch_stream(stream.to_string(), "default").await;
        assert_eq!(expected.len(), outputs.len());
        assert_eq!(expected.len(), timestamps.len());
        for (i, output) in outputs.iter().enumerate() {
            assert_eq!(
                &expected[i]
                    .as_log()
                    .get(log_schema().message_key())
                    .unwrap()
                    .to_string_lossy(),
                output,
            )
        }
        for (i, ts) in timestamps.iter().enumerate() {
            assert_eq!(get_timestamp(&expected[i]).timestamp_nanos(), *ts);
        }
    }

    fn get_timestamp(event: &Event) -> DateTime<Utc> {
        *event
            .as_log()
            .get(log_schema().timestamp_key())
            .unwrap()
            .as_timestamp()
            .unwrap()
    }

    async fn fetch_stream(stream: String, tenant: &str) -> (Vec<i64>, Vec<String>) {
        let query = format!("%7Btest_name%3D\"{}\"%7D", stream);
        let query = format!(
            "http://localhost:3100/opsramp/api/v1/query_range?query={}&direction=forward",
            query
        );

        let res = reqwest::Client::new()
            .get(&query)
            .header("X-Scope-OrgID", tenant)
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), 200);

        // The response type follows this api https://github.com/grafana/opsramp/blob/master/docs/api.md#get-opsrampapiv1query_range
        // where the result type is `streams`.
        let data = res.json::<serde_json::Value>().await.unwrap();

        // TODO: clean this up or explain it via docs
        let results = data
            .get("data")
            .unwrap()
            .get("result")
            .unwrap()
            .as_array()
            .unwrap();

        let values = results[0].get("values").unwrap().as_array().unwrap();

        // the array looks like: [ts, line].
        let timestamps = values
            .iter()
            .map(|v| v[0].as_str().unwrap().parse().unwrap())
            .collect();
        let lines = values
            .iter()
            .map(|v| v[1].as_str().unwrap().to_string())
            .collect();
        (timestamps, lines)
    }
}
