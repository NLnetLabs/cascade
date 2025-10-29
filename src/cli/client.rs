use std::time::Duration;

use reqwest::{IntoUrl, Method, RequestBuilder};
use url::Url;

const HTTP_CLIENT_TIMEOUT: Duration = Duration::from_secs(120);
static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

#[derive(Clone)]
pub struct CascadeApiClient {
    base_uri: Url,
}

impl CascadeApiClient {
    pub fn new(base_uri: impl IntoUrl) -> Self {
        CascadeApiClient {
            base_uri: base_uri.into_url().unwrap(),
        }
    }

    pub fn base_uri(&self) -> &str {
        self.base_uri.as_str()
    }

    pub fn request(&self, method: Method, s: &str) -> RequestBuilder {
        let path = self.base_uri.join(s).unwrap();

        let client = reqwest::ClientBuilder::new()
            .user_agent(APP_USER_AGENT)
            .timeout(HTTP_CLIENT_TIMEOUT)
            .build()
            .unwrap();

        tracing::debug!("Sending HTTP {method} request to '{path}'");

        client.request(method, path)
    }

    pub fn get(&self, s: &str) -> RequestBuilder {
        self.request(Method::GET, s)
    }

    pub fn post(&self, s: &str) -> RequestBuilder {
        self.request(Method::POST, s)
    }
}

pub fn format_http_error(err: reqwest::Error) -> String {
    if err.is_decode() {
        // Use the debug representation of decoding errors otherwise the cause
        // of the decoding failure, e.g. the underlying Serde error, gets lost
        // and makes determining why the response couldn't be decoded a game
        // of divide and conquer removing response fields one by one until the
        // offending field is determined.
        format!("HTTP request failed: {err:?}")
    } else {
        format!("HTTP request failed: {err}")
    }
}
