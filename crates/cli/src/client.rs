use std::error::Error;
use std::time::Duration;

use reqwest::{IntoUrl, Method, RequestBuilder};
use tracing::debug;
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

    pub fn request(&self, method: Method, s: &str) -> RequestBuilder {
        let path = self.base_uri.join(s).unwrap();

        let client = reqwest::ClientBuilder::new()
            .user_agent(APP_USER_AGENT)
            .timeout(HTTP_CLIENT_TIMEOUT)
            .build()
            .unwrap();

        debug!("Sending HTTP {method} request to '{path}'");

        client.request(method, path)
    }

    pub fn get(&self, s: &str) -> RequestBuilder {
        self.request(Method::GET, s)
    }

    pub fn post(&self, s: &str) -> RequestBuilder {
        self.request(Method::POST, s)
    }
}

/// Format HTTP errors with message based on error type, and chain error
/// descriptions together instead of simply printing the Debug representation
/// (which is confusing for users).
pub fn format_http_error(err: reqwest::Error) -> String {
    let mut message = String::new();

    // Returning a shortened timed out message to not have a redundant text
    // like: "... HTTP connection timed out: operation timed out"
    if err.is_timeout() {
        // "Returns true if the error is related to a timeout." [1]
        return String::from("HTTP connection timed out");
    }

    // [1]: https://docs.rs/reqwest/latest/reqwest/struct.Error.html
    if err.is_connect() {
        // "Returns true if the error is related to connect" [1]
        message.push_str("HTTP connection failed");
    } else if err.is_decode() {
        // "Returns true if the error is related to decoding the response’s body" [1]
        // Originally, we used the debug representation to be able to see all
        // fields related to the error and make finding the offending field
        // easier. This was confusing for users. Now we print the "source()"
        // of the error below, which contains the relevant information.
        message.push_str("HTTP response decoding failed");
    } else {
        // Covers unknown errors, non-OK HTTP status codes, errors "related to
        // the request" [1], errors "related to the request or response body"
        // [1], errors "from a type Builder" [1], errors "from
        // a RedirectPolicy." [1], errors "related to a protocol upgrade
        // request" [1]
        message.push_str("HTTP request failed");
    }

    // Chain error sources together to capture all relevant error parts. E.g.:
    // "client error (Connect): tcp connect error: Connection refused (os error 111)"
    // instead of just "client error (Connect)";
    // and "client error (SendRequest): connection closed before message completed"
    // instead of just "client error (SendRequest)"
    let mut we = err.source();
    while let Some(e) = we {
        message.push_str(&format!(": {e}"));
        we = e.source();
    }

    message
}
