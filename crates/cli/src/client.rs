use std::error::Error;
use std::time::Duration;

use reqwest::{IntoUrl, Method, RequestBuilder};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::{debug, warn};
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

    #[allow(dead_code)]
    pub fn get(&self, s: &str) -> RequestBuilder {
        self.request(Method::GET, s)
    }

    #[allow(dead_code)]
    pub fn post(&self, s: &str) -> RequestBuilder {
        self.request(Method::POST, s)
    }

    #[allow(dead_code)]
    pub async fn get_json_with<T, P>(&self, s: &str, payload: &P) -> Result<T, String>
    where
        T: DeserializeOwned,
        P: Serialize,
    {
        send_format_decode(self.request(Method::GET, s).json(payload)).await
    }

    pub async fn post_json_with<T, P>(&self, s: &str, payload: &P) -> Result<T, String>
    where
        T: DeserializeOwned,
        P: Serialize,
    {
        send_format_decode(self.request(Method::POST, s).json(payload)).await
    }

    pub async fn get_json<T>(&self, s: &str) -> Result<T, String>
    where
        T: DeserializeOwned,
    {
        send_format_decode(self.request(Method::GET, s)).await
    }

    pub async fn post_json<T>(&self, s: &str) -> Result<T, String>
    where
        T: DeserializeOwned,
    {
        send_format_decode(self.request(Method::POST, s)).await
    }
}

pub async fn send_format_decode<T>(req: RequestBuilder) -> Result<T, String>
where
    T: DeserializeOwned,
{
    req.send()
        .await
        .map_err(format_http_error)? // Format connection errors
        .error_for_status()
        .map_err(format_http_error)? // Format status code errors
        .json()
        .await
        .map_err(format_http_error) // Format decoding errors
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

    // [1]: https://docs.rs/reqwest/0.13.2/reqwest/struct.Error.html
    if err.is_connect() {
        // "Returns true if the error is related to connect" [1]
        message.push_str("HTTP connection failed");
    } else if err.is_status() {
        // "Returns true if the error is from Response::error_for_status" [1]
        message.push_str("HTTP request failed with status code ");
        if let Some(status) = err.status() {
            message.push_str(status.as_str());
        } else {
            // This should not happen, as we get into this branch from
            // Response::error_for_status.
            warn!(
                "internal inconsistency: HTTP error is of type status but did not contain a status code"
            );
            message.push_str("<unknown>");
        }
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
