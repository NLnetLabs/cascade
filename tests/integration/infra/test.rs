//! Defining and running tests.

use std::{fmt, panic::AssertUnwindSafe, pin::Pin, sync::Arc};

use futures_util::FutureExt;
use tokio::task::JoinSet;
use tracing::Instrument;

pub struct TestPatterns {
    pub raw: Vec<String>,
}

pub struct Test {
    pub name: String,
    pub default_jobs: Vec<serde_json::Value>,
    pub exec: TestExec,
}

type TestExec = Box<dyn Fn(Arc<super::Image>, serde_json::Value) -> TestFuture>;
type TestFuture = Pin<Box<dyn Future<Output = TestResult> + Send + 'static>>;

pub struct TestResult {
    pub name: String,
    pub job_value: serde_json::Value,
    pub result: Result<(), ()>,
}

impl Test {
    /// Construct a new single-job test.
    pub fn new<F: Future<Output = ()> + Send + 'static>(
        name: impl Into<String>,
        exec: fn(Arc<super::Container>) -> F,
    ) -> Self {
        let name = name.into();
        Self {
            name: name.clone(),
            default_jobs: vec![serde_json::Value::default()],
            exec: Box::new(move |image: Arc<super::Image>, job_value| -> TestFuture {
                let container = super::ContainerBuilder::new(&image).build();
                let name = name.clone();
                let span = tracing::info_span!(parent: tracing::Span::none(), "test", name);
                Box::pin(
                    async move {
                        let fut = (exec)(Arc::new(container.await));
                        let result = AssertUnwindSafe(fut).catch_unwind().await.map_err(|_| ());
                        TestResult {
                            name,
                            job_value,
                            result,
                        }
                    }
                    .instrument(span),
                ) as _
            }) as _,
        }
    }

    /// Run a test.
    ///
    /// The test will be matched against the given patterns, and on a hit, will
    /// be spawned onto the given [`JoinSet`].
    pub fn run(
        &self,
        patterns: &TestPatterns,
        join_set: &mut JoinSet<TestResult>,
        image: &Arc<super::Image>,
    ) {
        let job_values = self.filter(patterns);
        for value in job_values {
            let name = Self::job_name(&self.name, &value);
            println!("starting test {name}...");
            let job = (self.exec)(image.clone(), value);
            join_set.spawn(job);
        }
    }

    /// Filter this test based on the given patterns.
    fn filter(&self, patterns: &TestPatterns) -> Vec<serde_json::Value> {
        // TODO: Globs, fuzzy matching, parsing (fuzzy) JSON
        if patterns.raw.is_empty() || patterns.raw.contains(&self.name) {
            self.default_jobs.clone()
        } else {
            vec![]
        }
    }

    /// Format the name of a job.
    pub fn job_name(name: &str, value: &serde_json::Value) -> impl fmt::Display + use<> {
        if value.is_null() {
            name.to_string()
        } else {
            format!("{name}:{value}")
        }
    }
}
