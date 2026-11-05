//! Building and managing the Docker image.

use std::{
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

use bollard::{
    plugin::{BuildInfo, BuildInfoAux, ImageId},
    query_parameters::{BuildImageOptionsBuilder, BuilderVersion},
};
use futures_util::StreamExt;

//----------- ImageBuilder -----------------------------------------------------

/// A builder for an [`Image`].
pub struct ImageBuilder {
    /// A client for controlling Docker.
    docker: Arc<bollard::Docker>,

    /// The name of the image.
    name: Option<Box<str>>,

    /// The repository path.
    ///
    /// By default, fetched from the `CARGO_MANIFEST_DIR` env var.
    repo_path: Option<Box<Path>>,
}

impl ImageBuilder {
    /// Construct a new [`ImageBuilder`].
    pub fn new(docker: Arc<bollard::Docker>) -> Self {
        Self {
            docker,
            name: None,
            repo_path: None,
        }
    }

    /// Override the name of the image.
    #[expect(dead_code)]
    pub fn name(mut self, name: impl Into<Box<str>>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Override the repository path.
    #[expect(dead_code)]
    pub fn repo_path(mut self, repo_path: impl Into<Box<Path>>) -> Self {
        self.repo_path = Some(repo_path.into());
        self
    }

    /// Build the image using this configuration.
    #[tracing::instrument(level = "info", name = "build_image", skip_all)]
    pub async fn build(self) -> Image {
        tracing::info!("Initiating build");

        let docker = self.docker;

        let name = self
            .name
            .unwrap_or_else(|| "nlnetlabs/cascade-tests-runner".into());

        let repo_path = self.repo_path.unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap()).into()
        });

        tracing::debug!("Preparing image context");

        // Build the context tarball in memory without streaming.
        // It's very small because its size heavily affects rebuild times.
        let mut context = tar::Builder::new(vec![]);
        context.follow_symlinks(false);
        context.sparse(false);
        context.mode(tar::HeaderMode::Deterministic);
        context
            .append_path_with_name(repo_path.join("tests/integration/Dockerfile"), "Dockerfile")
            .unwrap();
        context
            .append_dir_all(".", repo_path.join("tests/integration/data"))
            .unwrap();
        let body = context.into_inner().unwrap();
        let body = bollard::body_full(body.into());

        tracing::debug!("Passing on to Docker");

        let session = uuid::Uuid::new_v4();
        let options = BuildImageOptionsBuilder::new()
            .t(&name)
            .version(BuilderVersion::BuilderBuildKit)
            .session(&session.to_string())
            .build();

        // Consume build info logs and wait.
        let mut state = BuildState::default();
        // NOTE: `stream` borrows `docker` and confuses the borrow checker.
        {
            let stream = docker.build_image(options, None, Some(body));
            let mut stream = std::pin::pin!(stream);

            while let Some(info) = stream.next().await {
                state.consume(info);
            }
        }

        let Some(id) = state.image_id else {
            panic!("Build finished without errors but missing image ID");
        };

        tracing::info!("Built image");

        Image { docker, name, id }
    }
}

//----------- Image ------------------------------------------------------------

/// A prepared Docker image.
pub struct Image {
    /// A client for controlling Docker.
    pub docker: Arc<bollard::Docker>,

    /// The name of the image.
    pub name: Box<str>,

    /// The ID of the built image.
    #[expect(dead_code)]
    pub id: Box<str>,
}

//------------------------------------------------------------------------------

/// The state of an image build.
///
/// This accumulates [`BuildInfo`] data, saving relevant information and
/// logging out the rest.
#[derive(Default)]
struct BuildState {
    /// The image ID that has been built.
    image_id: Option<Box<str>>,
}

impl BuildState {
    /// Consume the next build info message.
    fn consume(&mut self, info: Result<BuildInfo, bollard::errors::Error>) {
        let info = match info {
            Ok(info) => info,
            Err(err) => {
                tracing::error!("Error while watching build: {err:?}");
                panic!("Could not build image")
            }
        };

        tracing::trace!(?info, "build info");

        let Some(id) = info.id else {
            tracing::warn!("Bug: missing ID in build info");
            return;
        };

        match &*id {
            "moby.buildkit.trace" => {
                let Some(BuildInfoAux::BuildKit(resp)) = info.aux else {
                    tracing::warn!("Bug: Missing BuildKit aux data");
                    return;
                };

                fn digest(mut digest: &str) -> impl fmt::Display {
                    if let Some(s) = digest.strip_prefix("sha256:") {
                        digest = s;
                    }
                    format!("{digest:.8}")
                }

                for v in resp.vertexes {
                    if v.started.is_none() {
                        tracing::info!("[{}] {}", digest(&v.digest), v.name);
                    }
                }

                for s in resp.statuses {
                    if s.started.is_none() {
                        tracing::info!(
                            "[{}] {} {}/{}",
                            digest(&s.vertex),
                            s.id,
                            s.current,
                            s.total
                        );
                    }
                }

                for l in resp.logs {
                    if let Ok(msg) = std::str::from_utf8(&l.msg) {
                        tracing::info!("[{}] {msg}", digest(&l.vertex));
                    } else {
                        let msg = l.msg.utf8_chunks();
                        tracing::info!("[{}] {msg:?}", digest(&l.vertex));
                    }
                }

                for w in resp.warnings {
                    if let Ok(msg) = std::str::from_utf8(&w.short) {
                        tracing::warn!("[{}] {msg}", digest(&w.vertex));
                    } else {
                        let msg = w.short.utf8_chunks();
                        tracing::warn!("[{}] {msg:?}", digest(&w.vertex));
                    }
                }
            }

            "moby.image.id" => {
                let Some(BuildInfoAux::Default(ImageId { id: Some(id) })) = info.aux else {
                    tracing::warn!("Bug: Missing image ID");
                    return;
                };
                self.image_id = Some(id.into());
            }

            _ => {
                tracing::warn!("Bug: Unrecognized build info ID {id:?}");
            }
        }
    }
}
