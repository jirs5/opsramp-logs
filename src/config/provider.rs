use super::{component::ExampleError, GenerateConfig};
use crate::providers::ProviderRx;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use toml::Value;

#[derive(Debug, Deserialize, Serialize, PartialEq, Copy, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct Options {}

impl Default for Options {
    fn default() -> Self {
        Self {}
    }
}

#[async_trait]
#[typetag::serde(tag = "type")]
pub trait ProviderConfig: core::fmt::Debug + Send + Sync + dyn_clone::DynClone {
    async fn build(&self) -> Result<ProviderRx, &'static str>;
    fn provider_type(&self) -> &'static str;
}

/// Describes a provider plugin storing its type name and an optional example config.
pub struct ProviderDescription {
    pub type_str: &'static str,
    example_value: fn() -> Option<Value>,
}

impl ProviderDescription
where
    inventory::iter<ProviderDescription>:
        std::iter::IntoIterator<Item = &'static ProviderDescription>,
{
    /// Creates a new provider plugin description.
    /// Configuration example is generated by the `GenerateConfig` trait.
    pub fn new<B: GenerateConfig>(type_str: &'static str) -> Self {
        Self {
            type_str,
            example_value: || Some(B::generate_config()),
        }
    }

    /// Returns an example config for a plugin identified by its type.
    pub fn example(type_str: &str) -> Result<Value, ExampleError> {
        inventory::iter::<ProviderDescription>
            .into_iter()
            .find(|t| t.type_str == type_str)
            .ok_or_else(|| ExampleError::DoesNotExist {
                type_str: type_str.to_owned(),
            })
            .and_then(|t| (t.example_value)().ok_or(ExampleError::MissingExample))
    }
}

dyn_clone::clone_trait_object!(ProviderConfig);

inventory::collect!(ProviderDescription);

pub async fn init_provider(provider: Option<Box<dyn ProviderConfig>>) -> Option<ProviderRx> {
    match provider {
        Some(provider) => match provider.build().await {
            Ok(provider_rx) => {
                debug!(message = "Provider configured.", provider = ?provider.provider_type());
                // Some(controller.with_shutdown(ReceiverStream::new(provider_rx)))
                Some(provider_rx)
            }
            Err(err) => {
                error!(message = "Provider error.", error = ?err);
                None
            }
        },
        _ => None,
    }
}
