use serde::Deserialize;
use tau_engine::Rule as Tau;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct Rule {
    pub level: Option<String>,
    #[serde(alias = "title")]
    pub tag: String,
    #[serde(flatten)]
    pub tau: Tau,

    pub authors: Option<Vec<String>>,
    pub status: Option<String>,
}
