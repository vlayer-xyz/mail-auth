use crate::common::parse::TxtRecordParser;
use crate::{Error, Txt};
use std::sync::Arc;
use std::borrow::Cow;
use crate::common::verify::DomainKey;
use crate::dkim::{Atps, DomainKeyReport};
#[cfg(feature = "dns-resolvers")]
use crate::dmarc::Dmarc;
#[cfg(feature = "dns-resolvers")]
use crate::mta_sts::{MtaSts, TlsRpt};
#[cfg(feature = "dns-resolvers")]
use crate::spf::{Macro, Spf};

pub trait Resolve {
    async fn txt_lookup<'x, T: TxtRecordParser + Into<Txt> + UnwrapTxtRecord>(
        &self,
        key: impl IntoFqdn<'x>,
    ) -> crate::Result<Arc<T>>;
}

pub trait IntoFqdn<'x> {
    fn into_fqdn(self) -> Cow<'x, str>;
}

impl<'x> IntoFqdn<'x> for String {
    fn into_fqdn(self) -> Cow<'x, str> {
        if self.ends_with('.') {
            self.to_lowercase().into()
        } else {
            format!("{}.", self.to_lowercase()).into()
        }
    }
}

impl<'x> IntoFqdn<'x> for &'x str {
    fn into_fqdn(self) -> Cow<'x, str> {
        if self.ends_with('.') {
            self.to_lowercase().into()
        } else {
            format!("{}.", self.to_lowercase()).into()
        }
    }
}

impl<'x> IntoFqdn<'x> for &String {
    fn into_fqdn(self) -> Cow<'x, str> {
        if self.ends_with('.') {
            self.to_lowercase().into()
        } else {
            format!("{}.", self.to_lowercase()).into()
        }
    }
}

#[cfg(feature = "dns-resolvers")]
impl From<Spf> for Txt {
    fn from(v: Spf) -> Self {
        Txt::Spf(v.into())
    }
}

#[cfg(feature = "dns-resolvers")]
impl From<Macro> for Txt {
    fn from(v: Macro) -> Self {
        Txt::SpfMacro(v.into())
    }
}

#[cfg(feature = "dns-resolvers")]
impl From<Dmarc> for Txt {
    fn from(v: Dmarc) -> Self {
        Txt::Dmarc(v.into())
    }
}

#[cfg(feature = "dns-resolvers")]
impl From<MtaSts> for Txt {
    fn from(v: MtaSts) -> Self {
        Txt::MtaSts(v.into())
    }
}

#[cfg(feature = "dns-resolvers")]
impl From<TlsRpt> for Txt {
    fn from(v: TlsRpt) -> Self {
        Txt::TlsRpt(v.into())
    }
}

impl<T: Into<Txt>> From<crate::Result<T>> for Txt {
    fn from(v: crate::Result<T>) -> Self {
        match v {
            Ok(v) => v.into(),
            Err(err) => Txt::Error(err),
        }
    }
}


pub trait UnwrapTxtRecord: Sized {
    fn unwrap_txt(txt: Txt) -> crate::Result<Arc<Self>>;
}

impl UnwrapTxtRecord for DomainKey {
    fn unwrap_txt(txt: Txt) -> crate::Result<Arc<Self>> {
        match txt {
            Txt::DomainKey(a) => Ok(a),
            Txt::Error(err) => Err(err),
            _ => Err(Error::Io("Invalid record type".to_string())),
        }
    }
}

impl UnwrapTxtRecord for DomainKeyReport {
    fn unwrap_txt(txt: Txt) -> crate::Result<Arc<Self>> {
        match txt {
            Txt::DomainKeyReport(a) => Ok(a),
            Txt::Error(err) => Err(err),
            _ => Err(Error::Io("Invalid record type".to_string())),
        }
    }
}

impl UnwrapTxtRecord for Atps {
    fn unwrap_txt(txt: Txt) -> crate::Result<Arc<Self>> {
        match txt {
            Txt::Atps(a) => Ok(a),
            Txt::Error(err) => Err(err),
            _ => Err(Error::Io("Invalid record type".to_string())),
        }
    }
}

impl From<DomainKey> for Txt {
    fn from(v: DomainKey) -> Self {
        Txt::DomainKey(v.into())
    }
}

impl From<DomainKeyReport> for Txt {
    fn from(v: DomainKeyReport) -> Self {
        Txt::DomainKeyReport(v.into())
    }
}

impl From<Atps> for Txt {
    fn from(v: Atps) -> Self {
        Txt::Atps(v.into())
    }
}

#[cfg(feature = "dns-resolvers")]
impl UnwrapTxtRecord for Spf {
    fn unwrap_txt(txt: Txt) -> crate::Result<Arc<Self>> {
        match txt {
            Txt::Spf(a) => Ok(a),
            Txt::Error(err) => Err(err),
            _ => Err(Error::Io("Invalid record type".to_string())),
        }
    }
}

#[cfg(feature = "dns-resolvers")]
impl UnwrapTxtRecord for Macro {
    fn unwrap_txt(txt: Txt) -> crate::Result<Arc<Self>> {
        match txt {
            Txt::SpfMacro(a) => Ok(a),
            Txt::Error(err) => Err(err),
            _ => Err(Error::Io("Invalid record type".to_string())),
        }
    }
}

#[cfg(feature = "dns-resolvers")]
impl UnwrapTxtRecord for Dmarc {
    fn unwrap_txt(txt: Txt) -> crate::Result<Arc<Self>> {
        match txt {
            Txt::Dmarc(a) => Ok(a),
            Txt::Error(err) => Err(err),
            _ => Err(Error::Io("Invalid record type".to_string())),
        }
    }
}

#[cfg(feature = "dns-resolvers")]
impl UnwrapTxtRecord for MtaSts {
    fn unwrap_txt(txt: Txt) -> crate::Result<Arc<Self>> {
        match txt {
            Txt::MtaSts(a) => Ok(a),
            Txt::Error(err) => Err(err),
            _ => Err(Error::Io("Invalid record type".to_string())),
        }
    }
}

#[cfg(feature = "dns-resolvers")]
impl UnwrapTxtRecord for TlsRpt {
    fn unwrap_txt(txt: Txt) -> crate::Result<Arc<Self>> {
        match txt {
            Txt::TlsRpt(a) => Ok(a),
            Txt::Error(err) => Err(err),
            _ => Err(Error::Io("Invalid record type".to_string())),
        }
    }
}