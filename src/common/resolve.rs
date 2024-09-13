use std::sync::Arc;
use hickory_resolver::Name;
use std::borrow::Cow;
use crate::common::parse::TxtRecordParser;
use crate::{Error, Resolver, Txt};
use crate::common::lru::DnsCache;
#[cfg(any(test, feature = "test"))]
use crate::common::resolver;
use crate::common::resolver::{IntoFqdn, UnwrapTxtRecord};

impl Resolve for Resolver {
    async fn txt_lookup<'x, T: TxtRecordParser + Into<Txt> + UnwrapTxtRecord>(
        &self,
        key: impl IntoFqdn<'x>,
    ) -> crate::Result<Arc<T>> {
        let key = key.into_fqdn();
        if let Some(value) = self.cache_txt.get(key.as_ref()) {
            return T::unwrap_txt(value);
        }

        #[cfg(any(test, feature = "test"))]
        if true {
            return resolver::mock_resolve(key.as_ref());
        }

        let txt_lookup = self
            .resolver
            .txt_lookup(Name::from_str_relaxed(key.as_ref())?)
            .await?;
        let mut result = Err(Error::InvalidRecordType);
        let records = txt_lookup.as_lookup().record_iter().filter_map(|r| {
            let txt_data = r.data()?.as_txt()?.txt_data();
            match txt_data.len() {
                1 => Cow::from(txt_data[0].as_ref()).into(),
                0 => None,
                _ => {
                    let mut entry = Vec::with_capacity(255 * txt_data.len());
                    for data in txt_data {
                        entry.extend_from_slice(data);
                    }
                    Cow::from(entry).into()
                }
            }
        });

        for record in records {
            result = T::parse(record.as_ref());
            if result.is_ok() {
                break;
            }
        }
        T::unwrap_txt(self.cache_txt.insert(
            key.into_owned(),
            result.into(),
            txt_lookup.valid_until(),
        ))
    }
}

pub trait Resolve {
    async fn txt_lookup<'x, T: TxtRecordParser + Into<Txt> + UnwrapTxtRecord>(
        &self,
        key: impl IntoFqdn<'x>,
    ) -> crate::Result<Arc<T>>;
}