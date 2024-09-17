/*
 * Copyright (c) 2020-2023, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::{
    borrow::Cow,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    error::{ResolveError, ResolveErrorKind},
    proto::rr::RecordType,
    system_conf::read_system_conf,
    AsyncResolver, Name,
};

use crate::{
    dkim::{Atps, DomainKeyReport},
    dmarc::Dmarc,
    mta_sts::{MtaSts, TlsRpt},
    spf::{Macro, Spf},
    Error, IpLookupStrategy, Resolver, Txt, MX,
};
use crate::common::parse::TxtRecordParser;
use crate::common::resolve::{IntoFqdn, Resolve, UnwrapTxtRecord};
use super::{lru::{DnsCache, LruCache}, resolver, verify::DomainKey};

impl Resolver {
    pub fn new_cloudflare_tls() -> Result<Self, ResolveError> {
        Self::with_capacity(
            ResolverConfig::cloudflare_tls(),
            ResolverOpts::default(),
            128,
        )
    }

    pub fn new_cloudflare() -> Result<Self, ResolveError> {
        Self::with_capacity(ResolverConfig::cloudflare(), ResolverOpts::default(), 128)
    }

    pub fn new_google() -> Result<Self, ResolveError> {
        Self::with_capacity(ResolverConfig::google(), ResolverOpts::default(), 128)
    }

    pub fn new_quad9() -> Result<Self, ResolveError> {
        Self::with_capacity(ResolverConfig::quad9(), ResolverOpts::default(), 128)
    }

    pub fn new_quad9_tls() -> Result<Self, ResolveError> {
        Self::with_capacity(ResolverConfig::quad9_tls(), ResolverOpts::default(), 128)
    }

    pub fn new_system_conf() -> Result<Self, ResolveError> {
        let (config, options) = read_system_conf()?;
        Self::with_capacity(config, options, 128)
    }

    pub fn with_capacity(
        config: ResolverConfig,
        options: ResolverOpts,
        capacity: usize,
    ) -> Result<Self, ResolveError> {
        Ok(Self {
            resolver: AsyncResolver::tokio(config, options),
            cache_txt: LruCache::with_capacity(capacity),
            cache_mx: LruCache::with_capacity(capacity),
            cache_ipv4: LruCache::with_capacity(capacity),
            cache_ipv6: LruCache::with_capacity(capacity),
            cache_ptr: LruCache::with_capacity(capacity),
        })
    }

    pub fn with_capacities(
        config: ResolverConfig,
        options: ResolverOpts,
        txt_capacity: usize,
        mx_capacity: usize,
        ipv4_capacity: usize,
        ipv6_capacity: usize,
        ptr_capacity: usize,
    ) -> Result<Self, ResolveError> {
        Ok(Self {
            resolver: AsyncResolver::tokio(config, options),
            cache_txt: LruCache::with_capacity(txt_capacity),
            cache_mx: LruCache::with_capacity(mx_capacity),
            cache_ipv4: LruCache::with_capacity(ipv4_capacity),
            cache_ipv6: LruCache::with_capacity(ipv6_capacity),
            cache_ptr: LruCache::with_capacity(ptr_capacity),
        })
    }

    pub async fn txt_raw_lookup(&self, key: impl IntoFqdn<'_>) -> crate::Result<Vec<u8>> {
        let mut result = vec![];
        for record in self
            .resolver
            .txt_lookup(Name::from_str_relaxed(key.into_fqdn().as_ref())?)
            .await?
            .as_lookup()
            .record_iter()
        {
            if let Some(txt_data) = record.data().and_then(|r| r.as_txt()) {
                for item in txt_data.txt_data() {
                    result.extend_from_slice(item);
                }
            }
        }

        Ok(result)
    }

    pub async fn mx_lookup<'x>(&self, key: impl IntoFqdn<'x>) -> crate::Result<Arc<Vec<MX>>> {
        let key = key.into_fqdn();
        if let Some(value) = self.cache_mx.get(key.as_ref()) {
            return Ok(value);
        }

        #[cfg(any(test, feature = "test"))]
        if true {
            return mock_resolve(key.as_ref());
        }

        let mx_lookup = self
            .resolver
            .mx_lookup(Name::from_str_relaxed(key.as_ref())?)
            .await?;
        let mx_records = mx_lookup.as_lookup().records();
        let mut records: Vec<MX> = Vec::with_capacity(mx_records.len());
        for mx_record in mx_records {
            if let Some(mx) = mx_record.data().and_then(|r| r.as_mx()) {
                let preference = mx.preference();
                let exchange = mx.exchange().to_lowercase().to_string();

                if let Some(record) = records.iter_mut().find(|r| r.preference == preference) {
                    record.exchanges.push(exchange);
                } else {
                    records.push(MX {
                        exchanges: vec![exchange],
                        preference,
                    });
                }
            }
        }

        records.sort_unstable_by(|a, b| a.preference.cmp(&b.preference));

        Ok(self
            .cache_mx
            .insert(key.into_owned(), Arc::new(records), mx_lookup.valid_until()))
    }

    pub async fn ipv4_lookup<'x>(
        &self,
        key: impl IntoFqdn<'x>,
    ) -> crate::Result<Arc<Vec<Ipv4Addr>>> {
        let key = key.into_fqdn();
        if let Some(value) = self.cache_ipv4.get(key.as_ref()) {
            return Ok(value);
        }

        #[cfg(any(test, feature = "test"))]
        if true {
            return mock_resolve(key.as_ref());
        }

        let ipv4_lookup = self
            .resolver
            .ipv4_lookup(Name::from_str_relaxed(key.as_ref())?)
            .await?;
        let ips: Vec<Ipv4Addr> = ipv4_lookup
            .as_lookup()
            .record_iter()
            .filter_map(|r| r.data()?.as_a()?.0.into())
            .collect::<Vec<_>>();

        Ok(self
            .cache_ipv4
            .insert(key.into_owned(), Arc::new(ips), ipv4_lookup.valid_until()))
    }

    pub async fn ipv6_lookup<'x>(
        &self,
        key: impl IntoFqdn<'x>,
    ) -> crate::Result<Arc<Vec<Ipv6Addr>>> {
        let key = key.into_fqdn();
        if let Some(value) = self.cache_ipv6.get(key.as_ref()) {
            return Ok(value);
        }

        #[cfg(any(test, feature = "test"))]
        if true {
            return mock_resolve(key.as_ref());
        }

        let ipv6_lookup = self
            .resolver
            .ipv6_lookup(Name::from_str_relaxed(key.as_ref())?)
            .await?;
        let ips = ipv6_lookup
            .as_lookup()
            .record_iter()
            .filter_map(|r| r.data()?.as_aaaa()?.0.into())
            .collect::<Vec<_>>();

        Ok(self
            .cache_ipv6
            .insert(key.into_owned(), Arc::new(ips), ipv6_lookup.valid_until()))
    }

    pub async fn ip_lookup(
        &self,
        key: &str,
        mut strategy: IpLookupStrategy,
        max_results: usize,
    ) -> crate::Result<Vec<IpAddr>> {
        loop {
            match strategy {
                IpLookupStrategy::Ipv4Only | IpLookupStrategy::Ipv4thenIpv6 => {
                    match (self.ipv4_lookup(key).await, strategy) {
                        (Ok(result), _) => {
                            return Ok(result
                                .iter()
                                .take(max_results)
                                .copied()
                                .map(IpAddr::from)
                                .collect())
                        }
                        (Err(err), IpLookupStrategy::Ipv4Only) => return Err(err),
                        _ => {
                            strategy = IpLookupStrategy::Ipv6Only;
                        }
                    }
                }
                IpLookupStrategy::Ipv6Only | IpLookupStrategy::Ipv6thenIpv4 => {
                    match (self.ipv6_lookup(key).await, strategy) {
                        (Ok(result), _) => {
                            return Ok(result
                                .iter()
                                .take(max_results)
                                .copied()
                                .map(IpAddr::from)
                                .collect())
                        }
                        (Err(err), IpLookupStrategy::Ipv6Only) => return Err(err),
                        _ => {
                            strategy = IpLookupStrategy::Ipv4Only;
                        }
                    }
                }
            }
        }
    }

    pub async fn ptr_lookup<'x>(&self, addr: IpAddr) -> crate::Result<Arc<Vec<String>>> {
        if let Some(value) = self.cache_ptr.get(&addr) {
            return Ok(value);
        }

        #[cfg(any(test, feature = "test"))]
        if true {
            return mock_resolve(&addr.to_string());
        }

        let ptr_lookup = self.resolver.reverse_lookup(addr).await?;
        let ptr = ptr_lookup
            .as_lookup()
            .record_iter()
            .filter_map(|r| {
                let r = r.data()?.as_ptr()?;
                if !r.is_empty() {
                    r.to_lowercase().to_string().into()
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        Ok(self
            .cache_ptr
            .insert(addr, Arc::new(ptr), ptr_lookup.valid_until()))
    }

    pub async fn exists<'x>(&self, key: impl IntoFqdn<'x>) -> crate::Result<bool> {
        #[cfg(any(test, feature = "test"))]
        if true {
            let key = key.into_fqdn().into_owned();
            return match self.ipv4_lookup(key.as_str()).await {
                Ok(_) => Ok(true),
                Err(Error::DnsRecordNotFound(_)) => match self.ipv6_lookup(key.as_str()).await {
                    Ok(_) => Ok(true),
                    Err(Error::DnsRecordNotFound(_)) => Ok(false),
                    Err(err) => Err(err),
                },
                Err(err) => Err(err),
            };
        }

        let key = key.into_fqdn();
        match self
            .resolver
            .lookup_ip(Name::from_str_relaxed(key.as_ref())?)
            .await
        {
            Ok(result) => Ok(result.as_lookup().record_iter().any(|r| {
                r.data().map_or(false, |d| {
                    matches!(d.record_type(), RecordType::A | RecordType::AAAA)
                })
            })),
            Err(err) => {
                if matches!(err.kind(), ResolveErrorKind::NoRecordsFound { .. }) {
                    Ok(false)
                } else {
                    Err(err.into())
                }
            }
        }
    }

    #[cfg(any(test, feature = "test"))]
    pub fn txt_add<'x>(
        &self,
        name: impl IntoFqdn<'x>,
        value: impl Into<Txt>,
        valid_until: std::time::Instant,
    ) {
        self.cache_txt
            .insert(name.into_fqdn().into_owned(), value.into(), valid_until);
    }

    #[cfg(any(test, feature = "test"))]
    pub fn ipv4_add<'x>(
        &self,
        name: impl IntoFqdn<'x>,
        value: Vec<Ipv4Addr>,
        valid_until: std::time::Instant,
    ) {
        self.cache_ipv4
            .insert(name.into_fqdn().into_owned(), Arc::new(value), valid_until);
    }

    #[cfg(any(test, feature = "test"))]
    pub fn ipv6_add<'x>(
        &self,
        name: impl IntoFqdn<'x>,
        value: Vec<Ipv6Addr>,
        valid_until: std::time::Instant,
    ) {
        self.cache_ipv6
            .insert(name.into_fqdn().into_owned(), Arc::new(value), valid_until);
    }

    #[cfg(any(test, feature = "test"))]
    pub fn ptr_add(&self, name: IpAddr, value: Vec<String>, valid_until: std::time::Instant) {
        self.cache_ptr.insert(name, Arc::new(value), valid_until);
    }

    #[cfg(any(test, feature = "test"))]
    pub fn mx_add<'x>(
        &self,
        name: impl IntoFqdn<'x>,
        value: Vec<MX>,
        valid_until: std::time::Instant,
    ) {
        self.cache_mx
            .insert(name.into_fqdn().into_owned(), Arc::new(value), valid_until);
    }
}

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
            return mock_resolve(key.as_ref());
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


impl From<ResolveError> for Error {
    fn from(err: ResolveError) -> Self {
        match err.kind() {
            ResolveErrorKind::NoRecordsFound { response_code, .. } => {
                Error::DnsRecordNotFound(*response_code)
            }
            _ => Error::DnsError(err.to_string()),
        }
    }
}

pub trait ToReverseName {
    fn to_reverse_name(&self) -> String;
}

impl ToReverseName for IpAddr {
    fn to_reverse_name(&self) -> String {
        use std::fmt::Write;

        match self {
            IpAddr::V4(ip) => {
                let mut segments = String::with_capacity(15);
                for octet in ip.octets().iter().rev() {
                    if !segments.is_empty() {
                        segments.push('.');
                    }
                    let _ = write!(&mut segments, "{}", octet);
                }
                segments
            }
            IpAddr::V6(ip) => {
                let mut segments = String::with_capacity(63);
                for segment in ip.segments().iter().rev() {
                    for &p in format!("{segment:04x}").as_bytes().iter().rev() {
                        if !segments.is_empty() {
                            segments.push('.');
                        }
                        segments.push(char::from(p));
                    }
                }
                segments
            }
        }
    }
}

#[cfg(any(test, feature = "test"))]
pub fn mock_resolve<T>(domain: &str) -> crate::Result<T> {
    Err(if domain.contains("_parse_error.") {
        Error::ParseError
    } else if domain.contains("_invalid_record.") {
        Error::InvalidRecordType
    } else if domain.contains("_dns_error.") {
        Error::DnsError("".to_string())
    } else {
        Error::DnsRecordNotFound(hickory_resolver::proto::op::ResponseCode::NXDomain)
    })
}

#[cfg(test)]
mod test {
    use std::net::IpAddr;

    use crate::common::resolver::ToReverseName;

    #[test]
    fn reverse_lookup_addr() {
        for (addr, expected) in [
            ("1.2.3.4", "4.3.2.1"),
            (
                "2001:db8::cb01",
                "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2",
            ),
            (
                "2a01:4f9:c011:b43c::1",
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.3.4.b.1.1.0.c.9.f.4.0.1.0.a.2",
            ),
        ] {
            assert_eq!(addr.parse::<IpAddr>().unwrap().to_reverse_name(), expected);
        }
    }
}
