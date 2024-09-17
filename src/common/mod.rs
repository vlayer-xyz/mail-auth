/*
 * Copyright (c) 2020-2023, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use crate::{Error};

pub mod auth_results;
pub mod base32;
pub mod crypto;
pub mod headers;
pub mod lru;
pub mod message;
pub mod parse;
#[cfg(feature = "dns-resolvers")]
pub mod resolver;
pub mod verify;
pub mod resolve;

#[cfg(feature = "dns-resolvers")]
impl From<Error> for crate::IprevResult {
    fn from(err: Error) -> Self {
        if matches!(&err, Error::DnsError(_)) {
            crate::IprevResult::TempError(err)
        } else {
            crate::IprevResult::PermError(err)
        }
    }
}
