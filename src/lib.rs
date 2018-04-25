// The MIT License (MIT)

// Copyright (c) 2018 Matrix.Zhang <113445886@qq.com>

// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

//! This library supports Alibaba's Dayu SMS SDK version of '2017-05-25'.
//!
//! ## Basic usage
//!
//! ```rust
//! extern crate dayu;
//!
//! use dayu::Dayu;
//!
//! fn main() {
//!     let mut dayu = Dayu::new();
//!     dayu.set_access_key("access_key");
//!     dayu.set_access_secret("access_secret");
//!     dayu.set_sign_name("sign_name");
//!     dayu.send_sms(&["13888888888"], "TEMPLATE_CODE", None).unwrap();
//! }
//! ```

extern crate base64;
extern crate chrono;
#[macro_use]
extern crate failure;
extern crate openssl;
extern crate reqwest;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate textnonce;
extern crate url;
extern crate urlencoding;

use std::collections::BTreeMap;
use std::io::Read;

use chrono::Utc;
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use serde_json::Value;
use textnonce::TextNonce;
use url::Url;

static REQUEST_FORMAT: &str = "JSON";
static REGION_ID: &str = "cn-hangzhou";
static SIGN_METHOD: &str = "HMAC-SHA1";
static SIGNATURE_VERSION: &str = "1.0";
static VERSION: &str = "2017-05-25";

#[derive(Debug, Fail)]
pub enum ErrorKind {
    #[fail(display = "config of '{}' absence.", _0)]
    ConfigAbsence(&'static str),
    #[fail(display = "dayu's error: {}", _0)]
    Dayu(String),
    #[fail(display = "openssl error: {}", _0)]
    Openssl(openssl::error::ErrorStack),
    #[fail(display = "reqwest error: {}", _0)]
    Reqwest(reqwest::Error),
    #[fail(display = "serde_json error: {}", _0)]
    SerdeJson(serde_json::error::Error),
    #[fail(display = "std's io error: {}", _0)]
    Stdio(std::io::Error),
    #[fail(display = "textnonce error: {}", _0)]
    TextNonce(String),
    #[fail(display = "url parse error: {}", _0)]
    UrlParse(url::ParseError),
}

#[derive(Default)]
pub struct Dayu {
    access_key: String,
    access_secret: String,
    sign_name: String,
}
/// return when sms send ok
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DayuSuccess {
    /// receipt id, used for query
    pub biz_id: String,
    /// request id
    pub request_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DayuFail {
    code: String,
    message: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum DayuResponse {
    Success(DayuSuccess),
    Fail(DayuFail),
}

impl Dayu {
    /// construct new dayu sdk instance
    pub fn new() -> Dayu {
        Dayu::default()
    }

    /// set dayu sdk's access key
    pub fn set_access_key(&mut self, access_key: &str) {
        self.access_key = access_key.to_owned();
    }

    /// set dayu sdk's access secret
    pub fn set_access_secret(&mut self, access_secret: &str) {
        self.access_secret = access_secret.to_owned();
    }

    /// set dayu sdk's sign name
    pub fn set_sign_name(&mut self, sign_name: &str) {
        self.sign_name = sign_name.to_owned();
    }

    /// start send sms
    /// phones: support multi phone number
    /// template_code: SMS TEMPLATE CODE
    /// template_param: SMS TAPLATE PARAMS as JSON
    pub fn send_sms(
        &self,
        phones: &[&str],
        template_code: &str,
        template_param: Option<&Value>,
    ) -> Result<DayuSuccess, ErrorKind> {
        if self.access_key.is_empty() {
            return Err(ErrorKind::ConfigAbsence("access_key"));
        }

        if self.access_secret.is_empty() {
            return Err(ErrorKind::ConfigAbsence("access_secret"));
        }

        if self.sign_name.is_empty() {
            return Err(ErrorKind::ConfigAbsence("sign_name"));
        }

        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let text_nonce = TextNonce::sized(32)
            .map_err(ErrorKind::TextNonce)?
            .to_string();

        let phone_numbers = phones.join(",");

        let template_param = match template_param {
            Some(param) => serde_json::to_string(param).map_err(ErrorKind::SerdeJson)?,
            None => String::new(),
        };

        let mut map = BTreeMap::new();
        map.insert("Format", REQUEST_FORMAT);
        map.insert("AccessKeyId", &self.access_key);
        map.insert("SignatureMethod", SIGN_METHOD);
        map.insert("SignatureNonce", &text_nonce);
        map.insert("SignatureVersion", SIGNATURE_VERSION);
        map.insert("Timestamp", &timestamp);

        map.insert("Action", "SendSms");
        map.insert("PhoneNumbers", &phone_numbers);
        map.insert("RegionId", REGION_ID);
        map.insert("SignName", &self.sign_name);
        map.insert("TemplateCode", template_code);

        if !template_param.is_empty() {
            map.insert("TemplateParam", &template_param);
        }

        map.insert("Version", VERSION);

        let mut forms = map.into_iter()
            .map(|(key, value)| (key, urlencoding::encode(value)))
            .collect::<Vec<(&str, String)>>();

        let mut wait_sign = String::from("GET&%2F&");
        wait_sign.push_str(&forms
            .iter()
            .fold(vec![], |mut wait_sign, &(key, ref value)| {
                wait_sign.push(urlencoding::encode(&format!("{}={}", key, value)));
                wait_sign
            })
            .join(&urlencoding::encode("&")));

        PKey::hmac(format!("{}&", self.access_secret).as_bytes())
            .and_then(|pkey| {
                Signer::new(MessageDigest::sha1(), &pkey).and_then(|mut signer| {
                    signer
                        .update(wait_sign.as_bytes())
                        .and_then(|_| signer.sign_to_vec())
                })
            })
            .map_err(ErrorKind::Openssl)
            .map(|ref signature| {
                forms.push(("Signature", urlencoding::encode(&base64::encode(signature))))
            })?;

        Url::parse("http://dysmsapi.aliyuncs.com")
            .map_err(ErrorKind::UrlParse)
            .map(|mut url| {
                url.set_query(Some(&forms
                    .into_iter()
                    .map(|(key, value)| format!("{}={}", key, value))
                    .collect::<Vec<String>>()
                    .join("&")));
                url
            })
            .and_then(|url| reqwest::get(url).map_err(ErrorKind::Reqwest))
            .and_then(|mut response| {
                let mut body = String::new();
                response
                    .read_to_string(&mut body)
                    .map_err(ErrorKind::Stdio)
                    .map(|_| body)
            })
            .and_then(|body| {
                println!("body: {}", body);
                serde_json::from_str::<DayuResponse>(&body)
                    .map_err(ErrorKind::SerdeJson)
                    .and_then(|response| match response {
                        DayuResponse::Success(success) => Ok(success),
                        DayuResponse::Fail(fail) => {
                            Err(ErrorKind::Dayu(format!("{}:{}", fail.code, fail.message)))
                        }
                    })
            })
    }
}
