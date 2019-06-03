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
//! use dayu::Dayu;
//! use serde_json::json;
//!
//! fn main() {
//!     let mut dayu = Dayu::new();
//!     dayu.set_access_key("access_key");
//!     dayu.set_access_secret("access_secret");
//!     dayu.set_sign_name("阿里云短信测试专用");
//!     let mut rt = tokio::runtime::current_thread::Runtime::new().unwrap();
//!     rt.block_on(dayu.sms_send(&["138XXXXXXXX"], "SMS_123456", Some(&json!({"customer": "Rust"})))).unwrap();
//! }
//! ```

use std::collections::BTreeMap;
use std::convert::AsRef;
use std::fmt::{self, Display, Formatter};

use chrono::{NaiveDate, Utc};
use derive_more::From;
use failure::Fail;
use futures::{
    future::{self, Either},
    Future, IntoFuture,
};
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use reqwest::r#async::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use textnonce::TextNonce;
use url::Url;

static MAX_PAGE_SIZE: u8 = 50;
static REQUEST_FORMAT: &str = "JSON";
static SIGN_METHOD: &str = "HMAC-SHA1";
static SIGNATURE_VERSION: &str = "1.0";
static VERSION: &str = "2017-05-25";

#[derive(Debug, Fail, From)]
pub enum ErrorKind {
    #[fail(display = "config of '{}' absence.", _0)]
    ConfigAbsence(&'static str),
    #[fail(display = "dayu's error: {}", _0)]
    Dayu(DayuFailResponse),
    #[fail(display = "openssl error: {}", _0)]
    Openssl(openssl::error::ErrorStack),
    #[fail(display = "page size '{}' too large, max is 50.", _0)]
    PageTooLarge(u8),
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DayuSendResponse {
    pub biz_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DayuQueryDetail {
    pub phone_num: String,
    pub send_date: String,
    pub send_status: u8,
    pub receive_date: String,
    pub template_code: String,
    pub content: String,
    pub err_code: String,
}

#[derive(Debug, Deserialize)]
pub struct DayuQueryDetails {
    #[serde(rename = "SmsSendDetailDTO")]
    pub inner: Vec<DayuQueryDetail>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DayuQueryResponse {
    pub total_count: i32,
    pub total_page: Option<u8>,
    #[serde(rename = "SmsSendDetailDTOs")]
    pub details: Option<DayuQueryDetails>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct DayuFailResponse {
    pub code: String,
    pub message: String,
    pub request_id: String,
}

impl Display for DayuFailResponse {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", serde_json::to_string_pretty(self).unwrap())
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum DayuResponse {
    Send(DayuSendResponse),
    Query(DayuQueryResponse),
    Fail(DayuFailResponse),
}

#[derive(Default)]
pub struct Dayu {
    access_key: String,
    access_secret: String,
    sign_name: String,
}

fn make_url(dayu: &Dayu, action: &str, params: &[(&str, &str)]) -> Result<Url, ErrorKind> {
    if dayu.access_key.is_empty() {
        return Err(ErrorKind::ConfigAbsence("access_key"));
    }

    if dayu.access_secret.is_empty() {
        return Err(ErrorKind::ConfigAbsence("access_secret"));
    }

    if dayu.sign_name.is_empty() {
        return Err(ErrorKind::ConfigAbsence("sign_name"));
    }

    let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    TextNonce::sized(32)
        .map_err(Into::into)
        .map(|v| v.to_string())
        .and_then(|text_nonce| {
            let mut map = BTreeMap::new();
            map.insert("Format", REQUEST_FORMAT);
            map.insert("AccessKeyId", &dayu.access_key);
            map.insert("SignatureMethod", SIGN_METHOD);
            map.insert("SignatureNonce", &text_nonce);
            map.insert("SignatureVersion", SIGNATURE_VERSION);
            map.insert("Timestamp", &timestamp);
            map.insert("Action", action);
            map.insert("SignName", &dayu.sign_name);
            map.insert("Version", VERSION);

            for &(name, value) in params {
                if !value.is_empty() {
                    map.insert(name, value);
                }
            }

            let mut forms = map
                .into_iter()
                .map(|(key, value)| (key, urlencoding::encode(value)))
                .collect::<Vec<(&str, String)>>();

            let mut wait_sign = String::from("GET&%2F&");
            wait_sign.push_str(
                &forms
                    .iter()
                    .fold(vec![], |mut wait_sign, &(key, ref value)| {
                        wait_sign.push(urlencoding::encode(&format!("{}={}", key, value)));
                        wait_sign
                    })
                    .join(&urlencoding::encode("&")),
            );

            PKey::hmac(format!("{}&", &dayu.access_secret).as_bytes())
                .and_then(|pkey| {
                    Signer::new(MessageDigest::sha1(), &pkey).and_then(|mut signer| {
                        signer
                            .update(wait_sign.as_bytes())
                            .and_then(|_| signer.sign_to_vec())
                    })
                })
                .map_err(Into::into)
                .map(|ref signature| {
                    forms.push(("Signature", urlencoding::encode(&base64::encode(signature))))
                })
                .and_then(|_| {
                    Url::parse("http://dysmsapi.aliyuncs.com")
                        .map_err(Into::into)
                        .map(|mut url| {
                            url.set_query(Some(
                                &forms
                                    .into_iter()
                                    .map(|(key, value)| format!("{}={}", key, value))
                                    .collect::<Vec<String>>()
                                    .join("&"),
                            ));
                            url
                        })
                })
        })
}

macro_rules! do_request {
    ($dayu:expr, $action:expr, $params:expr, $type:tt) => {{
        make_url($dayu, $action, $params)
            .into_future()
            .and_then(|url| {
                Client::new()
                    .get(url)
                    .send()
                    .and_then(|mut response| response.json::<DayuResponse>())
                    .map_err(Into::into)
                    .and_then(|json_response| {
                        match json_response {
                            DayuResponse::$type(v) => Ok(v),
                            DayuResponse::Fail(fail) => Err(ErrorKind::Dayu(fail)),
                            _ => unreachable!(),
                        }
                        .into_future()
                    })
            })
    }};
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
    /// template_param: SMS TEMPLATE PARAMS as JSON
    pub fn sms_send<T: AsRef<str>>(
        &self,
        phones: &[T],
        template_code: &str,
        template_param: Option<&Value>,
    ) -> impl Future<Item = DayuSendResponse, Error = ErrorKind> {
        let phone_numbers = phones
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<&str>>()
            .join(",");

        let template_param = template_param
            .map(|v| serde_json::to_string(v).unwrap())
            .unwrap_or_else(String::new);

        do_request!(
            self,
            "SendSms",
            &[
                ("TemplateCode", template_code),
                ("PhoneNumbers", &phone_numbers),
                ("TemplateParam", &template_param),
            ],
            Send
        )
    }

    /// query sms send detail
    pub fn sms_query(
        &self,
        phone_number: &str,
        biz_id: Option<&str>,
        send_date: NaiveDate,
        current_page: u8,
        page_size: u8,
    ) -> impl Future<Item = DayuQueryResponse, Error = ErrorKind> {
        if page_size > MAX_PAGE_SIZE {
            return Either::A(future::err(ErrorKind::PageTooLarge(page_size)));
        }

        let send_date = send_date.format("%Y%m%d").to_string();
        let page_size = page_size.to_string();
        let current_page = current_page.to_string();

        Either::B(do_request!(
            self,
            "QuerySendDetails",
            &[
                ("PhoneNumber", phone_number),
                ("BizId", biz_id.unwrap_or_else(|| "")),
                ("SendDate", &send_date),
                ("PageSize", &page_size),
                ("CurrentPage", &current_page),
            ],
            Query
        ))
    }
}
