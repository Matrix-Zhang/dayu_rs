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
//!use dayu::Dayu;
//!use serde_json::json;
//!
//!let dayu = Dayu::new()
//!     .set_access_key("access_key")
//!     .set_access_secret("access_secret")
//!     .set_sign_name("阿里云测试短信");
//!dayu.sms_send(&["138XXXXXXXX"], "SMS_123456", Some(&json!({"customer": "Rust"}))).await.unwrap();
//! ```

use std::{
    collections::BTreeMap,
    convert::AsRef,
    fmt::{self, Display, Formatter},
};

use chrono::{NaiveDate, Utc};
use futures_util::TryFutureExt;
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use textnonce::TextNonce;
use thiserror::Error;
use url::Url;

static MAX_PAGE_SIZE: u8 = 50;
static REQUEST_FORMAT: &str = "JSON";
static SIGN_METHOD: &str = "HMAC-SHA1";
static SIGNATURE_VERSION: &str = "1.0";
static VERSION: &str = "2017-05-25";

#[derive(Debug, Error)]
pub enum DayuError {
    #[error("config of '{0}' absence")]
    ConfigAbsence(&'static str),
    #[error("dayu response error: {0}")]
    Dayu(DayuFailResponse),
    #[error("openssl error: {0}")]
    Openssl(#[from] openssl::error::ErrorStack),
    #[error("page size '{0}' too large, max is 50")]
    PageTooLarge(u8),
    #[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("serde_json error: {0}")]
    SerdeJson(#[from] serde_json::error::Error),
    #[error("std io error: {0}")]
    Stdio(#[from] std::io::Error),
    #[error("textnonce error: {0}")]
    TextNonce(String),
    #[error("url parse error: {0}")]
    UrlParse(#[from] url::ParseError),
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

#[derive(Default, Clone)]
pub struct Dayu {
    client: Client,
    access_key: String,
    access_secret: String,
    sign_name: String,
}

fn make_url(dayu: &Dayu, action: &str, params: &[(&str, &str)]) -> Result<Url, DayuError> {
    if dayu.access_key.is_empty() {
        return Err(DayuError::ConfigAbsence("access_key"));
    }

    if dayu.access_secret.is_empty() {
        return Err(DayuError::ConfigAbsence("access_secret"));
    }

    if dayu.sign_name.is_empty() {
        return Err(DayuError::ConfigAbsence("sign_name"));
    }

    let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    TextNonce::sized(32)
        .map_err(DayuError::TextNonce)
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
                .map(|(key, value)| (key, urlencoding::encode(value).into_owned()))
                .collect::<Vec<(&str, String)>>();

            let mut wait_sign = String::from("GET&%2F&");
            wait_sign.push_str(
                &forms
                    .iter()
                    .fold(vec![], |mut wait_sign, &(key, ref value)| {
                        wait_sign
                            .push(urlencoding::encode(&format!("{}={}", key, value)).into_owned());
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
                    forms.push((
                        "Signature",
                        urlencoding::encode(&base64::encode(signature)).into_owned(),
                    ))
                })
                .and_then(|_| {
                    Url::parse("https://dysmsapi.aliyuncs.com")
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
        let url = make_url($dayu, $action, $params)?;
        $dayu
            .client
            .get(url)
            .send()
            .and_then(|response| response.json::<DayuResponse>())
            .await
            .map_err(Into::into)
            .and_then(|json_response| match json_response {
                DayuResponse::$type(v) => Ok(v),
                DayuResponse::Fail(fail) => Err(DayuError::Dayu(fail)),
                _ => unreachable!(),
            })
    }};
}

impl Dayu {
    /// construct new dayu sdk instance
    pub fn new() -> Self {
        Self::default()
    }

    /// set dayu sdk's access key
    pub fn set_access_key(mut self, access_key: impl Into<String>) -> Self {
        self.access_key = access_key.into();
        self
    }

    /// set dayu sdk's access secret
    pub fn set_access_secret(mut self, access_secret: impl Into<String>) -> Self {
        self.access_secret = access_secret.into();
        self
    }

    /// set dayu sdk's sign name
    pub fn set_sign_name(mut self, sign_name: impl Into<String>) -> Self {
        self.sign_name = sign_name.into();
        self
    }

    /// start send sms
    /// phones: support multi phone number
    /// template_code: SMS TEMPLATE CODE
    /// template_param: SMS TEMPLATE PARAMS as JSON
    pub async fn sms_send<T: AsRef<str>>(
        &self,
        phones: &[T],
        template_code: T,
        template_param: Option<&Value>,
    ) -> Result<DayuSendResponse, DayuError> {
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
                ("TemplateCode", template_code.as_ref()),
                ("PhoneNumbers", &phone_numbers),
                ("TemplateParam", &template_param),
            ],
            Send
        )
    }

    /// query sms send detail
    pub async fn sms_query(
        &self,
        phone_number: &str,
        biz_id: Option<&str>,
        send_date: NaiveDate,
        current_page: u8,
        page_size: u8,
    ) -> Result<DayuQueryResponse, DayuError> {
        if page_size > MAX_PAGE_SIZE {
            return Err(DayuError::PageTooLarge(page_size));
        }

        let send_date = send_date.format("%Y%m%d").to_string();
        let page_size = page_size.to_string();
        let current_page = current_page.to_string();

        do_request!(
            self,
            "QuerySendDetails",
            &[
                ("PhoneNumber", phone_number),
                ("BizId", biz_id.unwrap_or("")),
                ("SendDate", &send_date),
                ("PageSize", &page_size),
                ("CurrentPage", &current_page),
            ],
            Query
        )
    }
}
